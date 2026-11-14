#!/usr/bin/env python3
"""Train one LightGBM Poisson model per severity on data/training.csv and save them to models/.

Models are saved as JSON tree dumps (models/<severity>.json) so predict.py can evaluate them in
plain Python without importing LightGBM, which can take over 10 seconds on Windows.

Usage:  python train.py
1. Time-based evaluation: train on versions published before SPLIT, test on later ones,
   compared with two baselines (always zero, historical rate from predict.py).
2. Final fit on all records; a severity's model is saved only if its Poisson deviance beat both
   baselines on the test period, otherwise predict.py keeps using the baseline for it.
   (MAE is reported but not used to choose: with mostly-zero targets MAE rewards always predicting
   zero, the median, while the model predicts the expected count.)
"""
import csv, json, os
import numpy as np
import lightgbm as lgb
from sklearn.metrics import mean_absolute_error, mean_poisson_deviance
from course_schema import SEVERITIES, TARGET_COLUMNS
from features import FEATURE_NAMES, vector
from predict import baseline

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data", "training.csv")
MODELS = os.path.join(HERE, "models")
SPLIT = "2025-11-01"
MIN_POSITIVES = 10  # fewer positive records than this: not enough to learn, keep the baseline
PARAMS = dict(objective="poisson", n_estimators=300, learning_rate=0.03, num_leaves=7, min_child_samples=20,
              subsample=0.8, subsample_freq=1, colsample_bytree=0.8, reg_lambda=1.0, verbose=-1, random_state=42)


def main():
    with open(DATA, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    X = np.array([vector(r) for r in rows])
    test = np.array([r["published_at"] >= SPLIT for r in rows])
    print(f"{len(rows)} records, {len(FEATURE_NAMES)} features; train {(~test).sum()} / test {test.sum()} (split {SPLIT})\n")
    os.makedirs(MODELS, exist_ok=True)
    report = {}

    for sev, col in zip(SEVERITIES, TARGET_COLUMNS):
        y = np.array([float(r[col]) for r in rows])
        base = np.array([baseline(r, sev) for r in rows])
        path = os.path.join(MODELS, f"{sev}.json")
        if (y[~test] > 0).sum() < MIN_POSITIVES:
            print(f"{sev:9} only {(y[~test] > 0).sum()} positive training records -> baseline")
            if os.path.exists(path):
                os.remove(path)
            continue
        model = lgb.LGBMRegressor(**PARAMS).fit(X[~test], y[~test])
        pred = model.predict(X[test])
        scores = {name: (mean_absolute_error(y[test], p), mean_poisson_deviance(y[test], np.maximum(p, 1e-6)))
                  for name, p in (("lightgbm", pred), ("baseline", base[test]), ("zero", np.zeros(test.sum())))}
        wins = scores["lightgbm"][1] < min(scores["baseline"][1], scores["zero"][1])
        print(f"{sev:9} positives test {(y[test] > 0).sum():3}   " + "   ".join(
            f"{n}: MAE {m:.3f} dev {d:.3f}" for n, (m, d) in scores.items()) + ("   -> LightGBM" if wins else "   -> baseline"))
        report[sev] = {n: {"mae": round(m, 4), "poisson_deviance": round(d, 4)} for n, (m, d) in scores.items()}
        report[sev]["used"] = "lightgbm" if wins else "baseline"
        if wins:
            final = lgb.LGBMRegressor(**PARAMS).fit(X, y)
            with open(path, "w") as f:
                json.dump(final.booster_.dump_model(), f)
            top = sorted(zip(final.feature_importances_, FEATURE_NAMES), reverse=True)[:5]
            print(f"{'':9} top features: " + ", ".join(n for _, n in top))
        elif os.path.exists(path):
            os.remove(path)

    with open(os.path.join(MODELS, "report.json"), "w") as f:
        json.dump({"split": SPLIT, "records": len(rows), "severities": report}, f, indent=2)


if __name__ == "__main__":
    main()
