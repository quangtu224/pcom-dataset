#!/usr/bin/env python3
"""PCOM prediction function.

Usage:  python predict.py input.csv output.csv [--integer]

input.csv  : one or more records in the course record schema (header row required)
output.csv : one row per input row with the five target_ghsa_*_count_90d columns
--integer  : output whole numbers (the median of the predicted Poisson distribution)

Model per severity: the LightGBM Poisson model in models/<severity>.json if train.py saved one
(evaluated here in plain Python, no LightGBM import needed),
otherwise the historical-rate baseline = advisories in the last 12 months (ghsa_<sev>_count_M0..M11)
scaled to 90 days, falling back to the lifetime rate. If a model file is unreadable or a row
cannot be processed, the baseline (or 0) is used, so a prediction is always produced.
"""
import csv, json, math, os, sys
from datetime import datetime
from course_schema import MONTHS, SEVERITIES, TARGET_COLUMNS

MODELS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")

WINDOW_DAYS = 90


def num(row, col):
    """Float value of a cell, or None for missing / empty / non-numeric."""
    v = (row.get(col) or "").strip()
    try:
        return float(v)
    except ValueError:
        return None


def days_between(row, start_col, end_col):
    try:
        a = datetime.fromisoformat(row[start_col].strip().replace("Z", "+00:00"))
        b = datetime.fromisoformat(row[end_col].strip().replace("Z", "+00:00"))
        return (b - a).total_seconds() / 86400
    except (KeyError, ValueError, AttributeError):
        return None


def baseline(row, sev):
    monthly = [num(row, f"ghsa_{sev}_count_M{m}") for m in MONTHS]
    seen = [x for x in monthly if x is not None]
    if seen:
        return sum(seen) * WINDOW_DAYS / (30.4375 * len(seen))  # rate over the observed months
    total, age = num(row, f"ghsa_{sev}_count"), days_between(row, "package_created_at", "published_at")
    if total is not None and age and age > 0:
        return total * WINDOW_DAYS / max(age, 365)  # shortcut: young packages treated as 1 year old to avoid huge rates
    return 0.0


def load_models():
    models = {}
    for s in SEVERITIES:
        path = os.path.join(MODELS, f"{s}.json")
        if os.path.exists(path):
            try:
                with open(path) as f:
                    models[s] = [t["tree_structure"] for t in json.load(f)["tree_info"]]
            except Exception as e:
                print(f"model {path} unreadable ({e}), using the baseline for {s}")
    return models


def tree_value(node, x):
    """Walk one LightGBM tree (JSON dump) with LightGBM's missing-value rules."""
    while "leaf_value" not in node:
        v = x[node["split_feature"]]
        missing = node["missing_type"]
        if (missing == "NaN" and math.isnan(v)) or (missing == "Zero" and (math.isnan(v) or abs(v) <= 1e-35)):
            left = node["default_left"]
        else:
            left = (0.0 if math.isnan(v) else v) <= node["threshold"]  # missing_type None: NaN counts as 0
        node = node["left_child"] if left else node["right_child"]
    return node["leaf_value"]


def model_predict(trees, x):
    """Poisson objective: the trees sum to log(expected count)."""
    return math.exp(sum(tree_value(t, x) for t in trees))


def predict_row(row, models):
    out = {}
    for sev, col in zip(SEVERITIES, TARGET_COLUMNS):
        try:
            if sev in models:
                from features import vector
                out[col] = model_predict(models[sev], vector(row))
            else:
                out[col] = baseline(row, sev)
        except Exception:
            try:
                out[col] = baseline(row, sev)
            except Exception:
                out[col] = 0.0  # never fail the whole prediction because of one bad cell
        out[col] = max(out[col], 0.0)
    return out


def poisson_median(lam):
    """Median of Poisson(lam): the best whole number under absolute error."""
    return 0 if lam <= 0 else max(0, math.floor(lam + 1 / 3 - 0.02 / lam))


def main(argv):
    args = [a for a in argv if not a.startswith("--")]
    if len(args) != 2:
        sys.exit(__doc__)
    integer = "--integer" in argv
    models = load_models()
    with open(args[0], newline="", encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    with open(args[1], "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=TARGET_COLUMNS)
        w.writeheader()
        for row in rows:
            pred = predict_row(row, models)
            w.writerow({c: poisson_median(v) if integer else round(v, 4) for c, v in pred.items()})
    print(f"wrote {len(rows)} prediction(s) to {args[1]}")


if __name__ == "__main__":
    main(sys.argv[1:])
