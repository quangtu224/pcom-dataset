# PCOM – npm vulnerability training dataset

Training data for predicting the **CVSS score of an npm package version one month ahead**.
Course: PCOM. Author: Quang Tu Dinh.

## Prediction function

```
python predict.py input.csv output.csv            # expected counts, e.g. 0.2464
python predict.py input.csv output.csv --integer  # rounded to whole numbers
```

`input.csv` holds one or more records in the course record schema (`course_schema.py`, header row required;
missing columns or cells are treated as NULL). `output.csv` holds one row per input row with the five
`target_ghsa_<severity>_count_90d` columns. Standard library only, no network access, runs in well under a second.

Model (pcom-entry-1): one LightGBM model with a Poisson objective per severity (`models/<severity>.json`,
trained by `train.py` on `data/training.csv`, features from `features.py`). Severities with too few
positive training records (critical, unknown) or where the model does not beat the baselines use the
historical-rate baseline: advisories in the 12 months before the version, scaled to 90 days
(the lifetime rate when there were none in the last 12 months). Since round 1 the models are strongly
regularised (at least 50 records per leaf, 150 trees, L2 = 10) to avoid over-extrapolating bursts of advisories.
The models are stored as JSON tree dumps and evaluated in plain Python, so prediction needs no
third-party package (importing LightGBM alone can exceed the 10-second limit on Windows). `--integer` outputs the median of the
predicted Poisson distribution, the best whole number under absolute error.

## Competition service (from pcom-entry-2)

`main.py` serves the automated competition rounds (template: riehlegroup/pcom-course-setup):

* `GET /health` -> `{"health": "up"}`
* `POST /predict` with `{"testdata_download_endpoint": ..., "prediction_upload_endpoint": ...}`: downloads the
  input CSV (several rows = versions of one package), predicts for the latest version with `predict.py`, and
  uploads a one-row CSV with the five target columns.

```
docker build -t pcom-api .
docker run -d --name pcom-api --restart unless-stopped -p 8000:8000 pcom-api
curl http://localhost:8000/health
```

## Training

```
pip install -r requirements.txt
python -c "import collect; collect.prune_cache()"   # drop cached data that may have changed (new versions, advisories)
python build_training.py   # data/training.csv in the course record schema (needs GITHUB_TOKEN for issue/PR fields)
python train.py            # time-based evaluation vs. baselines, then saves models/ and models/report.json
```

## Contents

| File | Purpose |
|---|---|
| `schema.sql` | Record schema (Homework 2), SQLite |
| `collect.py` | Collector: downloads public data and builds `data/pcom.db` (Python standard library only) |
| `packages_popular.txt` | Hand-picked popular npm packages (extend freely) |
| `build_training.py` | Builds `data/training.csv` in the course record schema (training data for the model) |
| `course_schema.py` | Column names of the course record schema |
| `predict.py` | Prediction function |
| `main.py`, `Dockerfile` | Web service for the automated competition rounds |
| `features.py` | Feature engineering shared by training and prediction |
| `train.py` | Trains and evaluates the LightGBM models |
| `models/` | Trained models and evaluation report |
| `data/training.csv` | Training data in the course record schema |
| `data/pcom.db` | Homework 3 dataset (SQLite); built locally by `collect.py`, committed only under tag `initial-training-data` |

## Records

* **`snapshot`** – one example = one package version at one cutoff month (first day of the month).
  Cutoffs run monthly from 2024-04-01 to the current month. For each cutoff the
  highest stable version released before the cutoff is used.
* **`monthly_metrics`** – 18 rows per snapshot, `month_offset` 1 = month just before the cutoff.
* **`package_info`** – audit table: sample group (`popular` / `advisory`) and mapped GitHub repository.

Required core data (per month, 18 months): `npm_downloads`, `github_open_issues`, `github_total_commits`.
Additional features: `npm_releases`, `known_cves_package`, `version_age_days`, `dependency_count`,
`known_cves_version`. `source_loc` and `mean_cyclomatic` are reserved and currently NULL.

**Target:** `new_cve_count` = distinct CVEs whose GitHub advisory was published in the cutoff month and whose
affected range contains the version; `max_cvss` = highest CVSS v3.x base score among them
(NULL if there is none or none is scored yet). Both are NULL while the target month is not over.

## Sources

| Data | Source |
|---|---|
| Versions, release dates, dependencies, repository URL | npm registry `registry.npmjs.org/<package>` |
| Monthly downloads | npm downloads API `api.npmjs.org/downloads/range/...` (daily values summed per month) |
| Total commits at month end | GitHub GraphQL: default-branch `history(until:)` total count |
| Open issues at month end | GitHub GraphQL search: issues created before month end − issues closed before month end (pull requests excluded) |
| CVEs, affected ranges, CVSS | GitHub Advisory Database REST API (reviewed, non-withdrawn, npm, with CVE id) |

## Package sample

* all packages in `packages_popular.txt`, plus
* 100 packages randomly sampled (seed 42) from packages that had a CVE advisory published between the first and last cutoff,
  so that the dataset contains positive targets.

## Reproduce / update

```
set GITHUB_TOKEN=<GitHub token, read-only public access is enough>     (Windows; use export on Linux/macOS)
python collect.py              # all packages
python collect.py --limit 5    # quick test
python build_training.py       # course-schema training data -> data/training.csv
```

Raw API responses are cached in `cache/` (not committed). Delete `cache/` to fetch fresh data, e.g. each
month before a new prediction round, so that new months and newly published advisories are included.

## Known limitations

* Open-issue counts are reconstructed from today's issue data: issues that were deleted or transferred, and issues
  that were closed and later reopened, can make historical counts slightly wrong.
* Commit counts use commit dates, which do not prove when the commits became public.
* Advisory affected ranges and scores are taken as they are today (later corrections are visible) – a mild form of leakage
  for `known_cves_*`.
* GitHub metrics are repository-wide, so packages in monorepos share issue/commit numbers.
* Months before a package/repository existed are NULL, not 0.
