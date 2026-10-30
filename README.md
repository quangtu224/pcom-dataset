# PCOM – npm vulnerability training dataset

Training data for predicting the **CVSS score of an npm package version one month ahead**.
Course: PCOM. Author: Quang Tu Dinh.

## Contents

| File | Purpose |
|---|---|
| `schema.sql` | Record schema (Homework 2), SQLite |
| `collect.py` | Collector: downloads public data and builds `data/pcom.db` (Python standard library only) |
| `packages_popular.txt` | Hand-picked popular npm packages (extend freely) |
| `test_collect.py` | Offline checks of date, version-range and repository parsing logic |
| `data/pcom.db` | The training dataset (SQLite) |
| `data/warnings.txt` | Data that could not be collected in the last run |

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
python test_collect.py
python collect.py              # all packages
python collect.py --limit 5    # quick test
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
