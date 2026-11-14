"""Turn one course-schema record (dict of strings from csv.DictReader) into model features.

Shared by train.py and predict.py so both see identical features. Missing values become NaN,
which LightGBM handles natively. M0 is the most recent month.
"""
import math
from datetime import datetime
from course_schema import SEVERITIES


def num(row, col):
    try:
        v = float((row.get(col) or "").strip())
        return v if math.isfinite(v) else None
    except ValueError:
        return None


def months_sum(row, name, months):
    vals = [num(row, f"{name}_M{m}") for m in months]
    vals = [v for v in vals if v is not None]
    return sum(vals) if vals else None


def ratio(a, b):
    return a / b if a is not None and b else None


def log1p(v):
    return math.log1p(max(v, 0)) if v is not None else None


def days_between(row, a, b):
    try:
        t = [datetime.fromisoformat(row[c].strip().replace("Z", "+00:00")) for c in (a, b)]
        return (t[1] - t[0]).total_seconds() / 86400
    except (KeyError, ValueError, AttributeError):
        return None


def daily_downloads(row, months):
    """Average downloads per observed day over the given months."""
    return ratio(months_sum(row, "package_downloads", months), months_sum(row, "package_download_days_observed", months))


R3, R6, R12 = range(3), range(6), range(12)


def features(row):
    f = {
        "package_age_days": days_between(row, "package_created_at", "published_at"),
        "log_unpacked_size": log1p(num(row, "unpacked_size")),
        "log_file_count": log1p(num(row, "file_count")),
    }
    for d in ("dependency_count", "optional_dependency_count", "peer_dependency_count",
              "dev_dependency_count", "bundled_dependency_count"):
        f[d] = num(row, d)

    d3, d36, d12 = daily_downloads(row, R3), daily_downloads(row, range(3, 6)), daily_downloads(row, R12)
    f["log_daily_downloads_3m"] = log1p(d3)
    f["log_daily_downloads_12m"] = log1p(d12)
    f["downloads_trend"] = log1p(d3) - log1p(d36) if d3 is not None and d36 is not None else None
    f["stable_releases_3m"] = months_sum(row, "package_stable_release_count", R3)
    f["stable_releases_12m"] = months_sum(row, "package_stable_release_count", R12)

    for name in ("issues_opened", "issues_closed", "pull_requests_opened", "pull_requests_merged"):
        f[f"{name}_3m"] = months_sum(row, name, R3)
        f[f"{name}_12m"] = months_sum(row, name, R12)
    f["issue_close_ratio_12m"] = ratio(f["issues_closed_12m"], f["issues_opened_12m"])
    f["pr_merge_ratio_12m"] = ratio(f["pull_requests_merged_12m"], f["pull_requests_opened_12m"])
    f["log_issues_open_M0"] = log1p(num(row, "issues_open_at_month_end_M0"))
    f["log_prs_open_M0"] = log1p(num(row, "pull_requests_open_at_month_end_M0"))

    for s in SEVERITIES:
        f[f"ghsa_{s}_total"] = num(row, f"ghsa_{s}_count")
        f[f"ghsa_{s}_3m"] = months_sum(row, f"ghsa_{s}_count", R3)
        f[f"ghsa_{s}_12m"] = months_sum(row, f"ghsa_{s}_count", R12)
    for w in ("total", "3m", "12m"):
        vals = [f[f"ghsa_{s}_{w}"] for s in SEVERITIES if f[f"ghsa_{s}_{w}"] is not None]
        f[f"ghsa_all_{w}"] = sum(vals) if vals else None
    return f


FEATURE_NAMES = list(features({}).keys())


def vector(row):
    f = features(row)
    return [math.nan if f[k] is None else float(f[k]) for k in FEATURE_NAMES]
