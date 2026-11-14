"""Column names of the course record schema (professor's version, M0..M11)."""

MONTHS = range(12)
SEVERITIES = ["low", "moderate", "high", "critical", "unknown"]

_MONTHLY = [
    "package_downloads", "package_download_days_observed", "package_stable_release_count",
    "issues_opened", "issues_closed", "issues_reopened",
    "pull_requests_opened", "pull_requests_closed_unmerged", "pull_requests_merged", "pull_requests_reopened",
    "issues_open_at_month_end", "pull_requests_open_at_month_end",
]

INPUT_COLUMNS = (
    ["purl", "package_created_at", "published_at",
     "unpacked_size", "file_count", "dependency_count", "optional_dependency_count",
     "peer_dependency_count", "dev_dependency_count", "bundled_dependency_count"]
    + [f"{name}_M{m}" for name in _MONTHLY for m in MONTHS]
    + [f"ghsa_{s}_count" for s in SEVERITIES]
    + [f"ghsa_{s}_count_M{m}" for s in SEVERITIES for m in MONTHS]
)

TARGET_COLUMNS = [f"target_ghsa_{s}_count_90d" for s in SEVERITIES]
