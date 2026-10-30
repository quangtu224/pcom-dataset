-- PCOM Homework 2: record schema for one-month-ahead CVSS prediction (npm)
-- Tested with SQLite 3. Run "PRAGMA foreign_keys = ON;" before inserting.

-- One row = one prediction example (package version at a cutoff month)
CREATE TABLE snapshot (
    id INTEGER PRIMARY KEY,
    package_name TEXT NOT NULL,
    package_version TEXT NOT NULL,
    cutoff_date TEXT NOT NULL CHECK (date(cutoff_date, 'start of month') IS cutoff_date),
    version_age_days INTEGER CHECK (version_age_days >= 0),
    dependency_count INTEGER CHECK (dependency_count >= 0),
    known_cves_version INTEGER CHECK (known_cves_version >= 0),
    source_loc INTEGER CHECK (source_loc >= 0),
    mean_cyclomatic REAL CHECK (mean_cyclomatic >= 1),
    new_cve_count INTEGER CHECK (new_cve_count >= 0),
    max_cvss REAL CHECK (max_cvss BETWEEN 0 AND 10),
    UNIQUE (package_name, package_version, cutoff_date),
    CHECK (max_cvss IS NULL OR new_cve_count > 0)
);

-- 18 rows per snapshot: month_offset 1 = month just before cutoff_date
CREATE TABLE monthly_metrics (
    snapshot_id INTEGER NOT NULL REFERENCES snapshot(id),
    month_offset INTEGER NOT NULL CHECK (month_offset BETWEEN 1 AND 18),
    npm_downloads INTEGER CHECK (npm_downloads >= 0),
    github_open_issues INTEGER CHECK (github_open_issues >= 0),
    github_total_commits INTEGER CHECK (github_total_commits >= 0),
    npm_releases INTEGER CHECK (npm_releases >= 0),
    known_cves_package INTEGER CHECK (known_cves_package >= 0),
    PRIMARY KEY (snapshot_id, month_offset)
);
