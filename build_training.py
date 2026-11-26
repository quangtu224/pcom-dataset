#!/usr/bin/env python3
"""Build data/training.csv in the course record schema (course_schema.py).

Usage:  set GITHUB_TOKEN=<token>   (PowerShell: $env:GITHUB_TOKEN = "<token>")
        python build_training.py              (all packages)
        python build_training.py --limit 5    (quick test)

One record = one stable package version at its publication time.
  * features: the 12 calendar months before the publication month (M0 = most recent month)
  * targets : GitHub-reviewed advisories (GHSA) naming the package, published in the 90 days
              after publication, counted per severity
Per package at most one record per 90 days, so target windows do not overlap.
Uses collect.py's cached API access (same packages as the Homework 3 dataset).
"""
import argparse, csv, os
from datetime import date, datetime, timedelta, timezone
import collect as c
from course_schema import INPUT_COLUMNS, SEVERITIES, TARGET_COLUMNS

OUT = os.path.join(c.HERE, "data", "training.csv")
ANCHOR_START = date(2023, 11, 1)   # earliest publication date; 12 months of history must exist before it
WINDOW = 90
SEVERITY = {"low": "low", "medium": "moderate", "moderate": "moderate", "high": "high", "critical": "critical"}


# ---------------------------------------------------------------- small helpers
def history_months(pub):
    """Month starts M0..M11 – the 12 full calendar months before the publication month."""
    first = date(pub.year, pub.month, 1)
    return [c.add_months(first, -(m + 1)) for m in range(12)]


def ts(s):
    """npm timestamp -> RFC 3339 UTC with exactly three fractional digits."""
    d = datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)
    return d.strftime("%Y-%m-%dT%H:%M:%S.") + f"{d.microsecond // 1000:03d}Z"


def purl(pkg, version):
    return "pkg:npm/" + ("%40" + pkg[1:] if pkg.startswith("@") else pkg) + "@" + version


def names(x):
    return set(x) if isinstance(x, (dict, list)) else set()


def dependency_counts(man):
    bundled = man.get("bundleDependencies", man.get("bundledDependencies"))
    if bundled is True:  # 'true' means: bundle all dependencies
        bundled = man.get("dependencies")
    return {
        "dependency_count": len(names(man.get("dependencies"))),
        "optional_dependency_count": len(names(man.get("optionalDependencies"))),
        "peer_dependency_count": len(names(man.get("peerDependencies")) | names(man.get("peerDependenciesMeta"))),
        "dev_dependency_count": len(names(man.get("devDependencies"))),
        "bundled_dependency_count": len(names(bundled)),
    }


def choose_anchors(stable, today):
    """Stable (date, version) pairs, at most one per 90 days, whose 90-day target window is over."""
    out, last = [], None
    for d, v in sorted(stable):
        if ANCHOR_START <= d <= today - timedelta(days=WINDOW) and (last is None or d >= last + timedelta(days=WINDOW)):
            out.append((d, v))
            last = d
    return out


# ---------------------------------------------------------------- GitHub issue / PR history
def github_counts(full_name, boundaries):
    """{boundary: (issues created<, issues closed<, PRs created<, PRs closed<, PRs merged<)} and repo creation date."""
    out, created = {}, None
    for i in range(0, len(boundaries), 6):
        chunk = boundaries[i:i + 6]
        parts = []
        for j, b in enumerate(chunk):
            for key, q in (("ic", "is:issue created"), ("ix", "is:issue closed"), ("pc", "is:pr created"),
                           ("px", "is:pr closed"), ("pm", "is:pr merged")):
                parts.append(f'{key}{j}: search(query: "repo:{full_name} {q}:<{b}", type: ISSUE) {{ issueCount }}')
        owner, name = full_name.split("/")
        d = c.graphql(f'query {{ repository(owner: "{owner}", name: "{name}") {{ createdAt }} {" ".join(parts)} }}',
                      full_name)
        created = c.iso_date(d["repository"]["createdAt"])
        for j, b in enumerate(chunk):
            out[b] = tuple(d[f"{k}{j}"]["issueCount"] for k in ("ic", "ix", "pc", "px", "pm"))
    return out, created


def github_month(gh, repo_created, m):
    """Course-schema GitHub fields for month m from cumulative counts at its two boundaries."""
    e = c.add_months(m, 1)
    if not gh or m not in gh or e not in gh or repo_created is None or e <= repo_created:
        return {}
    (ic0, ix0, pc0, px0, pm0), (ic1, ix1, pc1, px1, pm1) = gh[m], gh[e]
    merged = pm1 - pm0
    return {
        "issues_opened": ic1 - ic0,
        "issues_closed": ix1 - ix0,  # shortcut: final closure dates only; repeated closures need issue events
        "pull_requests_opened": pc1 - pc0,
        "pull_requests_merged": merged,
        "pull_requests_closed_unmerged": max(px1 - px0 - merged, 0),
        "issues_open_at_month_end": ic1 - ix1,
        "pull_requests_open_at_month_end": pc1 - px1,
        # issues_reopened / pull_requests_reopened stay NULL: they need per-issue event history
    }


# ---------------------------------------------------------------- one package
def package_records(pkg, ghsa, today, warnings):
    meta = c.registry(pkg)
    t = meta.get("time") or {}
    if "created" not in t:
        return []
    created = c.iso_date(t["created"])
    pubs = {v: c.iso_date(s) for v, s in t.items() if v not in ("created", "modified")}
    stable = [(d, v) for v, d in pubs.items() if c.parse_version(v) and c.parse_version(v)[3] == 1]
    anchors = [(d, v) for d, v in choose_anchors(stable, today) if v in (meta.get("versions") or {})]
    if not anchors:
        return []

    try:  # same start month as collect.py (cached yearly chunks are reused), up to the last full month
        daily = c.daily_downloads(pkg, c.month_starts(c.add_months(c.FIRST_CUTOFF, -c.HISTORY),
                                                      c.add_months(date(today.year, today.month, 1), -1)))
    except Exception as e:
        warnings.append(f"{pkg}: downloads unavailable ({e})")
        daily = {}
    repo, gh, repo_created = c.github_repo(meta), {}, None
    if repo and c.TOKEN:
        try:
            gh, repo_created = github_counts(repo, c.month_starts(c.add_months(ANCHOR_START, -12),
                                                                 date(today.year, today.month, 1)))
        except Exception as e:
            warnings.append(f"{pkg}: GitHub data unavailable ({e})")
    advisories = [(d, SEVERITY.get((s or "").lower(), "unknown")) for d, s in ghsa.get(pkg, {}).values()]

    rows = []
    for pub, version in anchors:
        man = meta["versions"][version]
        dist = man.get("dist") or {}
        r = {"purl": purl(pkg, version), "package_created_at": ts(t["created"]), "published_at": ts(t[version]),
             "unpacked_size": dist.get("unpackedSize"), "file_count": dist.get("fileCount"), **dependency_counts(man)}
        for sev in SEVERITIES:
            r[f"ghsa_{sev}_count"] = sum(1 for d, s in advisories if s == sev and d < pub)
            r[f"target_ghsa_{sev}_count_90d"] = sum(
                1 for d, s in advisories if s == sev and pub <= d < pub + timedelta(days=WINDOW))
        for i, m in enumerate(history_months(pub)):
            e = c.add_months(m, 1)
            for sev in SEVERITIES:
                r[f"ghsa_{sev}_count_M{i}"] = sum(1 for d, s in advisories if s == sev and m <= d < e)
            if e <= created:
                continue  # package did not exist yet: npm fields stay NULL
            days = [n for day, n in daily.items() if m.isoformat() <= day < e.isoformat() and day >= created.isoformat()]
            if days:
                r[f"package_downloads_M{i}"] = sum(days)
                r[f"package_download_days_observed_M{i}"] = len(days)
            r[f"package_stable_release_count_M{i}"] = sum(1 for d, _ in stable if m <= d < e)
            for k, v in github_month(gh, repo_created, m).items():
                r[f"{k}_M{i}"] = v
        rows.append(r)
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, help="only the first N packages (for testing)")
    args = ap.parse_args()
    if not c.TOKEN:
        print("WARNING: GITHUB_TOKEN not set -> GitHub issue/PR fields will be NULL.")
    today = datetime.now(timezone.utc).date()
    packages = c.choose_packages(c.load_advisories())[: args.limit]
    ghsa = c.load_ghsa()

    rows, warnings = [], []
    for i, (pkg, _) in enumerate(packages, 1):
        try:
            recs = package_records(pkg, ghsa, today, warnings)
            rows += recs
            print(f"[{i}/{len(packages)}] {pkg}: {len(recs)} records")
        except Exception as e:
            warnings.append(f"{pkg}: skipped ({e})")
            print(f"[{i}/{len(packages)}] {pkg}: SKIPPED ({e})")

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=INPUT_COLUMNS + TARGET_COLUMNS)
        w.writeheader()
        w.writerows(rows)
    with open(os.path.join(c.HERE, "data", "training_warnings.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(warnings) + "\n")

    print(f"\n== summary ==\n{len(rows)} records written to {OUT}")
    for col in TARGET_COLUMNS:
        print(f"  {col}: {sum(1 for r in rows if r[col] > 0)} records > 0")
    for col in ("package_downloads_M0", "issues_open_at_month_end_M0", "unpacked_size"):
        print(f"  {col}: {sum(1 for r in rows if r.get(col) is None)} NULL")
    print(f"{len(warnings)} warnings (see data/training_warnings.txt)")


if __name__ == "__main__":
    main()
