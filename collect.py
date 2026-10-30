#!/usr/bin/env python3
"""PCOM training-data collector: npm + GitHub + GitHub Advisory Database -> data/pcom.db.

Usage:  set GITHUB_TOKEN=<read-only token>      (Windows cmd)
        python collect.py                         (all packages)
        python collect.py --limit 5               (quick test)
Only the Python standard library is used. Raw API responses are cached in cache/,
so a re-run is fast and repeatable; delete cache/ to fetch fresh data.
"""
import argparse, hashlib, json, os, random, re, sqlite3, sys, time
import urllib.error, urllib.parse, urllib.request
from datetime import date, datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(HERE, "data", "pcom.db")
CACHE = os.path.join(HERE, "cache")
FIRST_CUTOFF = date(2024, 4, 1)
LAST_CUTOFF = date(2026, 10, 1)
HISTORY = 18          # months of features before each cutoff
N_ADVISORY = 100      # packages sampled from those with recent CVE advisories
SEED = 42
TOKEN = os.environ.get("GITHUB_TOKEN", "").strip()
WARNINGS = []


# ---------------------------------------------------------------- helpers
def add_months(d, n):
    m = d.year * 12 + d.month - 1 + n
    return date(m // 12, m % 12 + 1, 1)


def month_starts(first, last):
    """All first-of-month dates from first to last inclusive."""
    out, d = [], first
    while d <= last:
        out.append(d)
        d = add_months(d, 1)
    return out


def iso_date(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00")).date()


SEMVER = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+.*)?$")


def parse_version(v):
    """Semver -> sortable tuple; None if not semver. Release sorts above its prereleases."""
    m = SEMVER.match(v.strip())
    if not m:
        return None
    pre = m.group(4)
    # shortcut: prerelease ids compared as plain strings, fine since we only use them for range checks
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)), 1 if pre is None else 0, pre or "")


def in_range(version, rng):
    """GitHub advisory range, e.g. '>= 1.0.0, < 1.2.3' or '<= 0.5.0' or '= 2.0.1'."""
    v = parse_version(version)
    if v is None:
        return False
    for part in rng.split(","):
        m = re.match(r"^\s*(>=|<=|>|<|=)\s*(\S+)\s*$", part)
        if not m:
            return False
        op, bound = m.group(1), parse_version(m.group(2))
        if bound is None:
            return False
        ok = {">=": v >= bound, "<=": v <= bound, ">": v > bound, "<": v < bound, "=": v == bound}[op]
        if not ok:
            return False
    return True


def github_repo(meta):
    """'owner/name' from the npm repository field, or None."""
    repo = meta.get("repository")
    url = repo.get("url", "") if isinstance(repo, dict) else (repo or "")
    m = re.search(r"github\.com[/:]([\w.-]+)/([\w.-]+?)(?:\.git)?(?:[/#].*)?$", url)
    if m:
        return f"{m.group(1)}/{m.group(2)}"
    m = re.match(r"^(?:github:)?([\w.-]+)/([\w.-]+)$", url)  # shorthand "owner/repo"
    return f"{m.group(1)}/{m.group(2)}" if m else None


# ---------------------------------------------------------------- HTTP with cache
def fetch(url, body=None, headers=None, use_cache=True):  # use_cache=False forces a refetch
    """GET/POST returning (json, response headers). Retries on rate limits and 5xx."""
    key = hashlib.sha1((url + (body or "")).encode()).hexdigest()
    path = os.path.join(CACHE, key[:2], key + ".json")
    if use_cache and os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            c = json.load(f)
        return c["data"], c["headers"]
    hdr = {"User-Agent": "pcom-dataset-collector", **(headers or {})}
    for attempt in range(6):
        req = urllib.request.Request(url, data=body.encode() if body else None, headers=hdr)
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                data = json.loads(r.read().decode("utf-8"))
                rh = {k.lower(): v for k, v in r.headers.items()}
            break
        except urllib.error.HTTPError as e:
            if e.code == 404:
                raise
            if e.code in (403, 429) and e.headers.get("x-ratelimit-remaining") == "0":
                wait = max(int(e.headers.get("x-ratelimit-reset", "0")) - time.time(), 0) + 5
                print(f"  rate limit reached, waiting {wait:.0f}s")
                time.sleep(wait)
            elif e.code in (403, 429, 500, 502, 503, 504):
                time.sleep(int(e.headers.get("retry-after") or 10 * (attempt + 1)))
            else:
                raise
        except (urllib.error.URLError, TimeoutError):
            time.sleep(5 * (attempt + 1))
    else:
        raise RuntimeError(f"giving up on {url}")
    if isinstance(data, dict) and data.get("errors"):
        return data, rh  # never cache GraphQL errors
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"url": url, "fetched_at": datetime.now(timezone.utc).isoformat(), "data": data,
                   "headers": {k: rh[k] for k in ("link",) if k in rh}}, f)
    return data, rh


def gh_headers():
    h = {"Accept": "application/vnd.github+json"}
    if TOKEN:
        h["Authorization"] = f"Bearer {TOKEN}"
    return h


# ---------------------------------------------------------------- sources
def load_advisories():
    """{package: [(cve, published_date, range, cvss31_or_None), ...]} for reviewed, non-withdrawn npm CVEs."""
    out = {}
    url = "https://api.github.com/advisories?ecosystem=npm&type=reviewed&per_page=100"
    pages = 0
    while url:
        data, h = fetch(url, headers=gh_headers())
        pages += 1
        for a in data:
            if a.get("withdrawn_at") or not a.get("cve_id"):
                continue
            v3 = (a.get("cvss_severities") or {}).get("cvss_v3") or {}
            score = v3.get("score") if v3.get("vector_string") else None  # score 0.0 without vector = unscored
            for vuln in a.get("vulnerabilities") or []:
                p = vuln.get("package") or {}
                if p.get("ecosystem") == "npm" and vuln.get("vulnerable_version_range"):
                    out.setdefault(p["name"], []).append(
                        (a["cve_id"], iso_date(a["published_at"]), vuln["vulnerable_version_range"], score))
        m = re.search(r'<([^>]+)>;\s*rel="next"', h.get("link", ""))
        url = m.group(1) if m else None
    print(f"advisories: {pages} pages, {sum(map(len, out.values()))} CVE/package entries, {len(out)} packages")
    return out


def registry(pkg):
    data, _ = fetch("https://registry.npmjs.org/" + pkg.replace("/", "%2F"))
    return data


def monthly_downloads(pkg, months):
    """{month_start: downloads} using range queries of at most one year each."""
    per_day = {}
    start = months[0]
    end = add_months(months[-1], 1)
    while start < end:
        stop = min(add_months(start, 12), end)
        url = f"https://api.npmjs.org/downloads/range/{start}:{date.fromordinal(stop.toordinal() - 1)}/{pkg}"
        data, _ = fetch(url)
        for d in data.get("downloads", []):
            per_day[d["day"]] = d["downloads"]
        start = stop
    out = {}
    for m in months:
        key = m.isoformat()[:7]
        days = [n for day, n in per_day.items() if day.startswith(key)]
        out[m] = sum(days) if days else None
    return out


def github_monthly(full_name, month_ends):
    """{month_end: (open_issues, total_commits)} via GraphQL, 12 month ends per query."""
    owner, name = full_name.split("/")
    out = {}
    for i in range(0, len(month_ends), 12):
        chunk = month_ends[i:i + 12]
        hist = " ".join(f'c{j}: history(until: "{d}T00:00:00Z") {{ totalCount }}' for j, d in enumerate(chunk))
        search = " ".join(
            f'o{j}: search(query: "repo:{full_name} is:issue created:<{d}", type: ISSUE) {{ issueCount }} '
            f'x{j}: search(query: "repo:{full_name} is:issue closed:<{d}", type: ISSUE) {{ issueCount }}'
            for j, d in enumerate(chunk))
        q = (f'query {{ repository(owner: "{owner}", name: "{name}") {{ createdAt '
             f'defaultBranchRef {{ target {{ ... on Commit {{ {hist} }} }} }} }} {search} }}')
        for attempt in range(4):
            data, _ = fetch("https://api.github.com/graphql", body=json.dumps({"query": q}), headers=gh_headers(),
                            use_cache=attempt == 0)
            if "RATE_LIMIT" not in str(data.get("errors")).upper():
                break
            print("  GitHub secondary rate limit, waiting 60s")
            time.sleep(60)
        if data.get("errors") or not (data.get("data") or {}).get("repository"):
            raise RuntimeError(f"GraphQL error for {full_name}: {str(data.get('errors'))[:200]}")
        d = data["data"]
        created = iso_date(d["repository"]["createdAt"])
        target = ((d["repository"].get("defaultBranchRef") or {}).get("target")) or {}
        for j, me in enumerate(chunk):
            if me <= created:
                out[me] = (None, None)  # repository did not exist yet
                continue
            commits = (target.get(f"c{j}") or {}).get("totalCount")
            out[me] = (d[f"o{j}"]["issueCount"] - d[f"x{j}"]["issueCount"], commits)
    return out


# ---------------------------------------------------------------- package selection
def choose_packages(advisories):
    popular = [l.strip() for l in open(os.path.join(HERE, "packages_popular.txt"), encoding="utf-8")
               if l.strip() and not l.startswith("#")]
    recent = sorted(p for p, rows in advisories.items()
                    if p not in popular and any(FIRST_CUTOFF <= r[1] < LAST_CUTOFF for r in rows))
    sampled = random.Random(SEED).sample(recent, min(N_ADVISORY, len(recent)))
    return [(p, "popular") for p in popular] + [(p, "advisory") for p in sorted(sampled)]


# ---------------------------------------------------------------- build records
def build_package(db, pkg, advisories, cutoffs, today):
    meta = registry(pkg)
    times = {v: iso_date(t) for v, t in (meta.get("time") or {}).items() if v not in ("created", "modified")}
    created = iso_date(meta["time"]["created"]) if "created" in (meta.get("time") or {}) else None
    stable = [(parse_version(v), v) for v in times if parse_version(v) and parse_version(v)[3] == 1]
    advs = advisories.get(pkg, [])
    repo = github_repo(meta)

    months = month_starts(add_months(cutoffs[0], -HISTORY), add_months(cutoffs[-1], -1))
    try:
        dl = monthly_downloads(pkg, months)
    except Exception as e:
        WARNINGS.append(f"{pkg}: downloads unavailable ({e})")
        dl = {}
    gh = {}
    if repo and TOKEN:
        try:
            gh = github_monthly(repo, [add_months(m, 1) for m in months])
        except Exception as e:
            WARNINGS.append(f"{pkg}: GitHub data unavailable ({e})")

    n = 0
    for c in cutoffs:
        released = [(t, v) for t, v in stable if times[v] < c]
        if not released:
            continue
        version = max(released)[1]  # highest stable semver released before the cutoff
        rel = times[version]

        def cves(lo, hi, versioned):
            return {cve: s for cve, pub, rng, s in advs
                    if lo <= pub < hi and (not versioned or in_range(version, rng))}

        known = cves(date.min, c, True)
        new_count = max_cvss = None
        if add_months(c, 1) <= today:  # target month is over -> label is known
            new = cves(c, add_months(c, 1), True)
            new_count = len(new)
            scores = [s for s in new.values() if s is not None]
            max_cvss = max(scores) if scores else None
        deps = len((meta.get("versions", {}).get(version) or {}).get("dependencies") or {})
        cur = db.execute(
            "INSERT INTO snapshot (package_name, package_version, cutoff_date, version_age_days, dependency_count,"
            " known_cves_version, source_loc, mean_cyclomatic, new_cve_count, max_cvss)"
            " VALUES (?,?,?,?,?,?,NULL,NULL,?,?)",
            (pkg, version, c.isoformat(), (c - rel).days, deps, len(known), new_count, max_cvss))
        sid = cur.lastrowid
        for off in range(1, HISTORY + 1):
            m = add_months(c, -off)
            me = add_months(m, 1)
            alive = created is None or created < me
            issues, commits = gh.get(me, (None, None))
            releases = sum(1 for v, t in times.items() if m <= t < me) if alive else None
            db.execute("INSERT INTO monthly_metrics VALUES (?,?,?,?,?,?,?)",
                       (sid, off, dl.get(m) if alive else None, issues, commits, releases,
                        len(cves(date.min, me, False))))
        n += 1
    return repo, n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, help="only the first N packages (for testing)")
    args = ap.parse_args()
    if not TOKEN:
        print("WARNING: GITHUB_TOKEN not set -> GitHub issues/commits will be NULL and advisory paging is slow.")

    today = datetime.now(timezone.utc).date()
    cutoffs = month_starts(FIRST_CUTOFF, min(LAST_CUTOFF, date(today.year, today.month, 1)))
    advisories = load_advisories()
    packages = choose_packages(advisories)[: args.limit]

    os.makedirs(os.path.dirname(DB), exist_ok=True)
    if os.path.exists(DB):
        os.remove(DB)  # always rebuilt from cache/ so the DB matches the code
    db = sqlite3.connect(DB)
    db.executescript(open(os.path.join(HERE, "schema.sql"), encoding="utf-8").read())
    db.execute("PRAGMA foreign_keys = ON")
    db.execute("CREATE TABLE package_info (package_name TEXT PRIMARY KEY, sample_group TEXT, github_repo TEXT)")

    for i, (pkg, group) in enumerate(packages, 1):
        try:
            repo, n = build_package(db, pkg, advisories, cutoffs, today)
            db.execute("INSERT INTO package_info VALUES (?,?,?)", (pkg, group, repo))
            print(f"[{i}/{len(packages)}] {pkg}: {n} snapshots (repo: {repo})")
        except Exception as e:
            WARNINGS.append(f"{pkg}: skipped ({e})")
            print(f"[{i}/{len(packages)}] {pkg}: SKIPPED ({e})")
        db.commit()

    print("\n== summary ==")
    for t, cols in [("snapshot", ["new_cve_count", "max_cvss"]),
                    ("monthly_metrics", ["npm_downloads", "github_open_issues", "github_total_commits"])]:
        total = db.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
        print(f"{t}: {total} rows; " + ", ".join(
            f"{c} NULL={db.execute(f'SELECT COUNT(*) FROM {t} WHERE {c} IS NULL').fetchone()[0]}" for c in cols))
    print("snapshots with new_cve_count > 0:",
          db.execute("SELECT COUNT(*) FROM snapshot WHERE new_cve_count > 0").fetchone()[0])
    print(f"{len(WARNINGS)} warnings" + (" (see data/warnings.txt)" if WARNINGS else ""))
    with open(os.path.join(HERE, "data", "warnings.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(WARNINGS) + "\n")
    db.close()


if __name__ == "__main__":
    main()
