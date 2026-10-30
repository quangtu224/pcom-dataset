"""Offline checks for the collector's logic: python test_collect.py"""
import sqlite3
from datetime import date
from collect import add_months, github_repo, in_range, month_starts, parse_version

assert add_months(date(2026, 10, 1), -18) == date(2025, 4, 1)
assert add_months(date(2025, 12, 1), 1) == date(2026, 1, 1)
assert len(month_starts(date(2025, 4, 1), date(2026, 9, 1))) == 18

assert parse_version("1.2.3") < parse_version("1.10.0")
assert parse_version("2.0.0-beta.1") < parse_version("2.0.0")
assert parse_version("not-a-version") is None

assert in_range("0.5.0", "<= 0.5.0") and not in_range("0.5.1", "<= 0.5.0")
assert in_range("1.2.2", ">= 1.0.0, < 1.2.3") and not in_range("1.2.3", ">= 1.0.0, < 1.2.3")
assert in_range("2.0.1", "= 2.0.1") and not in_range("2.0.2", "= 2.0.1")
assert not in_range("0.9.9", ">= 1.0.0, < 1.2.3")

assert github_repo({"repository": {"url": "git+https://github.com/lodash/lodash.git"}}) == "lodash/lodash"
assert github_repo({"repository": "github:expressjs/express"}) == "expressjs/express"
assert github_repo({"repository": {"url": "https://github.com/babel/babel.git", "directory": "packages/x"}}) == "babel/babel"
assert github_repo({"repository": "https://gitlab.com/a/b"}) is None
assert github_repo({}) is None

db = sqlite3.connect(":memory:")
db.executescript(open("schema.sql", encoding="utf-8").read())
print("all tests passed")
