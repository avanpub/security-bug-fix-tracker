#!/usr/bin/env python3
"""Track Chrome security bug fixes per month.

Scrapes the Chrome Releases blog (chromereleases.googleblog.com, tokenless)
via its JSON feed, filters Stable-channel desktop security posts, and
attributes the Chromium issue ids of every disclosed security fix to the
calendar month in which the post was published, deduplicated per month.
This mirrors the Firefox MFSA counting: the month of public disclosure.

The Chrome Releases blog discloses every security bug that reaches Chrome
Stable, so the monthly unique-issue-id count is the complete total.
Window: months from --since (default 2025-01-01) to the current month,
parallel to the Firefox and GHSA monthly series.

Cross-check anchors (verified 2026-09-05): the 2026-07-29 M151 stable post
claims 371 security fixes (all attributed to July 2026), and the Google
blog's 1072 figure for Chrome 149 + 150 corresponds to ~1082 unique ids
disclosed across June/July 2026 in this counting. --as-of 2026-07-30
reproduces the snapshot data.
"""
import argparse
import csv
import datetime
import json
import os
import re
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cache_util
import mfsa_table
import net_http

FEED_URL = "https://chromereleases.googleblog.com/feeds/posts/default"

_STABLE_TITLE_RE = re.compile(r"(Extended )?Stable Channel Update for Desktop")
_BUG_LINK_RE = re.compile(r"(?:issues\.chromium\.org/issues|crbug\.com)/(\d+)")
_BUG_BARE_RE = re.compile(r"\[(\d{6,10})\]")
_CLAIM_RE = re.compile(r"includes (\d+) security fixes", re.I)

CHART_TITLE = "Chrome Security Bug Fixes by Month"
CHART_SUBTITLE = "All Severities"

PALETTES = {
    "google": {"bg": "#ffffff", "bar": "#0027ea", "grid": "#9aa0a6",
               "title": "#202124", "subtitle": "#5f6368", "label": "#202124"},
    "github-green": {"bg": "#0d1117", "bar": "#3fb950", "grid": "#3d444d",
                     "title": "#f0f6fc", "subtitle": "#9198a1", "label": "#ffffff"},
    "mozilla": dict(mfsa_table.DEFAULT_PALETTE),
}


def _fetch_feed(start_index: int, max_results: int = 150) -> dict:
    url = f"{FEED_URL}?alt=json&max-results={max_results}&start-index={start_index}"
    body, _headers = net_http.http_request(url, timeout=120)
    return json.loads(body)


def _month_keys(since: datetime.date, today: datetime.date) -> list[str]:
    keys = []
    y, m = since.year, since.month
    while (y, m) <= (today.year, today.month):
        keys.append(f"{y:04d}-{m:02d}")
        m += 1
        if m == 13:
            y, m = y + 1, 1
    return keys


def _collect(since: datetime.date, as_of: datetime.date | None, cache: dict | None):
    """(bug ids by month of disclosure, per-post claims).

    Posts are immutable, so with a cache their extractions are reused and
    paging stops early once a whole page is already covered — valid only when
    the cache reaches back past --since (tracked via covered_since). Notes
    print only for posts fetched on this run.
    """
    bugs: dict[str, set[str]] = defaultdict(set)
    claims: list[tuple] = []
    seen: set[str] = set()
    posts: dict = {} if cache is None else cache.setdefault("posts", {})
    covered = cache.get("covered_since") if cache else None
    covered_ok = bool(covered and covered <= since.isoformat())
    if posts:
        # cached posts contribute up front; the feed walk below only
        # discovers posts fetched for the first time
        for cached in posts.values():
            pub = cached["published"]
            if as_of and pub > as_of.isoformat():
                continue
            bugs[pub[:7]] |= set(cached["ids"])
    index, stop = 1, False
    exhausted = False
    while not stop:
        feed = _fetch_feed(index)
        entries = feed.get("feed", {}).get("entry", [])
        if not entries:
            exhausted = True
            break
        advanced = 0
        fresh_found = False
        for entry in entries:
            link = ""
            for item in entry.get("link", []):
                if item.get("rel") == "alternate":
                    link = item.get("href", "")
                    break
            published = datetime.date.fromisoformat(entry["published"]["$t"][:10])
            if published < since:
                stop = True
            if link in seen:
                continue
            seen.add(link)
            advanced += 1
            if stop:
                continue
            if as_of and published > as_of:
                continue
            cached = posts.get(link)
            if cached is not None:
                bugs[published.strftime("%Y-%m")] |= set(cached["ids"])
                continue
            fresh_found = True
            title = entry.get("title", {}).get("$t", "")
            if not _STABLE_TITLE_RE.search(title):
                posts[link] = {"published": published.isoformat(), "ids": [],
                               "claimed": None, "note": None}
                continue
            content = entry.get("content", {}).get("$t", "")
            m = re.search(r"Security Fixes", content, re.I)
            if not m:
                note = f"note: {published} {title!r} has no security-fix section"
                posts[link] = {"published": published.isoformat(), "ids": [],
                               "claimed": None, "note": note}
                print(note)
                continue
            sec = content[m.start():]
            ids = set(_BUG_LINK_RE.findall(sec)) | set(_BUG_BARE_RE.findall(sec))
            if not ids:
                note = f"note: {published} {title!r}: no issue ids found; skipped"
                posts[link] = {"published": published.isoformat(), "ids": [],
                               "claimed": None, "note": note}
                print(note)
                continue
            bugs[published.strftime("%Y-%m")] |= ids
            plain = re.sub(r"<[^>]+>", " ", sec)
            cm = _CLAIM_RE.search(plain)
            claims.append((published, int(cm.group(1)) if cm else None, len(ids)))
            posts[link] = {"published": published.isoformat(), "ids": sorted(ids),
                           "claimed": int(cm.group(1)) if cm else None, "note": None}
        if advanced == 0:
            exhausted = True
            break
        if not stop and cache is not None and not fresh_found and covered_ok:
            break
        index += len(entries)
    if cache is not None and (stop or exhausted):
        candidates = [c for c in (covered, since.isoformat()) if c]
        cache["covered_since"] = min(candidates)
    return bugs, claims


def _write_tsv(rows: list[list], out: str) -> None:
    with open(out, "w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh, delimiter="\t", lineterminator="\n")
        writer.writerow(["month", "bug_count"])
        writer.writerows(rows)


def _read_tsv(path: str) -> list[list]:
    rows = []
    with open(path, encoding="utf-8", newline="") as fh:
        reader = csv.reader(fh, delimiter="\t")
        next(reader, None)
        for r in reader:
            if not r:
                continue
            if not re.fullmatch(r"\d{4}-\d{2}", r[0]):
                raise ValueError(f"invalid month in {path}: {r[0]}")
            rows.append([r[0], int(r[1])])
    if not rows:
        raise ValueError(f"no monthly rows in {path}")
    return rows


def _write_chart_file(rows: list[list], out: str, today: datetime.date, palette: str) -> None:
    if not out:
        return
    mfsa_table._write_chart(rows, out, today, today,
                            title=CHART_TITLE, subtitle_label=CHART_SUBTITLE,
                            palette=PALETTES[palette])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--since", default="2025-01-01",
                        help="First month of the series (YYYY-MM-DD).")
    parser.add_argument("--as-of", default=None,
                        help="Only use posts published on/before this date (YYYY-MM-DD).")
    parser.add_argument("--out", default="chrome_monthly.tsv", help="Output TSV path.")
    parser.add_argument("--chart", default="chrome_monthly_chart.svg",
                        help="Output SVG chart path (empty string disables).")
    parser.add_argument("--chart-only", action="store_true",
                        help="Regenerate only the chart from the existing TSV.")
    parser.add_argument("--no-cache", action="store_true",
                        help="Bypass .cache/: refetch and re-extract every post.")
    parser.add_argument("--palette", default="google", choices=sorted(PALETTES),
                        help="Color scheme for the SVG chart.")
    args = parser.parse_args()

    today = datetime.date.today()
    cache = None
    if not args.no_cache:
        cache = cache_util.load_json("chrome_posts.json")
        if not isinstance(cache, dict):
            cache = {}

    if args.chart_only:
        rows = _read_tsv(args.out)
        _write_chart_file(rows, args.chart, today, args.palette)
        print(f"wrote chart to {args.chart} (palette: {args.palette}, {len(rows)} months)")
        return 0

    since = datetime.date.fromisoformat(args.since)
    as_of = datetime.date.fromisoformat(args.as_of) if args.as_of else None
    try:
        bugs, claims = _collect(since, as_of, cache)
    except (OSError, RuntimeError) as exc:
        print(f"error: feed fetch failed ({exc}); nothing was written")
        return 1
    if cache is not None:
        cache_util.save_json("chrome_posts.json", cache)

    for published, claimed, n_ids in claims:
        if claimed and claimed != n_ids:
            print(f"note: {published}: post claims {claimed} fixes, "
                  f"{n_ids} issue ids listed")

    months = _month_keys(since, today)
    rows = [[m, len(bugs.get(m, ()))] for m in months]
    _write_tsv(rows, args.out)
    for m, n in rows:
        print(f"{m}: {n} security bugs")
    print(f"wrote {len(rows)} months to {args.out}")

    _write_chart_file(rows, args.chart, today, args.palette)
    if args.chart:
        print(f"wrote chart to {args.chart}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
