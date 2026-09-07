#!/usr/bin/env python3
"""Track Red Hat security fixes (CVEs) per release month.

Fetches the Red Hat Security Data API in CSAF format
(https://access.redhat.com/hydra/rest/securitydata, tokenless — no API key
needed). The CVRF format is deprecated and no longer served; the CSAF list
endpoint returns, for a date window, every security advisory (RHSA, plus the
occasional CVE-carrying RHEA) with its severity rating, initial release
timestamp, and the full set of CVEs it addresses — so no per-advisory
documents need to be fetched.

Counting rule:
  * window: an advisory counts for the month of its INITIAL release date
    (the date part of the list entry's released_on, which equals the CSAF
    document's initial_release_date). The list's date filter is also keyed on
    the initial release date, so an advisory revised months later still
    appears in — and its current CVE set still counts toward — its initial
    month, the same way MSRC's monthly documents are treated here.
  * total: unique CVE ids across the month's advisories. A CVE fixed by
    advisories in several months (e.g. RHEL 8 in January, RHEL 9 in February)
    counts in every such month — each is a distinct fix delivery. CVEs that
    only appear in advisories released before --since are not counted in
    earlier months (the series starts there).
  * severity per CVE is the maximum advisory rating (Critical > Important >
    Moderate > Low) across the advisories fixing it that month; entries
    without a usable rating land in "unknown".
  * advisory-count context is printed per month and summarized in the README;
    the TSV tracks CVEs only (same shape as the MSRC tracker).

Revisions update advisories in place (the CVE set grows), and even
years-old advisories are occasionally revised — so completed months are NOT
immutable history and nothing is cached; every run refetches the whole
windowed list (~20-40 requests). This mirrors the Android tracker's
refetch-by-design rationale. There is deliberately no --no-cache flag.

Cross-check anchors (verified 2026-09-07):
  * advisory counts: the 2025 windows contain 3,730 RHSAs vs the Red Hat
    Product Security Risk Report 2025's "3,781 security advisories released
    in 2025" (−1.3%), with Low exactly 75 = 75, Critical 18 vs 19, Important
    2,457 vs 2,489, Moderate 1,180 vs 1,198. The report was frozen ~April
    2026 from Red Hat's internal errata data; the live CSAF list additionally
    drops reissued/withdrawn documents. Direction and size match the other
    trackers' snapshot-vs-live tolerances.
  * data integrity: windowed fetches are lossless — a single full-year window
    (2025) returns exactly the same 3,814 entries as the sum of its 12
    monthly windows (7 advisories carry an old-year RHSA number, e.g. a
    reissued RHSA-2024:xxxx, and are bucketed by their actual release date).
  * three-way agreement for 4 sampled advisories across 4 months and all 4
    severities (RHSA-2025:0851, RHSA-2025:8298, RHSA-2026:9742,
    RHSA-2026:61259 — each revised since initial release): the list entry's
    released_on equals the CSAF document's initial_release_date, and the
    CVE set agrees across the list entry, the individual CSAF document
    (/csaf/{id}.json), and the CVE endpoint (/cve.json?advisory={id}).
"""
import argparse
import csv
import datetime
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mfsa_table
import net_http

CSAF_LIST_URL = "https://access.redhat.com/hydra/rest/securitydata/csaf.json"
PER_PAGE = 1000

SEV_RANK = {"low": 1, "moderate": 2, "important": 3, "critical": 4}
SEVERITIES = ["critical", "important", "moderate", "low"]

CHART_TITLE = "Red Hat Security Fixes (CVEs) by Month"
CHART_SUBTITLE = "Red Hat Security Data API (CSAF)"

PALETTES = {
    "redhat": {"bg": "#ffffff", "bar": "#ee0000", "grid": "#b3b3b8",
               "title": "#151515", "subtitle": "#4d4d4d", "label": "#151515"},
    "redhat-dark": {"bg": "#151515", "bar": "#ff5e5e", "grid": "#3d3d3d",
                    "title": "#ffffff", "subtitle": "#b3b3b8",
                    "label": "#ffffff"},
}

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")


def _month_keys(since: datetime.date, today: datetime.date) -> list[str]:
    keys = []
    y, m = since.year, since.month
    while (y, m) <= (today.year, today.month):
        keys.append(f"{y:04d}-{m:02d}")
        m += 1
        if m == 13:
            y, m = y + 1, 1
    return keys


def _parse_ts(value) -> datetime.datetime | None:
    """Parse an ISO timestamp as aware UTC (tolerates +00:00 or Z suffix)."""
    if not isinstance(value, str) or not value:
        return None
    s = value.replace("Z", "+00:00")
    try:
        dt = datetime.datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt


def _fetch_window(start: datetime.date, end: datetime.date) -> list[dict]:
    """All CSAF list entries initially released in [start, end).

    Paginates while a page returns exactly PER_PAGE entries; entries are
    returned in API order (newest first).
    """
    entries: list[dict] = []
    page = 1
    while True:
        url = (f"{CSAF_LIST_URL}?after={start.isoformat()}"
               f"&before={end.isoformat()}&per_page={PER_PAGE}&page={page}")
        body, _headers = net_http.http_request(
            url, headers={"Accept": "application/json"},
            timeout=300, tag=f"redhat-{start:%Y-%m}-p{page}")
        batch = json.loads(body)
        if not isinstance(batch, list):
            raise ValueError(f"unexpected CSAF list response for "
                             f"{start:%Y-%m} page {page}: {type(batch).__name__}")
        entries.extend(batch)
        if len(batch) < PER_PAGE:
            return entries
        page += 1


def _collect(since: datetime.date, today: datetime.date) -> dict[str, dict]:
    """Month key -> {"total", "sev", "advisories"} for every month in range.

    Buckets each entry by its own initial release date (immune to API
    window-boundary inclusivity), dedupes CVEs per entry, then per month takes
    the unique CVE set with per-CVE max severity across the advisories that
    fix it that month.
    """
    months = _month_keys(since, today)

    # Window bounds: [1st of month, 1st of next month).
    bounds = []
    for m in months:
        y, mm = int(m[:4]), int(m[5:7])
        start = datetime.date(y, mm, 1)
        end = datetime.date(y + (mm == 12), mm % 12 + 1, 1)
        bounds.append((start, end))

    seen_ids: set[str] = set()
    buckets: dict[str, list[dict]] = {m: [] for m in months}
    n_entries = n_pages = n_no_cve = 0
    for start, end in bounds:
        entries = _fetch_window(start, end)
        n_pages += 1
        for entry in entries:
            rid = entry.get("RHSA")
            if not isinstance(rid, str) or rid in seen_ids:
                continue
            seen_ids.add(rid)
            ts = _parse_ts(entry.get("released_on"))
            if ts is None:
                print(f"note: entry without released_on skipped: {rid}")
                continue
            month = f"{ts.year:04d}-{ts.month:02d}"
            if month not in buckets:
                continue
            cves = {c for c in entry.get("CVEs") or []
                    if isinstance(c, str) and _CVE_RE.match(c)}
            if not cves:
                n_no_cve += 1
                continue
            sev = entry.get("severity")
            if not isinstance(sev, str) or sev.lower() not in SEV_RANK:
                sev = None
            else:
                sev = sev.lower()
            buckets[month].append({"id": rid, "cves": cves, "sev": sev,
                                   "ts": ts})
            n_entries += 1

    result: dict[str, dict] = {}
    for m in months:
        adv = buckets[m]
        best: dict[str, str | None] = {}
        for a in adv:
            for cve in a["cves"]:
                cur = best.get(cve, "missing")
                rank = SEV_RANK.get(a["sev"], 0) if a["sev"] else 0
                if cur == "missing" or rank > SEV_RANK.get(cur, 0):
                    best[cve] = a["sev"]
        sev_counts = {s: 0 for s in SEVERITIES}
        sev_counts["unknown"] = 0
        for sev in best.values():
            if sev is None:
                sev_counts["unknown"] += 1
            else:
                sev_counts[sev] += 1
        result[m] = {"total": len(best), "sev": sev_counts,
                     "advisories": len(adv)}
    print(f"note: {n_entries} CVE-carrying advisories across {n_pages} "
          f"window fetches ({n_no_cve} entries without CVEs skipped)")
    return result


def _write_tsv(rows: list[list], out: str) -> None:
    with open(out, "w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh, delimiter="\t", lineterminator="\n")
        writer.writerow(["month", "total", *SEVERITIES, "unknown"])
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
            if len(r) != 3 + len(SEVERITIES):
                raise ValueError(f"expected {3 + len(SEVERITIES)} columns in "
                                 f"{path}: {r}")
            rows.append([r[0], int(r[1]), *(int(v) for v in r[2:])])
    if not rows:
        raise ValueError(f"no monthly rows in {path}")
    return rows


def _write_chart_file(rows: list[list], out: str, today: datetime.date,
                      palette: str) -> None:
    if not out:
        return
    mfsa_table._write_chart(rows, out, today, today,
                            title=CHART_TITLE, subtitle_label=CHART_SUBTITLE,
                            palette=PALETTES[palette])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--since", default="2025-01-01",
                        help="First month of the series (YYYY-MM-DD).")
    parser.add_argument("--out", default="redhat_monthly.tsv",
                        help="Output TSV path.")
    parser.add_argument("--chart", default="redhat_chart.svg",
                        help="Output SVG chart path (empty string disables).")
    parser.add_argument("--chart-only", action="store_true",
                        help="Regenerate only the chart from the existing TSV.")
    parser.add_argument("--palette", default="redhat", choices=sorted(PALETTES),
                        help="Color scheme for the SVG chart.")
    args = parser.parse_args()

    today = datetime.date.today()

    if args.chart_only:
        try:
            rows = _read_tsv(args.out)
        except (OSError, ValueError) as exc:
            print(f"error: cannot read {args.out} ({exc}); "
                  f"nothing was written")
            return 1
        _write_chart_file(rows, args.chart, today, args.palette)
        print(f"wrote chart to {args.chart} (palette: {args.palette}, "
              f"{len(rows)} months)")
        return 0

    since = datetime.date.fromisoformat(args.since)
    try:
        months = _collect(since, today)
    except (OSError, RuntimeError, ValueError, KeyError) as exc:
        print(f"error: Red Hat fetch failed ({exc}); nothing was written")
        return 1

    rows = []
    for m in _month_keys(since, today):
        rec = months.get(m)
        counts = {s: 0 for s in SEVERITIES}
        counts["unknown"] = 0
        total = 0
        if rec:
            total = rec["total"]
            for sev, n in (rec.get("sev") or {}).items():
                if sev in counts:
                    counts[sev] = n
        rows.append([m, total, *(counts[s] for s in SEVERITIES + ["unknown"])])
    _write_tsv(rows, args.out)
    for m, total, *_sev in rows:
        print(f"{m}: {total} CVEs ({months.get(m, {}).get('advisories', 0)} "
              f"advisories)")
    print(f"wrote {len(rows)} months to {args.out}")

    _write_chart_file(rows, args.chart, today, args.palette)
    if args.chart:
        print(f"wrote chart to {args.chart}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
