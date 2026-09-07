#!/usr/bin/env python3
"""Track Microsoft security fixes (CVEs) per Patch Tuesday month.

Fetches the MSRC Security Update Guide via the CVRF API v3.0
(https://api.msrc.microsoft.com/cvrf/v3.0, tokenless — no API key needed):
one CVRF document per month ("2025-Jan", "2026-Aug", ...), each listing every
CVE in that release together with affected products, severity ratings, and a
full revision history. This reproduces the per-month "new CVE" counts that
the Zero Day Initiative reports in its monthly Security Update Reviews.

Counting rule:
  * window: a CVE counts for the month of its CVRF document if its EARLIEST
    RevisionHistory timestamp falls in [1st of month 00:00 UTC, end of that
    month's Patch Tuesday 23:59:59 UTC] (the Tuesday is the date part of the
    document's InitialReleaseDate). This selects CVEs new in that release and
    drops re-revisions of older CVEs, which MSRC re-publishes in later
    documents; later-in-the-month third-party bulk publishes are outside the
    window.
  * excluded: third-party CNA rows mirrored into the guide — titles that
    start with a CNA prefix (Chromium:, GitHub:, Cert CC, MITRE:, ...) or
    with a raw "CVE-yyyy-nnnnn" string — because those duplicates are already
    counted by the Chrome and GHSA trackers here, and ZDI reports them
    separately too ("with the addition of the third-party CVEs ...").
  * excluded: entries whose affected products are all Azure Linux / CBL
    Mariner ("azl3 <pkg> ... on Azure Linux 3.0" package rows), which are
    CNA mirrors of upstream component advisories.
  * everything else counts once per unique CVE id, including cloud/online
    service CVEs (no KB required), matching ZDI's tables. Severity per CVE is
    the maximum MSRC rating (Critical > Important > Moderate > Low) across
    the CVE's severity threats; entries without a rating land in "unknown".

Relationship to ZDI's published numbers: this rule follows ZDI's headline
prose convention, which excludes CNA-credited third-party rows (ZDI's tables
include some of them, marked with an asterisk). Residual deviations are small
and explained: ZDI exports the guide manually on Patch Tuesday morning, so
rows published later that day are missing from ZDI's table (we include them),
while a few ZDI-table rows are SUG-export artifacts that never appear in the
CVRF data (we exclude them).

Cross-check anchors (verified 2026-09-07):
  * 2025-01: 159 — matches ZDI's headline "159 new CVEs" exactly. (ZDI's
    table lists 163: the 2 third-party CNA rows excluded here by rule — ZDI's
    prose "entire release tops out at 161" adds them too — plus 2 export
    artifacts that are not in the CVRF document at all.)
  * 2026-07: 622 — ZDI's table lists 621 unique CVEs; +1 = CVE-2026-47301
    (Configuration Manager), present in MSRC data but missing from ZDI's
    export.
  * 2026-08: 422 — ZDI's table lists 420 (prose said 398 pre-update); +4 =
    rows published exactly at the document release instant that ZDI's
    snapshot missed (PowerShell RCE, Windows Telephony EoP, Windows App for
    Mac Info, Edge RCE), -2 = the MITRE-credited TPM rows CVE-2026-6726/6727,
    which ZDI's table includes but this rule excludes as CNA-credited
    third-party rows.

Cache: computed per-month aggregates for completed months live in
.cache/msrc_monthly_totals.json (gitignored) — completed-month windows are
immutable history, so they are never refetched; the current month is
recomputed from a fresh document fetch on every run. --no-cache bypasses the
cache entirely with identical results.
"""
import argparse
import csv
import datetime
import json
import os
import re
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cache_util
import mfsa_table
import net_http

UPDATES_URL = "https://api.msrc.microsoft.com/cvrf/v3.0/updates"
CVRF_URL = "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/"

_DOC_ID_RE = re.compile(r"^(\d{4})-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)$")
_DOC_MONTH = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}

# Titles of third-party CNA rows mirrored into the guide. Deliberately NOT a
# blanket "anything with a colon" rule: real MSRC rows such as "Game: Age of
# Empires II ..." and "AMD Zen Information Disclosure Vulnerability" exist,
# and the GitHub Copilot rows are genuine Microsoft fixes. Two CNA title
# shapes occur: "<CNA>: <CVE-id> <desc>" and "<CNA> <CVE-id>: <desc>".
_THIRD_PARTY_TITLE_RE = re.compile(
    r"^(?:Chromium:|GitHub:|GitHub CLI:|GitHub CVE-|Cert CC|MITRE[ :]"
    r"|VulnCheck:|HackerOne:|Red Hat[,:]|AMD CVE-|CVE-\d{4}-\d{4,7}\b)")
_AZURE_LINUX_MARKERS = ("Azure Linux", "Mariner")

SEV_RANK = {"low": 1, "moderate": 2, "important": 3, "critical": 4}
SEVERITIES = ["critical", "important", "moderate", "low"]

CHART_TITLE = "Microsoft Security Fixes (CVEs) by Month"
CHART_SUBTITLE = "Patch Tuesday (MSRC)"

PALETTES = {
    "msrc": {"bg": "#ffffff", "bar": "#0078d4", "grid": "#b3b3b8",
             "title": "#1b1b1f", "subtitle": "#4a4a52", "label": "#1b1b1f"},
    "msrc-dark": {"bg": "#1b1b1f", "bar": "#4aa3e8", "grid": "#43434d",
                  "title": "#ffffff", "subtitle": "#b3b3b8", "label": "#ffffff"},
}

_CACHE_NAME = "msrc_monthly_totals.json"
_RULE_VERSION = 2


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
    """Parse an ISO timestamp (str or {"Value": str}) as aware UTC."""
    if isinstance(value, dict):
        value = value.get("Value")
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


def _first_revision(vuln: dict) -> datetime.datetime | None:
    dates = [d for d in (_parse_ts(r.get("Date"))
                         for r in vuln.get("RevisionHistory") or [])
             if d is not None]
    return min(dates) if dates else None


def _title(vuln: dict) -> str:
    t = vuln.get("Title")
    if isinstance(t, dict):
        return t.get("Value") or ""
    return t if isinstance(t, str) else ""


def _product_names(doc: dict) -> dict[str, str]:
    names: dict[str, str] = {}

    def walk(branch: dict) -> None:
        n = branch.get("Name")
        name = n.get("Value") if isinstance(n, dict) else n
        pid = branch.get("ProductID")
        if pid and isinstance(pid, str):
            names[pid] = name or ""
        for child in branch.get("Branches") or []:
            walk(child)

    tree = doc.get("ProductTree") or {}
    for branch in tree.get("Branch") or []:
        walk(branch)
    for p in tree.get("FullProductName") or []:
        pid = p.get("ProductID")
        if isinstance(pid, str):
            names[pid] = p.get("Value") or p.get("CPE") or ""
    return names


def _affected_products(vuln: dict, names: dict[str, str]) -> set[str]:
    ids = [pid for ps in vuln.get("ProductStatuses") or []
           for pid in ps.get("ProductID", [])]
    return {names.get(pid, str(pid)) for pid in ids}


def _max_severity(vuln: dict) -> str | None:
    best = None
    for threat in vuln.get("Threats") or []:
        if threat.get("Type") != 3:
            continue
        desc = threat.get("Description")
        value = desc.get("Value") if isinstance(desc, dict) else desc
        if isinstance(value, str) and value.lower() in SEV_RANK:
            if best is None or SEV_RANK[value.lower()] > SEV_RANK[best]:
                best = value.lower()
    return best


def _count_doc(doc: dict) -> dict:
    """Apply the counting rule to one CVRF document.

    Returns {"tuesday": date, "total": int, "sev": {sev: count},
             "skipped": int} for the entries selected by the rule.
    """
    tracking = doc.get("DocumentTracking") or {}
    ird = _parse_ts(tracking.get("InitialReleaseDate"))
    if ird is None:
        raise ValueError("CVRF document without InitialReleaseDate")
    tuesday = ird.date()
    window_start = datetime.datetime(tuesday.year, tuesday.month, 1,
                                     tzinfo=datetime.timezone.utc)
    window_end = datetime.datetime(tuesday.year, tuesday.month, tuesday.day,
                                   23, 59, 59, tzinfo=datetime.timezone.utc)

    names = _product_names(doc)
    total = 0
    sev_counts = {s: 0 for s in SEVERITIES}
    sev_counts["unknown"] = 0
    skipped = 0
    for vuln in doc.get("Vulnerability") or []:
        first = _first_revision(vuln)
        if not (first and window_start <= first <= window_end):
            continue
        title = _title(vuln)
        if not title:
            skipped += 1
            continue
        if _THIRD_PARTY_TITLE_RE.match(title):
            continue
        products = _affected_products(vuln, names)
        if products and all(any(marker in p for marker in _AZURE_LINUX_MARKERS)
                            for p in products):
            continue
        total += 1
        sev = _max_severity(vuln)
        if sev is None:
            sev_counts["unknown"] += 1
        else:
            sev_counts[sev] += 1
    return {"tuesday": tuesday, "total": total, "sev": sev_counts,
            "skipped": skipped}


def _doc_month(doc_id: str, updates_entry: dict) -> str | None:
    """Month key (YYYY-MM) for a CVRF document id, or None."""
    m = _DOC_ID_RE.match(doc_id)
    if not m:
        return None
    month = f"{m.group(1)}-{_DOC_MONTH[m.group(2)]:02d}"
    ird = _parse_ts(updates_entry.get("InitialReleaseDate"))
    if ird is not None:
        from_ird = f"{ird.year:04d}-{ird.month:02d}"
        if from_ird != month:
            print(f"note: doc {doc_id}: id month {month} != release month "
                  f"{from_ird}; using {from_ird}")
            month = from_ird
    return month


def _load_cache() -> dict:
    data = cache_util.load_json(_CACHE_NAME)
    if not isinstance(data, dict) or data.get("rule_version") != _RULE_VERSION:
        return {}
    months = data.get("months")
    return months if isinstance(months, dict) else {}


def _save_cache(months: dict) -> None:
    try:
        cache_util.save_json(_CACHE_NAME, {"rule_version": _RULE_VERSION,
                                           "months": months})
    except OSError as exc:
        print(f"note: could not write cache ({exc}); continuing")


def _collect(since: datetime.date, today: datetime.date,
             use_cache: bool) -> dict[str, dict]:
    """Month key -> {"tuesday", "total", "sev"} for every month doc found in
    [since, today]. Completed months may come from cache; the current month
    is always recomputed from a fresh fetch."""
    body, _headers = net_http.http_request(
        UPDATES_URL, headers={"Accept": "application/json"},
        timeout=120, tag="msrc-updates")
    updates = json.loads(body).get("value") or []

    wanted: dict[str, str] = {}  # month key -> doc id
    for entry in updates:
        doc_id = entry.get("ID") or entry.get("Alias") or ""
        month = _doc_month(doc_id, entry)
        if month and month in _month_keys(since, today):
            wanted[month] = doc_id

    current_month = f"{today.year:04d}-{today.month:02d}"
    cache = _load_cache() if use_cache else {}
    result: dict[str, dict] = {}
    fetched = cached = 0
    for month in sorted(wanted):
        doc_id = wanted[month]
        if use_cache and month in cache and month != current_month:
            rec = cache[month]
            if isinstance(rec, dict) and "total" in rec and "sev" in rec:
                result[month] = {"tuesday": rec.get("tuesday"),
                                 "total": rec["total"], "sev": rec["sev"]}
                cached += 1
                continue
        body, _headers = net_http.http_request(
            f"{CVRF_URL}{doc_id}", headers={"Accept": "application/json"},
            timeout=300, tag=f"msrc-{doc_id}")
        counts = _count_doc(json.loads(body))
        if counts["skipped"]:
            print(f"note: {doc_id}: skipped {counts['skipped']} entries "
                  f"without a title")
        result[month] = {"tuesday": counts["tuesday"].isoformat(),
                         "total": counts["total"], "sev": counts["sev"]}
        fetched += 1
        if month != current_month:
            cache[month] = {"doc": doc_id, "tuesday": result[month]["tuesday"],
                            "total": counts["total"], "sev": counts["sev"]}
    if use_cache:
        _save_cache(cache)
    print(f"note: {cached} completed months from cache, {fetched} fetched "
          f"fresh, {len(wanted)} months with documents")
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
    parser.add_argument("--out", default="msrc_monthly.tsv",
                        help="Output TSV path.")
    parser.add_argument("--chart", default="msrc_chart.svg",
                        help="Output SVG chart path (empty string disables).")
    parser.add_argument("--chart-only", action="store_true",
                        help="Regenerate only the chart from the existing TSV.")
    parser.add_argument("--no-cache", action="store_true",
                        help="Fetch every document fresh and skip the cache.")
    parser.add_argument("--palette", default="msrc", choices=sorted(PALETTES),
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
        months = _collect(since, today, use_cache=not args.no_cache)
    except (OSError, RuntimeError, ValueError, KeyError) as exc:
        print(f"error: MSRC fetch failed ({exc}); nothing was written")
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
        print(f"{m}: {total} CVEs")
    print(f"wrote {len(rows)} months to {args.out}")

    _write_chart_file(rows, args.chart, today, args.palette)
    if args.chart:
        print(f"wrote chart to {args.chart}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
