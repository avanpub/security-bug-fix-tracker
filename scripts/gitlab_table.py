#!/usr/bin/env python3
"""Track GitLab security fixes (CVEs) per month.

Fetches the GitLab patch-release Atom feed (docs.gitlab.com/releases/
patch-releases.xml, tokenless) and attributes every unique CVE id in each
post's "Security fixes" section to the calendar month in which the post was
published, deduplicated per month. This mirrors the Chrome and Firefox
counting: the month of public disclosure.

GitLab does not disclose per-bug counts; the CVE is the public unit of
counting. Severity per CVE comes from each post's summary table
(Critical/High/Medium/Low, case normalized); when a CVE appears in several
posts the highest observed severity wins. Bug-fix-only patch releases
contain no CVEs and contribute zero.

Window: months from --since (default 2025-01-01) to the current month,
parallel to the Firefox, Chrome, and GHSA monthly series. The feed itself
reaches back to 2023-05.

Cross-check anchors (verified 2026-09-05): the 2026-08-12 post "GitLab Patch
Release: 19.2.2, 19.1.4, 19.0.6" lists 14 security fixes and the 2026-08-26
post lists 7 — both reproduced exactly; --as-of 2026-08-27 reproduces the
snapshot data.
"""
import argparse
import csv
import datetime
import os
import re
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mfsa_table
import net_http

FEED_URL = "https://docs.gitlab.com/releases/patch-releases.xml"
_ATOM = "{http://www.w3.org/2005/Atom}"

_SEC_H2_RE = re.compile(r"<h2[^>]*>[^<]*Security\s+Fixes[^<]*</h2>", re.I)
_CVE_RE = re.compile(r"CVE-(\d{4}-\d{4,7})", re.I)
_HREF_CVE_RE = re.compile(r"cve-(\d{4}-\d{4,7})", re.I)
_ROW_RE = re.compile(
    r"<td[^>]*>\s*<a\s+href=[\"']([^\"']+)[\"'][^>]*>[^<]*</a>\s*</td>\s*"
    r"<td[^>]*>\s*([A-Za-z]+)\s*</td>",
    re.I | re.S)
_H3_ID_RE = re.compile(r"<h3[^>]*\bid=[\"']([^\"']+)[\"'][^>]*>", re.I)
_NEXT_H_RE = re.compile(r"<h[23][^>]*>", re.I)

SEV_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITIES = ["critical", "high", "medium", "low"]

CHART_TITLE = "GitLab Security Fixes (CVEs) by Month"
CHART_SUBTITLE = "Patch Releases"

PALETTES = {
    "gitlab": {"bg": "#ffffff", "bar": "#fc6d26", "grid": "#b3b3b8",
               "title": "#24263a", "subtitle": "#77517d", "label": "#24263a"},
    "gitlab-dark": {"bg": "#24263a", "bar": "#fc6d26", "grid": "#4e4c69",
                    "title": "#ffffff", "subtitle": "#b3b3b8", "label": "#ffffff"},
    "github-green": {"bg": "#0d1117", "bar": "#3fb950", "grid": "#3d444d",
                     "title": "#f0f6fc", "subtitle": "#9198a1", "label": "#ffffff"},
}


def _month_keys(since: datetime.date, today: datetime.date) -> list[str]:
    keys = []
    y, m = since.year, since.month
    while (y, m) <= (today.year, today.month):
        keys.append(f"{y:04d}-{m:02d}")
        m += 1
        if m == 13:
            y, m = y + 1, 1
    return keys


def _security_section(content: str) -> str | None:
    m = _SEC_H2_RE.search(content)
    if not m:
        m = re.search(r"Security\s+Fixes", content, re.I)
        if not m:
            return None
        start = m.end()
    else:
        start = m.end()
    nxt = content.find("<h2", start)
    return content[start: nxt if nxt != -1 else len(content)]


def _h3_blocks(sec: str) -> list[tuple[str, str]]:
    """(lowercased h3 id, block text) for each detail section of a post."""
    blocks = []
    for m in _H3_ID_RE.finditer(sec):
        nxt = _NEXT_H_RE.search(sec, m.end())
        end = nxt.start() if nxt else len(sec)
        blocks.append((m.group(1).strip().lower(), sec[m.end():end]))
    return blocks


def _severities(sec: str) -> dict[str, str]:
    """CVE id -> highest severity in the post, via the summary table.

    Modern posts use href/#id slugs that carry the CVE id itself; older
    posts use descriptive slugs, matched against the h3 detail-section ids
    whose text contains the CVE ids.
    """
    rows = []
    for href, sev in _ROW_RE.findall(sec):
        frag = href.split("#")[-1].strip().lower()
        rows.append((frag, sev.strip().lower()))
    cand: dict[str, list[str]] = defaultdict(list)
    for frag, sev in rows:
        if sev in SEV_RANK:
            cm = _HREF_CVE_RE.search(frag)
            if cm:
                cand[f"CVE-{cm.group(1).upper()}"].append(sev)
    row_sev = dict(rows)
    for slug, text in _h3_blocks(sec):
        sevs = [s for s in (row_sev.get(slug),) if s in SEV_RANK]
        if not sevs:
            continue
        for cm in _CVE_RE.finditer(text):
            cand[f"CVE-{cm.group(1).upper()}"].append(sevs[0])
    return {cve: max(sevs, key=lambda s: SEV_RANK[s])
            for cve, sevs in cand.items() if sevs}


def _collect(since: datetime.date, as_of: datetime.date | None):
    """(unique CVE ids by month of disclosure, severity per CVE)."""
    body, _headers = net_http.http_request(FEED_URL, timeout=120)
    root = ET.fromstring(body)
    cves: dict[str, set[str]] = defaultdict(set)
    sev_by_cve: dict[str, str] = {}
    for entry in root.findall(f"{_ATOM}entry"):
        published = datetime.date.fromisoformat(
            (entry.findtext(f"{_ATOM}published") or "")[:10])
        if published < since or (as_of and published > as_of):
            continue
        title = (entry.findtext(f"{_ATOM}title") or "").strip()
        content = entry.findtext(f"{_ATOM}content") or ""
        sec = _security_section(content)
        if sec is None:
            continue
        ids = {f"CVE-{m.upper()}" for m in _CVE_RE.findall(sec)}
        if not ids:
            print(f"note: {published} {title!r}: security section, no CVEs found")
            continue
        post_sev = _severities(sec)
        for cve, sev in post_sev.items():
            if SEV_RANK[sev] > SEV_RANK.get(sev_by_cve.get(cve, ""), 0):
                sev_by_cve[cve] = sev
        unmapped = ids - set(post_sev)
        if unmapped:
            print(f"note: {published} {title!r}: no severity for "
                  f"{sorted(unmapped)}")
        cves[published.strftime("%Y-%m")] |= ids
    return cves, sev_by_cve


def _write_tsv(rows: list[list], out: str) -> None:
    with open(out, "w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh, delimiter="\t", lineterminator="\n")
        writer.writerow(["month", "total", *SEVERITIES])
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
            if len(r) != 2 + len(SEVERITIES):
                raise ValueError(f"expected {2 + len(SEVERITIES)} columns in "
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
    parser.add_argument("--as-of", default=None,
                        help="Only use posts published on/before this date (YYYY-MM-DD).")
    parser.add_argument("--out", default="gitlab_monthly.tsv", help="Output TSV path.")
    parser.add_argument("--chart", default="gitlab_chart.svg",
                        help="Output SVG chart path (empty string disables).")
    parser.add_argument("--chart-only", action="store_true",
                        help="Regenerate only the chart from the existing TSV.")
    parser.add_argument("--palette", default="gitlab", choices=sorted(PALETTES),
                        help="Color scheme for the SVG chart.")
    args = parser.parse_args()

    today = datetime.date.today()

    if args.chart_only:
        rows = _read_tsv(args.out)
        _write_chart_file(rows, args.chart, today, args.palette)
        print(f"wrote chart to {args.chart} (palette: {args.palette}, {len(rows)} months)")
        return 0

    since = datetime.date.fromisoformat(args.since)
    as_of = datetime.date.fromisoformat(args.as_of) if args.as_of else None
    try:
        cves, sev_by_cve = _collect(since, as_of)
    except (OSError, RuntimeError, ET.ParseError) as exc:
        print(f"error: feed fetch failed ({exc}); nothing was written")
        return 1

    months = _month_keys(since, today)
    rows = []
    for m in months:
        ids = cves.get(m, set())
        counts = {s: 0 for s in SEVERITIES}
        for cve in ids:
            sev = sev_by_cve.get(cve)
            if sev in counts:
                counts[sev] += 1
        rows.append([m, len(ids), *(counts[s] for s in SEVERITIES)])
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
