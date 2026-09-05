#!/usr/bin/env python3
"""Build a monthly TSV of unique security bugs fixed in desktop Firefox and render
a Mozilla-style SVG bar chart from the same data.

Data source: github.com/mozilla/foundation-security-advisories (the canonical repo
behind mozilla.org/en-US/security/advisories/). Each advisory is a YAML file with
`announced`, `fixed_in`, and a per-CVE `advisories` map. Individual bug IDs live in
each CVE's `bugs[].url` lists; a CVE is often a "rollup" that bundles many bugs.

Bug-level severity is not published, so each bug is attributed to the severity of
the rollup group it sits in: the group's `desc` label when it starts with
`Critical|High|Moderate|Low Severity`, otherwise the containing CVE's `impact`.
Each unique bug is counted once per month, at its maximum observed severity.

The SVG chart replicates the visual style of Mozilla's "Firefox Security Bug Fixes
by Month" graphic (dark purple card, lavender bars, dotted gridlines). Layout and
color constants were extracted pixel-wise from the original 2560x1440 PNG; values
are expressed here on a 1280x720 logical canvas (the original at half scale).
"""
import argparse
import csv
import datetime
import glob
import os
import re
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict

import yaml

REPO_URL = "https://github.com/mozilla/foundation-security-advisories"

DESKTOP_FIREFOX = {"Firefox", "Firefox ESR"}

SEV_ORDER = {"critical": 4, "high": 3, "moderate": 2, "low": 1}
SEVERITIES = ["critical", "high", "moderate", "low"]

# ---- SVG chart style constants (extracted from Mozilla's original PNG) ----
BG_COLOR = "#210340"
BAR_COLOR = "#e4d7fc"
GRID_COLOR = "#ae89ff"
TITLE_COLOR = "#ffffff"
SUBTITLE_COLOR = "#c4a8fc"

DEFAULT_PALETTE = {
    "bg": BG_COLOR,
    "bar": BAR_COLOR,
    "grid": GRID_COLOR,
    "title": TITLE_COLOR,
    "subtitle": SUBTITLE_COLOR,
    "label": TITLE_COLOR,
}

W, H = 1280, 720
PLOT_X0, PLOT_X1 = 51.5, 1228.5
BASELINE_Y = 611.5
GRID_TOP_Y = 150.0
TITLE_X, TITLE_Y = 53.0, 88.0
SUBTITLE_X, SUBTITLE_Y = 53.0, 127.0
MAX_BAR_PX = 411.5

_SEV_DESC_RE = re.compile(r"^(Critical|High|Moderate|Low)\s+[Ss]everity")
_ORDINAL_RE = re.compile(r"(\d)(?:st|nd|rd|th)\b")
_VERSION_RE = re.compile(r"^(.*?)\s+\d")


def parse_date(raw: str):
    text = _ORDINAL_RE.sub(r"\1", str(raw).strip())
    for fmt in ("%B %d, %Y", "%b %d, %Y"):
        try:
            return datetime.datetime.strptime(text, fmt).date()
        except ValueError:
            continue
    return None


def product_tokens(data: dict) -> list[str]:
    tokens = []
    fixed_in = data.get("fixed_in") or []
    if isinstance(fixed_in, str):
        fixed_in = [fixed_in]
    for item in fixed_in:
        for part in str(item).split(","):
            part = part.strip()
            m = _VERSION_RE.match(part)
            tokens.append(m.group(1).strip() if m else part)
    return [t for t in tokens if t]


def clone_repo(dest: str) -> None:
    subprocess.run(
        ["git", "clone", "--depth", "1", REPO_URL, dest],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _month_is_incomplete(month: str, today: datetime.date) -> bool:
    y, m = (int(x) for x in month.split("-"))
    if m == 12:
        last_day = datetime.date(y + 1, 1, 1) - datetime.timedelta(days=1)
    else:
        last_day = datetime.date(y, m + 1, 1) - datetime.timedelta(days=1)
    return last_day > today


def _write_chart(rows: list[list], out: str, cutoff: datetime.date, today: datetime.date,
                 title: str = "Firefox Security Bug Fixes by Month",
                 subtitle_label: str = "All Sources \u00b7 All Severities",
                 palette: dict | None = None,
                 xlabels: list[str] | None = None,
                 mark_last_incomplete: bool | None = None,
                 footnote: str | None = None) -> None:
    pal = {**DEFAULT_PALETTE, **(palette or {})}
    n = len(rows)
    slot = (PLOT_X1 - PLOT_X0) / n
    bar_w = min(46.0, slot * 0.6)
    max_val = max(r[1] for r in rows) or 1
    scale = MAX_BAR_PX / max_val
    val_font = min(33.0, slot * 0.45)
    lab_font = min(24.0, slot * 0.4)
    last_month = rows[-1][0]
    if mark_last_incomplete is None:
        incomplete = _month_is_incomplete(last_month, today)
    else:
        incomplete = mark_last_incomplete

    bars = []
    gridlines = []
    for i, (month, total, *_rest) in enumerate(rows):
        cx = PLOT_X0 + i * slot + slot / 2
        bx = PLOT_X0 + i * slot + (slot - bar_w) / 2
        hpx = total * scale
        top = BASELINE_Y - hpx
        bars.append((month, bx, top, bar_w, hpx, total))
        gridlines.append(PLOT_X0 + i * slot)

    lines = [f'<line x1="{PLOT_X0}" y1="{BASELINE_Y}" x2="{PLOT_X1}" y2="{BASELINE_Y}" '
             f'stroke="{pal["grid"]}" stroke-width="2" stroke-dasharray="2 2.5"/>']
    for x in gridlines:
        lines.append(f'<line x1="{x:.1f}" y1="{GRID_TOP_Y}" x2="{x:.1f}" y2="{BASELINE_Y}" '
                     f'stroke="{pal["grid"]}" stroke-width="2" stroke-dasharray="2 3.5"/>')

    bar_svg = []
    for month, bx, top, bw, hpx, total in bars:
        rect = (f'<rect x="{bx:.1f}" y="{top:.1f}" width="{bw:.1f}" height="{hpx:.1f}" '
                f'fill="{pal["bar"]}"/>')
        if incomplete and month == last_month:
            rect = (f'<rect x="{bx:.1f}" y="{top:.1f}" width="{bw:.1f}" height="{hpx:.1f}" '
                    f'fill="{pal["bar"]}" opacity="0.35"/>'
                    f'<rect x="{bx:.1f}" y="{top:.1f}" width="{bw:.1f}" height="{hpx:.1f}" '
                    f'fill="url(#stripes)"/>')
        label = f"{total}*" if (incomplete and month == last_month) else str(total)
        bar_svg.append(rect)
        bar_svg.append(f'<text x="{bx + bw / 2:.1f}" y="{top - 2.5:.1f}" text-anchor="middle" '
                       f'font-family="Inter, Segoe UI, Helvetica, Arial, sans-serif" '
                       f'font-size="{val_font:.1f}" font-weight="600" fill="{pal["label"]}">{label}</text>')

    xlabels_svg = []
    if xlabels is None:
        for i, (month, *_rest) in enumerate(rows):
            cx = PLOT_X0 + i * slot + slot / 2
            ym = int(month[:4]); mm = int(month[5:7])
            abbr = datetime.date(ym, mm, 1).strftime("%b").upper()
            xlabels_svg.append(f'<text x="{cx:.1f}" y="635" text-anchor="middle" '
                               f'font-family="Inter, Segoe UI, Helvetica, Arial, sans-serif" '
                               f'font-size="{lab_font:.1f}" fill="{pal["grid"]}">{abbr}</text>')
            xlabels_svg.append(f'<text x="{cx:.1f}" y="665" text-anchor="middle" '
                               f'font-family="Inter, Segoe UI, Helvetica, Arial, sans-serif" '
                               f'font-size="{lab_font:.1f}" fill="{pal["grid"]}">{ym}</text>')
    else:
        for i, lab in enumerate(xlabels):
            cx = PLOT_X0 + i * slot + slot / 2
            xlabels_svg.append(f'<text x="{cx:.1f}" y="650" text-anchor="middle" '
                               f'font-family="Inter, Segoe UI, Helvetica, Arial, sans-serif" '
                               f'font-size="{lab_font:.1f}" fill="{pal["grid"]}">{lab}</text>')

    cutoff = cutoff.strftime("%b %-d, %Y")
    subtitle = f"{subtitle_label} \u00b7 Data through {cutoff}"
    if footnote is None:
        footnote = "* current month, still in progress" if incomplete else ""
    elif not incomplete:
        footnote = ""

    svg = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">',
        f'<rect width="{W}" height="{H}" rx="24" fill="{pal["bg"]}"/>',
        '<defs>'
        '<pattern id="stripes" width="12" height="12" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">'
        f'<rect width="12" height="12" fill="none"/>'
        f'<rect width="5" height="12" fill="{pal["bg"]}" opacity="0.85"/>'
        '</pattern>'
        '</defs>',
        *lines,
        *bar_svg,
        *xlabels_svg,
        f'<text x="{TITLE_X}" y="{TITLE_Y}" font-family="Inter, Segoe UI, Helvetica, Arial, sans-serif" '
        f'font-size="45" font-weight="700" fill="{pal["title"]}">{title}</text>',
        f'<text x="{SUBTITLE_X}" y="{SUBTITLE_Y}" font-family="Inter, Segoe UI, Helvetica, Arial, sans-serif" '
        f'font-size="24" fill="{pal["subtitle"]}">{subtitle}</text>',
    ]
    if footnote:
        svg.append(f'<text x="{PLOT_X1}" y="700" text-anchor="end" '
                   f'font-family="Inter, Segoe UI, Helvetica, Arial, sans-serif" '
                   f'font-size="16" fill="{pal["grid"]}">{footnote}</text>')
    svg.append("</svg>")

    with open(out, "w", encoding="utf-8") as fh:
        fh.write("\n".join(svg) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--since", default="2025-01-01", help="Include advisories announced on/after this date (YYYY-MM-DD).")
    parser.add_argument("--out", default="mozilla_mfsa.tsv", help="Output TSV path.")
    parser.add_argument("--chart", default="mozilla_mfsa_chart.svg", help="Output SVG chart path (empty string disables).")
    args = parser.parse_args()

    since = datetime.date.fromisoformat(args.since)

    month_bugs = defaultdict(set)          # month -> set of bug ids
    bug_severities = defaultdict(set)      # bug id -> set of observed severities
    last_date = since
    skipped = 0
    included = 0

    with tempfile.TemporaryDirectory(prefix="mfsa-src-") as tmp:
        repo = os.path.join(tmp, "repo")
        clone_repo(repo)
        files = sorted(glob.glob(os.path.join(repo, "announce", "*", "mfsa*.yml")))

        for path in files:
            with open(path, encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
            if not isinstance(data, dict):
                continue

            announced = parse_date(str(data.get("announced", "")))
            if announced is None:
                skipped += 1
                continue
            if announced < since:
                continue

            tokens = product_tokens(data)
            if not any(t in DESKTOP_FIREFOX for t in tokens):
                continue

            if announced > last_date:
                last_date = announced
            month = announced.strftime("%Y-%m")
            for entry in (data.get("advisories") or {}).values():
                if not isinstance(entry, dict):
                    continue
                cve_impact = (entry.get("impact") or "low").strip().lower()
                for bug in entry.get("bugs") or []:
                    desc = str(bug.get("desc", ""))
                    m = _SEV_DESC_RE.match(desc)
                    severity = m.group(1).lower() if m else cve_impact
                    for tok in str(bug.get("url", "")).split(","):
                        tok = tok.strip()
                        if not re.fullmatch(r"\d+", tok):
                            continue
                        bug_id = int(tok)
                        month_bugs[month].add(bug_id)
                        bug_severities[bug_id].add(severity)
            included += 1

    rows = []
    for month in sorted(month_bugs):
        sev_counts = Counter()
        for bug in month_bugs[month]:
            sev_counts[max(bug_severities[bug], key=SEV_ORDER.get)] += 1
        rows.append(
            [month, len(month_bugs[month])]
            + [sev_counts.get(s, 0) for s in SEVERITIES]
        )

    with open(args.out, "w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh, delimiter="\t", lineterminator="\n")
        writer.writerow(["month", "total", "critical", "high", "moderate", "low"])
        writer.writerows(rows)

    if args.chart:
        _write_chart(rows, args.chart, last_date, datetime.date.today())

    print(f"wrote {len(rows)} monthly rows to {args.out} (from {included} desktop-Firefox advisories)")
    if args.chart:
        print(f"wrote chart to {args.chart}")
    if skipped:
        print(f"note: skipped {skipped} advisories missing parseable announced")
    return 0


if __name__ == "__main__":
    sys.exit(main())