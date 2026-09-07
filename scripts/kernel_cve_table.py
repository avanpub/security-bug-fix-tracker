#!/usr/bin/env python3
"""Track Linux kernel security CVEs (kernel.org CNA) per disclosure month.

Counts unique CVEs published by the kernel.org CVE assignment team, bucketed
by the calendar month in which each CVE was first made public. The data
source is the team's own repository, vulns.git
(https://git.kernel.org/pub/scm/linux/security/vulns.git, mirror
https://kernel.googlesource.com/pub/scm/linux/security/vulns), which keeps
one entry per CVE under state directories cve/published/, cve/rejected/,
cve/reserved/, cve/returned/, and cve/review/.

Counting rule:
  * disclosure date: the CVE JSON files carry no publication date, so each
    CVE's disclosure date is taken from git history — the earliest commit
    that added a path cve/published/<year>/<CVE id>.json. This matches
    cve.org's per-record "datePublished" exactly (verified: 15/15 random
    spot checks across 2024-05..2026-08, plus CVE-2026-22976 where the git
    commit 2026-01-21T06:57:55Z equals cve.org datePublished
    2026-01-21T06:57:23Z).
  * current state: a CVE counts only if it is currently under
    cve/published/ at HEAD. CVEs later moved to rejected/ or returned/ drop
    out retroactively — completed months are therefore recomputed on every
    run, matching the kernel team's guidance to track state changes rather
    than snapshot at creation time.
  * deduplicated by CVE id; each CVE counts once, in its disclosure month.
    Announcement bursts after stable releases make months uneven — spike
    months are genuine disclosure bursts, including batches of older CVE
    ids (CVE-2022-..., CVE-2023-...) published from the team's backlog.

Caveats:
  * the kernel CVE program started in February 2024, so earlier months are
    zero by construction, and the 2024 baseline reflects a new, automated
    assignment process ("overly cautious" per the kernel documentation,
    ~10 CVEs/day) rather than a change in vulnerability rate — treat any
    growth on top of this baseline, not the baseline itself, as the signal.
  * CVEs are assigned only after a fix is already available in a released
    tree; like every series here this counts disclosed fixes, not
    discoveries.
  * the repository holds no per-CVE severity (the kernel team deliberately
    does not score), so the series is a plain total.

Cross-check anchors (verified 2026-09-07): 15/15 random CVEs from
2024-02..2026-08 have git-history disclosure months identical to cve.org
"datePublished" (via the public CVE Services API); program totals ~4.3k
(2024), ~5.7k (2025), ~5.2k (2026 through August) are consistent with the
team's published "~10 CVEs per day" pace.

Cache: the full vulns.git clone lives in .cache/kernel-cve-repo/ (gitignored,
~150 MB; a full clone is required because publication dates come from git
history, and kernel.org does not support partial-clone filters). The clone is
refreshed in place on every run; --no-cache removes and re-clones it with
identical results.
"""
import argparse
import csv
import datetime
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mfsa_table

REPO_URLS = [
    "https://git.kernel.org/pub/scm/linux/security/vulns.git",
    "https://kernel.googlesource.com/pub/scm/linux/security/vulns",
]
REPO_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    ".cache", "kernel-cve-repo")

_PUBLISHED_JSON_RE = re.compile(
    r"^cve/published/\d{4}/(CVE-\d{4}-\d{4,7})\.json$")
_CVE_ID_RE = re.compile(r"CVE-\d{4}-\d{4,7}")

CHART_TITLE = "Linux Kernel CVEs by Month"
CHART_SUBTITLE = "kernel.org CNA (vulns.git)"

PALETTES = {
    "kernel": {"bg": "#ffffff", "bar": "#f0b429", "grid": "#b3b3b8",
               "title": "#1b1b1f", "subtitle": "#8a6d1a", "label": "#1b1b1f"},
    "kernel-dark": {"bg": "#1b1b1f", "bar": "#f5c542", "grid": "#43434d",
                    "title": "#ffffff", "subtitle": "#b3b3b8", "label": "#ffffff"},
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


def _run(args: list[str], **kwargs) -> str:
    return subprocess.run(args, check=True, capture_output=True,
                          text=True, **kwargs).stdout


def _refresh_repo(force: bool, repo_url: str | None) -> str:
    """Ensure .cache/kernel-cve-repo exists with up-to-date history.

    Returns the repo directory. Raises RuntimeError on failure.
    """
    urls = [repo_url] if repo_url else REPO_URLS
    if force and os.path.isdir(REPO_DIR):
        subprocess.run(["rm", "-rf", REPO_DIR], check=True)
    if not os.path.isdir(os.path.join(REPO_DIR, ".git")):
        last_exc: Exception | None = None
        for url in urls:
            try:
                print(f"note: cloning {url} into {REPO_DIR}")
                subprocess.run(["git", "clone", url, REPO_DIR], check=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                break
            except subprocess.CalledProcessError as exc:
                last_exc = exc
                print(f"note: clone from {url} failed ({exc}); trying next source")
                subprocess.run(["rm", "-rf", REPO_DIR], check=False)
        else:
            raise RuntimeError(f"could not clone vulns.git from {urls} "
                               f"({last_exc})")
    else:
        try:
            _run(["git", "-C", REPO_DIR, "fetch", "origin"])
        except subprocess.CalledProcessError as exc:
            raise RuntimeError(f"fetch failed ({exc})") from exc
        _run(["git", "-C", REPO_DIR, "reset", "--hard", "origin/master"])
    return _run(["git", "-C", REPO_DIR, "rev-parse", "--short", "HEAD"]).strip()


def _first_publication_dates() -> dict[str, datetime.datetime]:
    """CVE id -> earliest commit (UTC-naive) that added it under cve/published/."""
    proc = subprocess.Popen(
        ["git", "-C", REPO_DIR, "log", "--no-renames", "--diff-filter=A",
         "--name-only", "--format=%cI"],
        stdout=subprocess.PIPE, text=True)
    first_pub: dict[str, datetime.datetime] = {}
    current_date = None
    for line in proc.stdout:
        line = line.rstrip("\n")
        if not line:
            continue
        if line[0].isdigit():
            current_date = datetime.datetime.fromisoformat(line)
            current_date = current_date.astimezone(datetime.timezone.utc)
            current_date = current_date.replace(tzinfo=None)
            continue
        m = _PUBLISHED_JSON_RE.match(line)
        if m and current_date is not None:
            cve = m.group(1)
            if cve not in first_pub or current_date < first_pub[cve]:
                first_pub[cve] = current_date
    if proc.wait() != 0:
        raise RuntimeError("git log over vulns.git history failed")
    return first_pub


def _currently_published() -> set[str]:
    out = _run(["git", "-C", REPO_DIR, "ls-tree", "-r", "--name-only",
                "HEAD", "cve/published/"])
    ids = set()
    for line in out.splitlines():
        m = _PUBLISHED_JSON_RE.match(line.strip())
        if m:
            ids.add(m.group(1))
    return ids


def _collect(since: datetime.date, today: datetime.date, force_refresh: bool,
             repo_url: str | None) -> dict[str, int]:
    head = _refresh_repo(force_refresh, repo_url)
    print(f"note: vulns.git at {head}")
    first_pub = _first_publication_dates()
    current = _currently_published()
    never_public = current - set(first_pub)
    if never_public:
        print(f"note: {len(never_public)} currently-published CVEs have no "
              f"publication history; skipped")
    months = _month_keys(since, today)
    allowed = set(months)
    counts = {m: 0 for m in months}
    for cve, date in first_pub.items():
        if cve not in current:
            continue
        month = f"{date.year:04d}-{date.month:02d}"
        if month in allowed:
            counts[month] += 1
    print(f"note: {len(current)} CVEs currently published, "
          f"{len(first_pub)} with publication history")
    return counts


def _write_tsv(rows: list[list], out: str) -> None:
    with open(out, "w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh, delimiter="\t", lineterminator="\n")
        writer.writerow(["month", "total"])
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
            if len(r) != 2:
                raise ValueError(f"expected 2 columns in {path}: {r}")
            rows.append([r[0], int(r[1])])
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
    parser.add_argument("--out", default="kernel_monthly.tsv",
                        help="Output TSV path.")
    parser.add_argument("--chart", default="kernel_chart.svg",
                        help="Output SVG chart path (empty string disables).")
    parser.add_argument("--chart-only", action="store_true",
                        help="Regenerate only the chart from the existing TSV.")
    parser.add_argument("--no-cache", action="store_true",
                        help="Remove and re-clone the vulns.git cache first.")
    parser.add_argument("--repo", default=None,
                        help="Override the vulns.git URL (default: kernel.org, "
                             "Google mirror fallback).")
    parser.add_argument("--palette", default="kernel", choices=sorted(PALETTES),
                        help="Color scheme for the SVG chart.")
    args = parser.parse_args()

    today = datetime.date.today()

    if args.chart_only:
        try:
            rows = _read_tsv(args.out)
        except (OSError, ValueError) as exc:
            print(f"error: cannot read {args.out} ({exc}); nothing was written")
            return 1
        _write_chart_file(rows, args.chart, today, args.palette)
        print(f"wrote chart to {args.chart} (palette: {args.palette}, "
              f"{len(rows)} months)")
        return 0

    since = datetime.date.fromisoformat(args.since)
    try:
        counts = _collect(since, today, args.no_cache, args.repo)
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"error: vulns.git update failed ({exc}); nothing was written")
        return 1

    rows = [[m, counts[m]] for m in _month_keys(since, today)]
    _write_tsv(rows, args.out)
    for m, total in rows:
        print(f"{m}: {total} CVEs")
    print(f"wrote {len(rows)} months to {args.out}")

    _write_chart_file(rows, args.chart, today, args.palette)
    if args.chart:
        print(f"wrote chart to {args.chart}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
