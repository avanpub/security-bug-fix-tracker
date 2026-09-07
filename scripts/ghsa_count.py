#!/usr/bin/env python3
"""Track the number of GitHub security advisories (GHSAs).

Modes:

1. Global snapshot (tokenless, default when --project is absent): scrapes the
   GitHub Advisory Database (github.com/advisories, default view = reviewed)
   and appends a row to a snapshot log TSV. Run periodically to track the
   overall count over time; re-running on the same day updates that day's row
   in place.

2. Global monthly series + chart (needs a GitHub token): counts reviewed
   advisories published per month via GraphQL `securityAdvisories`
   `publishedSince` boundary deltas and writes a monthly TSV plus an SVG bar
   chart.

3. Project mode (--project, tokenless by default): tracks advisories for one
   project. --project accepts a registry key (e.g. rabbitmq) or ANY
   owner/repo (e.g. nginx/nginx). "affecting" = reviewed package-DB
   advisories (REST /advisories?affects=...) unioned with the repo-published
   GHSAs, deduped by GHSA id; "published_by" = the advisories the project
   itself announced on its repo security page. Package names for REST
   matching come from registry curation (when the repo matches an entry), the
   repo's own name, and --packages; with a token, names are additionally
   discovered from the repo's own advisories via batched GraphQL
   `securityAdvisory` lookups (capped at 200 advisories; the REST
   single-advisory endpoint rejects the Actions GITHUB_TOKEN with 403).
   Token-authed REST listings fall back to anonymous requests on 403.
   Writes a snapshot log, a monthly TSV and an SVG chart. Without discovery
   no token is needed: project queries are small and the unauthenticated REST
   rate limit (60/h) suffices.

The GraphQL Advisory Database dataset contains reviewed advisories only
(unreviewed and malware entries are not exposed), which matches the
reviewed-only scope of this tracker. Verified 2026-09-05: unfiltered
totalCount equals the site's "All reviewed" figure.

Token (global monthly only): classic or fine-grained PAT, no scopes required
(public data). Pass via --token or the GH_TOKEN/GITHUB_TOKEN environment
variable. Never hard-code it in a file.

The global monthly series and the project REST queries reuse a `.cache/`
directory between runs (completed months and previously seen advisories are
immutable); `--no-cache` bypasses it.
"""
import argparse
import csv
import datetime
import json
import os
import re
import sys
import urllib.error
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cache_util
import mfsa_table
import net_http

ADVISORIES_URL = "https://github.com/advisories"
GRAPHQL_URL = "https://api.github.com/graphql"

_GQL_TEMPLATE = ('query { securityAdvisories(first: 1, publishedSince: "%s") '
                 "{ totalCount } }")

GHSA_CHART_TITLE = "Overall GitHub Reviewed Advisories by Month"
GHSA_CHART_SUBTITLE = "All Ecosystems"

PALETTES = {
    "github-green": {"bg": "#0d1117", "bar": "#3fb950", "grid": "#3d444d",
                     "title": "#f0f6fc", "subtitle": "#9198a1", "label": "#ffffff"},
    "github-blue": {"bg": "#0d1117", "bar": "#58a6ff", "grid": "#3d444d",
                    "title": "#f0f6fc", "subtitle": "#9198a1", "label": "#ffffff"},
    "teal": {"bg": "#161b22", "bar": "#2dd4bf", "grid": "#404d5c",
             "title": "#f0f6fc", "subtitle": "#8b949e", "label": "#ffffff"},
    "light": {"bg": "#ffffff", "bar": "#0969da", "grid": "#d1d9e0",
              "title": "#1f2328", "subtitle": "#59636e", "label": "#1f2328"},
}

PROJECTS = {
    "rabbitmq": {
        "title": "RabbitMQ",
        "packages": ["rabbitmq", "com.rabbitmq:amqp-client"],
        "repos": ["rabbitmq/rabbitmq-server"],
    },
}

_GHSA_RE = re.compile(r"GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}")


def _fetch_advisories_page() -> str:
    body, _headers = net_http.http_request(ADVISORIES_URL, headers={"Accept": "text/html"})
    return body.decode("utf-8", "replace")


def _parse_reviewed_count(html: str) -> int:
    text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html))
    m = re.search(r"All reviewed\s*([\d,]+)", text)
    if not m:
        m = re.search(r"([\d,]+)\s+advisories", text)
    if not m:
        raise RuntimeError("could not parse reviewed advisory count from github.com/advisories")
    return int(m.group(1).replace(",", ""))


def _update_snapshot_tsv(path: str, today: datetime.date, header: list[str], values: list[str]) -> None:
    rows = []
    if os.path.exists(path):
        with open(path, encoding="utf-8", newline="") as fh:
            reader = csv.reader(fh, delimiter="\t")
            next(reader, None)
            rows = [r for r in reader if r]
    today_iso = today.isoformat()
    rows = [r for r in rows if r[0] != today_iso]
    rows.append([today_iso] + values)
    rows.sort(key=lambda r: r[0])
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh, delimiter="\t", lineterminator="\n")
        writer.writerow(header)
        writer.writerows(rows)


def _gql_total_count(token: str, published_since: str, tag: str | None = None) -> int:
    body = json.dumps({"query": _GQL_TEMPLATE % published_since}).encode()
    resp_body, _headers = net_http.http_request(GRAPHQL_URL, data=body, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json",
        "User-Agent": "ghsa-count-tracker",
    })
    out = json.loads(resp_body)
    if out.get("errors"):
        raise RuntimeError(f"GraphQL errors: {json.dumps(out['errors'])[:400]}")
    return out["data"]["securityAdvisories"]["totalCount"]


def _monthly_series(token: str, since: datetime.date, today: datetime.date,
                    cache: dict | None = None) -> list[list]:
    """Monthly counts via publishedSince boundary deltas.

    Completed months are final (new advisories always publish with later
    dates, so they cancel in the boundary delta), so with a cache only the
    current month and the most recent completed month are re-queried; older
    months are served from cached counts.
    """
    months = []
    y, m = since.year, since.month
    while (y, m) <= (today.year, today.month):
        months.append(datetime.date(y, m, 1))
        m += 1
        if m == 13:
            y, m = y + 1, 1
    served: set[str] = set()
    if cache:
        for boundary in months[:-2]:
            month = boundary.strftime("%Y-%m")
            if month in cache:
                served.add(month)
    needed: list[datetime.date] = []
    seen_boundaries: set[datetime.date] = set()
    for i, boundary in enumerate(months):
        if boundary.strftime("%Y-%m") in served:
            continue
        nxt = months[i + 1] if i + 1 < len(months) else None
        for b in (boundary, nxt):
            if b is not None and b not in seen_boundaries:
                seen_boundaries.add(b)
                needed.append(b)
    cumulative = {}
    for boundary in needed:
        cumulative[boundary] = _gql_total_count(
            token, boundary.strftime("%Y-%m-%dT00:00:00Z"), tag="graphql-totalCount")
    rows = []
    for i, boundary in enumerate(months):
        month = boundary.strftime("%Y-%m")
        if month in served:
            rows.append([month, cache[month]])
            continue
        nxt = months[i + 1] if i + 1 < len(months) else None
        next_count = cumulative.get(nxt, 0) if nxt else 0
        rows.append([month, cumulative[boundary] - next_count])
    if cache is not None:
        for row in rows[:-1]:
            cache[row[0]] = row[1]
    return rows


def _rest_page(url: str, headers: dict, tag: str):
    """Fetch one REST page; on 403 with a token attached, retry
    once anonymously (the Actions GITHUB_TOKEN gets 403 from a number of
    /advisories* endpoints while staying well inside its rate quota)."""
    try:
        return net_http.http_request(url, headers=headers, tag=tag, pace=0.3)
    except urllib.error.HTTPError as exc:
        if exc.code != 403 or not any(k == "Authorization" for k in headers):
            raise
    print("note: tokenised REST request got 403; retrying anonymously", flush=True)
    anon = {k: v for k, v in headers.items() if k != "Authorization"}
    return net_http.http_request(url, headers=anon, tag=f"{tag}:anon", pace=0.3)


def _rest_advisories(url: str, known_ids: set[str] | None = None,
                     record=None, token: str | None = None,
                     tag: str | None = None) -> list[dict]:
    """GET /advisories with Link-header pagination; returns all pages.

    The listing is newest-first and advisories are immutable, so with
    known_ids paging stops at the first page containing an already-fetched
    advisory (older pages are then known too). record(), when given, receives
    each page's {ghsa_id: published_date} map for caching. token, when given,
    is sent as a Bearer token: authenticated requests draw on the account's
    rate limit (5,000/h, or 1,000/h for an Actions GITHUB_TOKEN) instead of
    the unauthenticated 60/h per-IP pool that CI runners share.
    """
    out = []
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "ghsa-count-tracker",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    while url:
        body, resp_headers = _rest_page(url, headers, tag or "rest")
        page = json.loads(body)
        out.extend(page)
        if record is not None:
            record({adv["ghsa_id"]: adv["published_at"][:10] for adv in page})
        if known_ids and any(adv["ghsa_id"] in known_ids for adv in page):
            break
        link = resp_headers.get("Link", "")
        url = ""
        for part in link.split(","):
            if 'rel="next"' in part and "<" in part:
                url = part[part.index("<") + 1:part.rindex(">")]
                break
    return out


def _project_affecting_rest(packages: list[str], cache: dict | None = None,
                            token: str | None = None) -> dict[str, str]:
    """ghsa_id -> published date for reviewed advisories affecting package names."""
    found = {}
    pkg_cache: dict | None = None if cache is None else cache.setdefault("packages", {})
    for pkg in packages:
        known = dict(pkg_cache.get(pkg) or ()) if pkg_cache is not None else {}
        found.update(known)
        base = ("https://api.github.com/advisories?type=reviewed"
                f"&affects={urllib.parse.quote(pkg)}&per_page=100")
        record = ((lambda new, _pkg=pkg: pkg_cache.setdefault(_pkg, {}).update(new))
                  if pkg_cache is not None else None)
        for adv in _rest_advisories(base, known_ids=set(known) or None,
                                    record=record, token=token,
                                    tag=f"rest-affects:{pkg}"):
            found.setdefault(adv["ghsa_id"], adv["published_at"][:10])
    return found


def _fetch_repo_advisories_page(repo: str, page: int) -> str:
    url = f"https://github.com/{repo}/security/advisories"
    if page > 1:
        url += f"?page={page}"
    body, _headers = net_http.http_request(
        url, headers={"Accept": "text/html"},
        tag=f"repo-security-page:{repo}:p{page}")
    return body.decode("utf-8", "replace")


def _project_repo_published(repo: str) -> dict[str, str | None]:
    """ghsa_id -> scraped published date for advisories published by repo."""
    ids: list[str] = []
    dates: dict[str, str] = {}
    page = 1
    while page <= 100:
        try:
            html = _fetch_repo_advisories_page(repo, page)
        except urllib.error.HTTPError as exc:
            if exc.code == 404 and page == 1:
                return {}
            raise
        page_ids = list(dict.fromkeys(_GHSA_RE.findall(html)))
        new_ids = [i for i in page_ids if i not in ids]
        if not new_ids:
            break
        page_dates = re.findall(r'datetime="(\d{4}-\d{2}-\d{2})', html)
        for i, d in zip(new_ids, page_dates):
            dates.setdefault(i, d)
        ids.extend(new_ids)
        page += 1
    return {i: dates.get(i) for i in ids}


def _resolve_project(value: str) -> tuple[dict, str]:
    """Resolve a registry key or any owner/repo into (project, file slug)."""
    if value in PROJECTS:
        proj = dict(PROJECTS[value])
        proj["packages"] = list(proj["packages"])
        return proj, value
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}", value):
        raise ValueError(f"unknown project {value!r}: pass a registry key or owner/repo")
    for key in sorted(PROJECTS):
        if value in PROJECTS[key]["repos"]:
            proj = dict(PROJECTS[key])
            proj["packages"] = list(proj["packages"])
            return proj, key
    owner, name = value.split("/", 1)
    return {"title": name, "packages": [], "repos": [value]}, f"{owner}_{name}"


_GQL_DISCOVERY_BATCH = 30


def _gql_discovery_query(ids: list[str]) -> str:
    decls = "\n".join(
        f'    a{i}: securityAdvisory(identifier: {{ghsaId: "{ghsa}"}}) '
        f'{{ vulnerabilities {{ package {{ name }} }} }}'
        for i, ghsa in enumerate(ids))
    return "query {\n" + decls + "\n}"


def _gql_discovery_batch(ids: list[str], token: str) -> dict[str, list[str] | None]:
    """ghsa_id -> sorted package names (None if not in the advisory DB)."""
    body = json.dumps({"query": _gql_discovery_query(ids)}).encode()
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json",
        "User-Agent": "ghsa-count-tracker",
    }
    try:
        resp_body, _headers = net_http.http_request(
            GRAPHQL_URL, data=body, headers=headers, tag="graphql-discovery")
    except urllib.error.HTTPError as exc:
        if exc.code == 403:
            print("note: tokenised GraphQL discovery got 403; retrying anonymously", flush=True)
            anon = {k: v for k, v in headers.items() if k != "Authorization"}
            resp_body, _headers = net_http.http_request(
                GRAPHQL_URL, data=body, headers=anon, tag="graphql-discovery:anon")
        else:
            raise
    out = json.loads(resp_body)
    if not isinstance(out.get("data"), dict) or out.get("errors"):
        raise RuntimeError(f"GraphQL discovery errors: {json.dumps(out.get('errors', []))[:400]}")
    data = out["data"]
    result: dict[str, list[str] | None] = {}
    for i, ghsa in enumerate(ids):
        node = data.get(f"a{i}")
        if node is None:
            result[ghsa] = None
            continue
        pkgs = sorted({v["package"]["name"] for v in node.get("vulnerabilities", [])
                       if (v.get("package") or {}).get("name")})
        result[ghsa] = pkgs
    return result


def _discover_packages(ghsa_ids: list[str], token: str, cap: int = 200,
                       cache: dict | None = None) -> list[str]:
    """Package names affected by the given advisories.

    Batched GraphQL `securityAdvisory` lookups (the REST single-advisory
    endpoint rejects the Actions GITHUB_TOKEN with 403 while the quota is
    untouched). Repo-published advisories may be absent from the Advisory
    Database (null node); those are skipped. Results are cached
    per GHSA id (cache["discovery"]) and saved incrementally by the caller,
    so future runs only query uncached ids.
    """
    names: set[str] = set()
    disc_cache: dict | None = None if cache is None else cache.setdefault("discovery", {})
    ids = sorted(set(ghsa_ids))
    if len(ids) > cap:
        print(f"note: discovery capped at {cap} of {len(ids)} repo advisories")
        ids = ids[:cap]
    todo: list[str] = []
    fresh_missing: list[str] = []
    for ghsa in ids:
        cached = disc_cache.get(ghsa) if disc_cache is not None else None
        if cached is None:
            todo.append(ghsa)
        else:
            names.update(cached)
    for i in range(0, len(todo), _GQL_DISCOVERY_BATCH):
        batch_result = _gql_discovery_batch(todo[i:i + _GQL_DISCOVERY_BATCH], token)
        for ghsa, pkgs in batch_result.items():
            if pkgs is None:
                fresh_missing.append(ghsa)
            else:
                names.update(pkgs)
                if disc_cache is not None:
                    disc_cache[ghsa] = pkgs
    if fresh_missing:
        print(f"note: {len(fresh_missing)} repo advisories are not in the global advisory DB "
              f"(repo-only); skipped in discovery")
    return sorted(names)


def _project_fetch(project: dict, token: str | None = None) -> tuple[dict[str, str], dict[str, str | None]]:
    """(REST-affecting map, repo-published map) for one PROJECTS entry."""
    rest = _project_affecting_rest(project["packages"], token=token)
    published = {}
    for repo in project["repos"]:
        published.update(_project_repo_published(repo))
    return rest, published


def _month_keys(since: datetime.date, today: datetime.date) -> list[str]:
    keys = []
    y, m = since.year, since.month
    while (y, m) <= (today.year, today.month):
        keys.append(f"{y:04d}-{m:02d}")
        m += 1
        if m == 13:
            y, m = y + 1, 1
    return keys


def _write_project_monthly(path: str, months: list[str], aff: dict[str, int], pub: dict[str, int]) -> None:
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh, delimiter="\t", lineterminator="\n")
        writer.writerow(["month", "affecting", "published_by"])
        writer.writerows([m, aff.get(m, 0), pub.get(m, 0)] for m in months)


def _read_project_monthly_tsv(path: str) -> tuple[list[str], dict[str, int], dict[str, int]]:
    months, aff, pub = [], {}, {}
    with open(path, encoding="utf-8", newline="") as fh:
        reader = csv.reader(fh, delimiter="\t")
        next(reader, None)
        for r in reader:
            if not r:
                continue
            month = r[0]
            if not re.fullmatch(r"\d{4}-\d{2}", month):
                raise ValueError(f"invalid month in {path}: {month}")
            months.append(month)
            aff[month] = int(r[1])
            pub[month] = int(r[2]) if len(r) > 2 else 0
    if not months:
        raise ValueError(f"no monthly rows in {path}")
    return months, aff, pub


def _emit_project_charts(proj: dict, months: list[str], aff: dict[str, int], pub: dict[str, int],
                         args: argparse.Namespace, today: datetime.date, which: str) -> None:
    title = f"{proj['title']} GitHub Advisories by Month"
    if which in ("affecting", "both"):
        mfsa_table._write_chart([[m, aff.get(m, 0)] for m in months], args.chart, today, today,
                                title=title, subtitle_label="Affecting project packages",
                                palette=PALETTES[args.palette])
        print(f"wrote chart to {args.chart}")
    if which == "both":
        out = re.sub(r"_ghsa_chart\.svg$", "_ghsa_published_chart.svg", args.chart)
        mfsa_table._write_chart([[m, pub.get(m, 0)] for m in months], out, today, today,
                                title=title, subtitle_label="Published by the project",
                                palette=PALETTES[args.palette])
        print(f"wrote chart to {out}")


def _read_monthly_tsv(path: str) -> list[list]:
    rows = []
    with open(path, encoding="utf-8", newline="") as fh:
        reader = csv.reader(fh, delimiter="\t")
        next(reader, None)
        for r in reader:
            if not r:
                continue
            month, count = r[0], int(r[1])
            if not re.fullmatch(r"\d{4}-\d{2}", month):
                raise ValueError(f"invalid month in {path}: {month}")
            rows.append([month, count])
    if not rows:
        raise ValueError(f"no monthly rows in {path}")
    rows.sort(key=lambda r: r[0])
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--counts", default=None, help="Snapshot log TSV (appended each run).")
    parser.add_argument("--monthly", default=None, help="Monthly TSV path.")
    parser.add_argument("--chart", default=None, help="Monthly SVG chart path.")
    parser.add_argument("--since", default="2025-01-01", help="First month of the monthly series (YYYY-MM-DD).")
    parser.add_argument("--token", default=None, help="GitHub token (else GH_TOKEN/GITHUB_TOKEN env).")
    parser.add_argument("--project", default=None, metavar="KEY_OR_OWNER/REPO",
                        help="Project mode: registry key or any owner/repo (e.g. rabbitmq, nginx/nginx).")
    parser.add_argument("--packages", default=None,
                        help="Comma-separated extra package names for REST affects matching (project mode).")
    parser.add_argument("--series", default="affecting", choices=["affecting", "both"],
                        help="Chart series for project mode.")
    parser.add_argument("--chart-only", action="store_true",
                        help="Regenerate only the chart from the existing monthly TSV (no network, no snapshot).")
    parser.add_argument("--no-cache", action="store_true",
                        help="Bypass .cache/ (full GraphQL series and REST pagination).")
    parser.add_argument("--palette", default="github-green", choices=sorted(PALETTES),
                        help="Color scheme for the SVG chart.")
    args = parser.parse_args()

    if args.series != "affecting" and not args.project:
        parser.error("--series requires --project")
    if args.packages and not args.project:
        parser.error("--packages requires --project")
    proj = None
    if args.project:
        try:
            proj, slug = _resolve_project(args.project)
        except ValueError as exc:
            parser.error(str(exc))
        if args.packages:
            proj["packages"] += [p.strip() for p in args.packages.split(",") if p.strip()]
        args.counts = args.counts or f"{slug}_ghsa_counts.tsv"
        args.monthly = args.monthly or f"{slug}_ghsa_monthly.tsv"
        args.chart = args.chart or f"{slug}_ghsa_chart.svg"
    else:
        args.counts = args.counts or "ghsa_counts.tsv"
        args.monthly = args.monthly or "ghsa_monthly.tsv"
        args.chart = args.chart or "ghsa_chart.svg"

    today = datetime.date.today()

    if args.chart_only:
        if args.project:
            try:
                months, aff, pub = _read_project_monthly_tsv(args.monthly)
            except (ValueError, OSError) as exc:
                print(f"error: {exc}; run once with --project to create {args.monthly}")
                return 1
            _emit_project_charts(proj, months, aff, pub, args, today, args.series)
            print(f"(palette: {args.palette}, {len(months)} months)")
            return 0
        rows = _read_monthly_tsv(args.monthly)
        mfsa_table._write_chart(rows, args.chart, today, today,
                                title=GHSA_CHART_TITLE, subtitle_label=GHSA_CHART_SUBTITLE,
                                palette=PALETTES[args.palette])
        print(f"wrote chart to {args.chart} (palette: {args.palette}, {len(rows)} months)")
        return 0

    if args.project:
        since = datetime.date.fromisoformat(args.since)
        token = args.token or os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
        proj_cache = None
        if not args.no_cache:
            proj_cache = cache_util.load_json(f"ghsa_project_{slug}.json")
            if not isinstance(proj_cache, dict):
                proj_cache = {}
        try:
            published = {}
            for repo in proj["repos"]:
                published.update(_project_repo_published(repo))
            packages = list(dict.fromkeys(
                proj["packages"] + [proj["repos"][0].split("/", 1)[1]]))
            if token and published:
                discovered = _discover_packages(sorted(published), token, cache=proj_cache)
                added = [n for n in discovered if n not in packages]
                if added:
                    print(f"discovered {len(added)} package name(s) from repo advisories: "
                          f"{', '.join(added[:10])}{' ...' if len(added) > 10 else ''}")
                packages += added
            rest = _project_affecting_rest(packages, proj_cache, token=token)
        except (urllib.error.HTTPError, urllib.error.URLError, RuntimeError) as exc:
            if proj_cache is not None and proj_cache.get("discovery"):
                cache_util.save_json(f"ghsa_project_{slug}.json", proj_cache)
            print(f"error: token={token is not None}")
            print(f"error: project fetch failed ({exc!r}); nothing was written")
            if (isinstance(exc, urllib.error.HTTPError) and exc.code == 403
                    and not token):
                print("hint: unauthenticated REST requests share a 60/h per-IP "
                      "limit (often exhausted on CI runners); set GH_TOKEN to "
                      "authenticate")
            return 1
        if proj_cache is not None:
            cache_util.save_json(f"ghsa_project_{slug}.json", proj_cache)
        if not published:
            print(f"note: no published advisories found on {', '.join(proj['repos'])} security page(s)")
        union = dict(rest)
        for ghsa, d in published.items():
            union.setdefault(ghsa, d)
        overlap = len(set(rest) & set(published))
        affecting_total, published_total = len(union), len(published)
        _update_snapshot_tsv(args.counts, today,
                             ["snapshot_date", "affecting", "published_by"],
                             [str(affecting_total), str(published_total)])
        print(f"snapshot: affecting={affecting_total} published_by={published_total} "
              f"(REST {len(rest)} + repo {len(published)} - overlap {overlap}) -> {args.counts}")
        dateless = sorted(i for i, d in published.items() if not d)
        if dateless:
            print(f"note: {len(dateless)} repo advisories without a scraped date; excluded from monthly")

        months = _month_keys(since, today)
        month_set = set(months)
        aff: dict[str, int] = {}
        pub: dict[str, int] = {}
        for ghsa, d in union.items():
            if d and d[:7] in month_set:
                aff[d[:7]] = aff.get(d[:7], 0) + 1
        for ghsa, d in published.items():
            if d and d[:7] in month_set:
                pub[d[:7]] = pub.get(d[:7], 0) + 1
        _write_project_monthly(args.monthly, months, aff, pub)
        print(f"wrote {len(months)} monthly rows to {args.monthly}")

        if args.chart:
            _emit_project_charts(proj, months, aff, pub, args, today, args.series)
        return 0

    html = _fetch_advisories_page()
    reviewed = _parse_reviewed_count(html)
    _update_snapshot_tsv(args.counts, today, ["snapshot_date", "reviewed"], [str(reviewed)])
    print(f"snapshot: {reviewed} reviewed advisories -> {args.counts}")

    token = args.token or os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not token:
        print("note: no token (--token or GH_TOKEN/GITHUB_TOKEN); skipping monthly series and chart")
        return 0

    try:
        since = datetime.date.fromisoformat(args.since)
        monthly_cache = None
        if not args.no_cache:
            monthly_cache = cache_util.load_json("ghsa_monthly_totals.json")
            if not isinstance(monthly_cache, dict):
                monthly_cache = {}
        rows = _monthly_series(token, since, today, monthly_cache)
    except (OSError, RuntimeError) as exc:
        print(f"note: GraphQL monthly series failed ({exc}); the snapshot was still written")
        return 1
    if monthly_cache is not None:
        cache_util.save_json("ghsa_monthly_totals.json", monthly_cache)

    with open(args.monthly, "w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh, delimiter="\t", lineterminator="\n")
        writer.writerow(["month", "ghsa"])
        writer.writerows(rows)
    print(f"wrote {len(rows)} monthly rows to {args.monthly}")

    if args.chart:
        mfsa_table._write_chart(rows, args.chart, today, today,
                                title=GHSA_CHART_TITLE, subtitle_label=GHSA_CHART_SUBTITLE,
                                palette=PALETTES[args.palette])
        print(f"wrote chart to {args.chart}")
    return 0


if __name__ == "__main__":
    sys.exit(main())