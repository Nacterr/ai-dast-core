"""Well-known file discovery: ``read_robots``.

Fetches a small, fixed set of policy files at the target's origin:

* ``/robots.txt`` — crawler rules, and frequently a map of paths the operator would rather
  you did not see;
* ``/sitemap.xml`` — the site's own index of its pages;
* ``/.well-known/security.txt`` — the security contact, per RFC 9116.

The AI chooses the **origin**; the **paths are harness constants**. That distinction is the
whole safety argument for this tool: a caller cannot ask it to probe an arbitrary path, so
it cannot be turned into a content-discovery scanner.

A ``Disallow`` entry is a disclosure *hint*, never a vulnerability. Worth knowing, not worth
reporting as a defect — the report says so explicitly rather than implying the paths are
sensitive.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

from app.models.tools import (
    ReadRobotsData,
    ReadRobotsRequest,
    RobotRule,
    WellKnownFile,
)
from app.tools.base import ToolOutcome, ok
from app.tools.http_client import EgressDenied
from app.tools.shared import clean_text, require_in_scope

# Harness-owned. Never assembled from AI input.
WELL_KNOWN_PATHS: tuple[str, ...] = (
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
)

MAX_RULES = 200
MAX_DISCOVERED_PATHS = 60
MAX_EXCERPT_CHARS = 2000
MAX_CRAWL_DELAY_S = 60.0

_ROBOTS_COMMENT = re.compile(r"#.*$")
_ROBOTS_DIRECTIVE = re.compile(r"^([A-Za-z-]+)\s*:\s*(.*)$")
_SITEMAP_LOC = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.IGNORECASE)
_SECURITY_CONTACT = re.compile(r"^Contact\s*:\s*(.+)$", re.IGNORECASE | re.MULTILINE)

# Rules that mean "nothing useful here"; skipped so the planner is not handed noise.
_IGNORED_RULE_VALUES = {"", "*"}


@dataclass
class _RobotsParse:
    """Structured result of parsing a robots.txt body."""

    rules: list[RobotRule]
    user_agents: list[str]
    sitemaps: list[str]
    crawl_delay_s: float | None
    disallowed_paths: list[str]


def read_robots(ctx, request: ReadRobotsRequest) -> ToolOutcome:
    """Read the well-known policy files at the target origin."""
    decision = require_in_scope(ctx, request.url)
    origin = _origin_of(decision.url)

    paths = list(WELL_KNOWN_PATHS)
    if not request.include_sitemap:
        paths = [path for path in paths if path != "/sitemap.xml"]

    files: list[WellKnownFile] = []
    robots_body = ""
    sitemap_bodies: list[str] = []
    notes: list[str] = []

    for path in paths:
        url = urljoin(origin + "/", path.lstrip("/"))
        scope_check = ctx.scope.check_url(url, resolve=False)
        if not scope_check.allowed:
            notes.append(f"{path} skipped: {scope_check.reason}")
            continue

        try:
            exchange = ctx.http.request(url, method="GET", follow_redirects=True)
        except EgressDenied as exc:
            notes.append(f"{path} refused by the scope guard: {exc.reason}")
            continue

        body = exchange.body_prefix if exchange.status_code == 200 else ""
        found = exchange.status_code == 200 and bool(body.strip())

        files.append(
            WellKnownFile(
                path=path,
                url=exchange.final_url or url,
                status_code=exchange.status_code,
                found=found,
                content_type=str((exchange.headers or {}).get("content-type", ""))[:200],
                bytes=exchange.body_bytes,
                excerpt=body[:MAX_EXCERPT_CHARS],
            )
        )

        if found:
            if path == "/robots.txt":
                robots_body = body
            elif path == "/sitemap.xml":
                sitemap_bodies.append(body)
        elif exchange.error:
            notes.append(f"{path}: {exchange.error}")

    parsed = _parse_robots(robots_body) if robots_body else _RobotsParse([], [], [], None, [])

    sitemap_urls: list[str] = list(parsed.sitemaps)
    for body in sitemap_bodies:
        sitemap_urls.extend(_parse_sitemap(body))
    # Also honour sitemaps declared inside robots.txt by fetching nothing extra: they are
    # reported as candidates, and the planner can open them with browser_open if in scope.
    sitemap_urls = _dedupe(sitemap_urls)[:MAX_DISCOVERED_PATHS]

    discovered = _build_discovered_paths(ctx, origin, parsed.disallowed_paths, sitemap_urls)

    security_txt_file = next(
        (entry for entry in files if entry.path == "/.well-known/security.txt"), None
    )
    has_security_txt = bool(security_txt_file and security_txt_file.found)
    if has_security_txt and security_txt_file is not None:
        contacts = _SECURITY_CONTACT.findall(security_txt_file.excerpt)
        if contacts:
            notes.append(
                "security.txt lists a contact; report vulnerabilities there rather than "
                "testing further: " + ", ".join(clean_text(item, 100) for item in contacts[:3])
            )

    if robots_body and not parsed.disallowed_paths:
        notes.append("robots.txt was served but disallowed no paths.")
    if not robots_body:
        notes.append("No robots.txt was served at this origin.")

    # Feed the harness's own surface model, not just the payload.
    for url in discovered:
        ctx.session.surface.add_link(
            _link_record(ctx, url, first_seen_page=decision.url)
        )
    ctx.session.surface.robots = {
        "origin": origin,
        "has_robots": bool(robots_body),
        "has_security_txt": has_security_txt,
        "rule_count": len(parsed.rules),
        "crawl_delay_s": parsed.crawl_delay_s,
        "discovered_paths": discovered,
        "sitemap_urls": sitemap_urls,
    }

    data = ReadRobotsData(
        origin=origin,
        user_agents=parsed.user_agents[:20],
        rules=parsed.rules[:MAX_RULES],
        sitemap_urls=sitemap_urls,
        discovered_paths=discovered,
        files=files,
        has_security_txt=has_security_txt,
        crawl_delay_s=parsed.crawl_delay_s,
        notes=notes,
    )

    found_count = sum(1 for entry in files if entry.found)
    summary = (
        f"Checked {len(files)} well-known path(s) at {origin}; {found_count} returned content. "
        f"robots.txt "
        + ("was found" if robots_body else "was absent")
        + f" with {len(parsed.rules)} rule(s) and {len(parsed.user_agents)} user-agent block(s). "
        f"{len(discovered)} in-scope path(s) were derived from them"
        + (" and are now in the known-URL list." if discovered else ".")
        + (
            " Note: a Disallow entry is a disclosure hint, not a vulnerability."
            if parsed.disallowed_paths
            else ""
        )
    )
    if parsed.crawl_delay_s is not None:
        summary += (
            f" robots.txt requests a crawl-delay of {parsed.crawl_delay_s:g}s per user-agent; "
            "the harness rate limit is unchanged and remains the binding constraint."
        )
    return ok(summary, data)


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #


def _parse_robots(body: str) -> _RobotsParse:
    """Parse a robots.txt body into rules, sitemaps, crawl-delay and paths."""
    rules: list[RobotRule] = []
    user_agents: list[str] = []
    sitemaps: list[str] = []
    disallowed: list[str] = []
    crawl_delay: float | None = None
    current_agent = ""
    # Whether the current block is for all agents. Rules for `*` are the ones that tell us
    # what the operator considers sensitive, so they are kept.
    current_applies_to_all = False

    for raw_line in body.splitlines()[:2000]:
        line = _ROBOTS_COMMENT.sub("", raw_line).strip()
        if not line:
            continue
        match = _ROBOTS_DIRECTIVE.match(line)
        if not match:
            continue
        directive = match.group(1).lower()
        value = match.group(2).strip()

        if directive == "user-agent":
            agent = value.lower()
            current_agent = value[:200]
            current_applies_to_all = agent == "*"
            if current_agent and current_agent not in user_agents:
                user_agents.append(current_agent)
            continue

        if directive == "sitemap":
            if value:
                sitemaps.append(value[:500])
                rules.append(RobotRule(kind="sitemap", value=value[:500], user_agent=current_agent))
            continue

        if directive == "crawl-delay":
            try:
                parsed_delay = float(value)
            except ValueError:
                continue
            if 0 < parsed_delay <= MAX_CRAWL_DELAY_S:
                crawl_delay = parsed_delay if crawl_delay is None else min(crawl_delay, parsed_delay)
                rules.append(
                    RobotRule(kind="crawl-delay", value=value[:50], user_agent=current_agent)
                )
            continue

        if directive in {"disallow", "allow"}:
            if value in _IGNORED_RULE_VALUES:
                continue
            rules.append(RobotRule(kind=directive, value=value[:500], user_agent=current_agent))
            # Only '*' rules describe the operator's intent for an unknown crawler; a rule
            # under a named agent is not our business.
            if directive == "disallow" and (current_applies_to_all or not current_agent):
                disallowed.append(value[:500])
            # The cap is checked after every append so that a hostile 100k-line file cannot
            # grow the rule list before the loop notices.
            if len(rules) >= MAX_RULES:
                break
            continue

        rules.append(RobotRule(kind="other", value=f"{directive}: {value}"[:500], user_agent=current_agent))
        if len(rules) >= MAX_RULES:
            break

    return _RobotsParse(
        rules=rules,
        user_agents=user_agents,
        sitemaps=sitemaps,
        crawl_delay_s=crawl_delay,
        disallowed_paths=disallowed,
    )


def _parse_sitemap(body: str) -> list[str]:
    """Extract ``<loc>`` entries from a sitemap or sitemap index."""
    return [match[:500] for match in _SITEMAP_LOC.findall(body[:400_000])]


# --------------------------------------------------------------------------- #
# Path derivation
# --------------------------------------------------------------------------- #


def _build_discovered_paths(
    ctx, origin: str, disallowed: list[str], sitemaps: list[str]
) -> list[str]:
    """Turn robots rules and sitemap entries into absolute, in-scope URLs.

    Only URLs that pass the scope guard are returned, so the planner is never handed a link
    it would be refused for using. Wildcards in robots rules are dropped: expanding them
    would mean guessing paths, and guessing is exactly what this tool must not do.
    """
    candidates: list[str] = []

    for entry in disallowed:
        if any(character in entry for character in "*$"):
            continue
        candidates.append(urljoin(origin + "/", entry.lstrip("/")))

    for entry in sitemaps:
        absolute = urljoin(origin + "/", entry.strip())
        candidates.append(absolute)

    discovered: list[str] = []
    for url in _dedupe(candidates):
        parts = urlsplit(url)
        if parts.scheme not in {"http", "https"} or not parts.netloc:
            continue
        if not ctx.scope.check_url(url, resolve=False).allowed:
            continue
        discovered.append(url)
        if len(discovered) >= MAX_DISCOVERED_PATHS:
            break
    return discovered


def _link_record(ctx, url: str, *, first_seen_page: str):
    """Build a surface LinkRecord for a discovered path."""
    from app.models.scan import LinkRecord
    from urllib.parse import parse_qs

    decision = ctx.scope.check_url(url, resolve=False)
    query = parse_qs(urlsplit(url).query, keep_blank_values=True)
    return LinkRecord(
        url=url,
        first_seen_page=first_seen_page,
        in_scope=decision.allowed,
        scope_reason="" if decision.allowed else decision.reason,
        has_query=bool(query),
        query_keys=sorted(query)[:25],
    )


def _origin_of(url: str) -> str:
    parts = urlsplit(url)
    port = f":{parts.port}" if parts.port else ""
    return f"{parts.scheme.lower()}://{(parts.hostname or '').lower()}{port}"


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    unique: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            unique.append(value)
    return unique


__all__ = ["WELL_KNOWN_PATHS", "read_robots"]
