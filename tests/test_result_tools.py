"""Tests for the result tools and well-known file discovery.

Two halves:

* **Parsing** (fast, no network) — the robots.txt and sitemap parsers, which are the parts
  most likely to meet hostile real-world input.
* **Tools** (``integration``) — ``read_robots``, ``get_scan_status``, ``get_alerts`` and
  ``get_http_history`` against the local demo target.
"""

from __future__ import annotations

import pytest

from app.models.tools import (
    GetAlertsRequest,
    GetHttpHistoryRequest,
    GetScanStatusRequest,
    ReadRobotsRequest,
    ToolCall,
    ToolStatus,
)
from app.tools.well_known import (
    WELL_KNOWN_PATHS,
    _build_discovered_paths,
    _parse_robots,
    _parse_sitemap,
)


# --------------------------------------------------------------------------- #
# robots.txt parsing
# --------------------------------------------------------------------------- #

ROBOTS_SAMPLE = """
# a comment
User-agent: *
Disallow: /admin
Disallow: /api/v1/orders
Disallow:
Allow: /public
Crawl-delay: 2

User-agent: BadBot
Disallow: /

Sitemap: https://example.com/sitemap.xml
"""


def test_parse_robots_extracts_rules_and_agents() -> None:
    parsed = _parse_robots(ROBOTS_SAMPLE)
    assert parsed.user_agents == ["*", "BadBot"]
    assert "/admin" in parsed.disallowed_paths
    assert "/api/v1/orders" in parsed.disallowed_paths
    # The rule under a named agent is recorded but not treated as our concern.
    assert "/" not in parsed.disallowed_paths
    assert parsed.crawl_delay_s == 2.0
    assert parsed.sitemaps == ["https://example.com/sitemap.xml"]


def test_parse_robots_ignores_empty_and_wildcard_disallow() -> None:
    """``Disallow:`` (empty) means 'allow everything', not 'disallow everything'."""
    parsed = _parse_robots("User-agent: *\nDisallow:\nDisallow: *\n")
    assert parsed.disallowed_paths == []


def test_parse_robots_handles_comments_and_whitespace() -> None:
    parsed = _parse_robots("  User-agent:   *   # comment\n   Disallow: /secret  # why\n")
    assert parsed.user_agents == ["*"]
    assert parsed.disallowed_paths == ["/secret"]


def test_parse_robots_bounds_a_hostile_body() -> None:
    """A 100k-line robots.txt must not be able to consume memory or CPU."""
    body = "\n".join(f"Disallow: /path-{index}" for index in range(100_000))
    body = "User-agent: *\n" + body
    parsed = _parse_robots(body)
    assert len(parsed.rules) <= 200


def test_parse_robots_rejects_absurd_crawl_delay() -> None:
    parsed = _parse_robots("User-agent: *\nCrawl-delay: 999999\n")
    assert parsed.crawl_delay_s is None


def test_parse_robots_takes_the_smallest_crawl_delay() -> None:
    parsed = _parse_robots("User-agent: *\nCrawl-delay: 10\nUser-agent: X\nCrawl-delay: 3\n")
    assert parsed.crawl_delay_s == 3.0


def test_parse_robots_tolerates_malformed_lines() -> None:
    parsed = _parse_robots("this is not a directive\n:::\nUser-agent: *\nDisallow: /a\n")
    assert parsed.disallowed_paths == ["/a"]


def test_parse_sitemap_extracts_loc_entries() -> None:
    body = "<urlset><url><loc>https://a.test/x</loc></url><url><loc>/y</loc></url></urlset>"
    assert _parse_sitemap(body) == ["https://a.test/x", "/y"]


def test_parse_sitemap_handles_no_entries() -> None:
    assert _parse_sitemap("<urlset></urlset>") == []


def test_well_known_paths_are_harness_owned_constants() -> None:
    """The tool must fetch a fixed list; a caller cannot ask it to probe arbitrary paths."""
    assert set(WELL_KNOWN_PATHS) == {"/robots.txt", "/sitemap.xml", "/.well-known/security.txt"}
    assert all(path.startswith("/") for path in WELL_KNOWN_PATHS)


def test_wildcard_disallow_entries_are_not_expanded() -> None:
    """Expanding ``/private/*`` would mean guessing paths; the tool must not guess."""

    class _Ctx:
        class scope:  # noqa: N801
            @staticmethod
            def check_url(url, resolve=False):  # noqa: ANN001
                class _D:
                    allowed = True
                    reason = ""

                return _D()

    discovered = _build_discovered_paths(
        _Ctx(), "https://example.com", ["/a*", "/b$", "/real"], []
    )
    assert discovered == ["https://example.com/real"]


# --------------------------------------------------------------------------- #
# read_robots against the demo target
# --------------------------------------------------------------------------- #

pytestmark_integration = pytest.mark.integration


def _dispatch(ctx, tool: str, args: dict):
    from app.tools.catalog import build_default_registry

    return build_default_registry().dispatch(ToolCall(tool=tool, args=args), ctx)


@pytest.mark.integration
def test_read_robots_finds_and_parses_the_policy_files(ctx_factory, demo_server: str) -> None:
    ctx = ctx_factory(demo_server)
    result = _dispatch(ctx, "read_robots", {"url": demo_server + "/"})

    assert result.ok, result.error
    data = result.data
    assert data["origin"] == demo_server
    assert len(data["files"]) == 3
    found = {entry["path"] for entry in data["files"] if entry["found"]}
    assert found == {"/robots.txt", "/sitemap.xml", "/.well-known/security.txt"}

    assert "*" in data["user_agents"]
    assert "BadBot" in data["user_agents"]
    assert data["crawl_delay_s"] == 1.0
    assert data["has_security_txt"] is True

    # Disallow rules are on the '*'-agent block, so they are ours to consider.
    rules = {(rule["kind"], rule["value"]) for rule in data["rules"]}
    assert ("disallow", "/admin") in rules
    assert ("disallow", "/api/v1/orders") in rules
    assert ("disallow", "/internal/metrics") in rules


@pytest.mark.integration
def test_read_robots_derives_in_scope_paths(ctx_factory, demo_server: str) -> None:
    ctx = ctx_factory(demo_server)
    result = _dispatch(ctx, "read_robots", {"url": demo_server + "/"})
    discovered = result.data["discovered_paths"]

    assert any(url.endswith("/admin") for url in discovered)
    assert any(url.endswith("/internal/metrics") for url in discovered)
    # Every derived URL must be absolute and fetchable, or the planner would be handed a
    # link it is refused for using.
    for url in discovered:
        assert url.startswith(("http://", "https://"))
        assert ctx.scope.check_url(url, resolve=False).allowed

    # And they must land in the harness's own surface model.
    for url in discovered:
        assert url in ctx.session.surface.links


@pytest.mark.integration
def test_read_robots_records_the_structure_on_the_session(ctx_factory, demo_server: str) -> None:
    ctx = ctx_factory(demo_server)
    _dispatch(ctx, "read_robots", {"url": demo_server + "/"})
    robots = ctx.session.surface.robots
    assert robots["has_robots"] is True
    assert robots["has_security_txt"] is True
    assert robots["discovered_paths"]


@pytest.mark.integration
def test_read_robots_notes_the_security_contact(ctx_factory, demo_server: str) -> None:
    ctx = ctx_factory(demo_server)
    result = _dispatch(ctx, "read_robots", {"url": demo_server + "/"})
    notes = " ".join(result.data["notes"])
    assert "security@example.com" in notes


@pytest.mark.integration
def test_read_robots_can_skip_the_sitemap(ctx_factory, demo_server: str) -> None:
    ctx = ctx_factory(demo_server)
    result = _dispatch(ctx, "read_robots", {"url": demo_server + "/", "include_sitemap": False})
    assert all(entry["path"] != "/sitemap.xml" for entry in result.data["files"])


@pytest.mark.integration
def test_read_robots_handles_missing_files(ctx_factory, demo_server: str) -> None:
    """A 404 on a well-known path is information, not an error."""
    ctx = ctx_factory(demo_server)
    result = _dispatch(ctx, "read_robots", {"url": demo_server + "/nonexistent-dir/"})
    assert result.ok, result.error
    # The demo server only serves these at the root, so a subpath returns the 404 page,
    # which is not valid policy content but is still a 200 with HTML.
    assert result.data["files"]


@pytest.mark.integration
def test_read_robots_refuses_out_of_scope(ctx_factory, demo_server: str) -> None:
    ctx = ctx_factory(demo_server)
    result = _dispatch(ctx, "read_robots", {"url": "https://elsewhere.test/"})
    assert result.status == ToolStatus.ERROR
    assert "out of scope" in (result.error or "").lower()


@pytest.mark.integration
def test_read_robots_records_http_exchanges(ctx_factory, demo_server: str) -> None:
    ctx = ctx_factory(demo_server)
    _dispatch(ctx, "read_robots", {"url": demo_server + "/"})
    history = ctx.session.surface.http_history
    assert len(history) == 3
    assert {entry.requested_url.rsplit("/", 1)[-1] for entry in history} == {
        "robots.txt",
        "sitemap.xml",
        "security.txt",
    }
    assert all(entry.status_code == 200 for entry in history)


# --------------------------------------------------------------------------- #
# get_scan_status
# --------------------------------------------------------------------------- #


@pytest.mark.integration
def test_get_scan_status_is_free_and_reports_progress(ctx_factory, demo_server: str) -> None:
    ctx = ctx_factory(demo_server)
    opened = _dispatch(ctx, "browser_open", {"url": demo_server + "/"})
    links = _dispatch(ctx, "extract_links", {"page_id": opened.data["page_id"]})
    assert links.ok

    before = ctx.limits.budgets["requests"].used
    result = _dispatch(ctx, "get_scan_status", {})
    after = ctx.limits.budgets["requests"].used

    assert result.ok, result.error
    assert after == before, "a result tool must not consume request budget"

    data = result.data
    assert data["pages_opened"] == 1
    assert data["urls_known"] > 0
    assert data["urls_in_scope"] > 0
    assert "browser_open" in data["tools_used"]
    assert "extract_links" in data["tools_used"]
    assert data["findings_total"] == 0
    assert data["remaining"]["steps"] > 0
    assert data["suggestions"], "the harness should be able to name its own gaps"


@pytest.mark.integration
def test_get_scan_status_suggests_unrun_tools(ctx_factory, demo_server: str) -> None:
    ctx = ctx_factory(demo_server)
    _dispatch(ctx, "browser_open", {"url": demo_server + "/"})
    result = _dispatch(ctx, "get_scan_status", {})
    suggestions = " ".join(result.data["suggestions"]).lower()
    assert "check_headers" in suggestions
    assert "read_robots" in suggestions


@pytest.mark.integration
def test_get_scan_status_reports_finding_counts(ctx_factory, demo_server: str) -> None:
    ctx = ctx_factory(demo_server)
    _dispatch(ctx, "check_headers", {"url": demo_server + "/"})
    # Fold findings the way the loop does, then ask.
    result = _dispatch(ctx, "get_scan_status", {})
    assert "check_headers" in result.data["tools_used"]
    # The tool call itself carries findings; the session only gets them via the loop, so
    # counts here reflect the session, which is zero for a bare dispatch.
    assert result.data["findings_total"] == 0


# --------------------------------------------------------------------------- #
# get_alerts
# --------------------------------------------------------------------------- #


def _run_finding_tool(ctx, tool: str, args: dict):
    """Dispatch a finding-producing tool and fold its findings into the session."""
    from app.models.finding import Finding

    result = _dispatch(ctx, tool, args)
    for payload in result.findings:
        ctx.session.findings.append(Finding.model_validate(payload))
    return result


@pytest.mark.integration
def test_get_alerts_returns_findings_produced_earlier(ctx_factory, demo_server: str) -> None:
    ctx = ctx_factory(demo_server)
    produced = _run_finding_tool(ctx, "check_headers", {"url": demo_server + "/"})
    assert produced.findings

    before = ctx.limits.budgets["requests"].used
    result = _dispatch(ctx, "get_alerts", {})
    assert ctx.limits.budgets["requests"].used == before, "get_alerts must be free"

    assert result.ok, result.error
    assert result.data["total_findings"] == len(produced.findings)
    assert result.data["returned"] == len(produced.findings)
    titles = {alert["title"] for alert in result.data["alerts"]}
    assert titles == {finding["title"] for finding in produced.findings}
    for alert in result.data["alerts"]:
        assert alert["evidence_count"] >= 1


@pytest.mark.integration
def test_get_alerts_filters_by_severity(ctx_factory, demo_server: str) -> None:
    ctx = ctx_factory(demo_server)
    # The demo target reflects any Origin with credentials on /api/reflect, which is a high.
    _run_finding_tool(ctx, "analyze_cors", {"url": demo_server + "/api/reflect"})

    high = _dispatch(ctx, "get_alerts", {"severity": "high"})
    assert high.ok
    assert all(alert["severity"] in {"high", "critical"} for alert in high.data["alerts"])
    assert high.data["alerts"], "expected at least one high finding"


@pytest.mark.integration
def test_get_alerts_filters_by_category(ctx_factory, demo_server: str) -> None:
    ctx = ctx_factory(demo_server)
    _run_finding_tool(ctx, "analyze_cors", {"url": demo_server + "/api/reflect"})
    result = _dispatch(ctx, "get_alerts", {"category": "cors"})
    assert result.ok
    assert all(alert["category"] == "cors" for alert in result.data["alerts"])
    assert result.data["alerts"]


@pytest.mark.integration
def test_get_alerts_filtering_out_everything_is_not_an_error(ctx_factory, demo_server: str) -> None:
    ctx = ctx_factory(demo_server)
    result = _dispatch(ctx, "get_alerts", {"severity": "critical"})
    assert result.ok
    assert result.data["alerts"] == []
    assert "not that the target is clean" in result.summary


@pytest.mark.integration
def test_get_alerts_rejects_an_invalid_severity(ctx_factory, demo_server: str) -> None:
    ctx = ctx_factory(demo_server)
    result = _dispatch(ctx, "get_alerts", {"severity": "catastrophic"})
    assert result.status == ToolStatus.DENIED
    assert "severity" in (result.denial_reason or "")


@pytest.mark.integration
def test_get_alerts_respects_the_limit(ctx_factory, demo_server: str) -> None:
    ctx = ctx_factory(demo_server)
    _run_finding_tool(ctx, "check_headers", {"url": demo_server + "/"})
    result = _dispatch(ctx, "get_alerts", {"limit": 3})
    assert result.data["returned"] <= 3
    assert result.data["matched"] > 3


# --------------------------------------------------------------------------- #
# get_http_history
# --------------------------------------------------------------------------- #


@pytest.mark.integration
def test_get_http_history_reads_without_sending(ctx_factory, demo_server: str) -> None:
    ctx = ctx_factory(demo_server)
    _run_finding_tool(ctx, "check_headers", {"url": demo_server + "/"})

    before = ctx.limits.budgets["requests"].used
    result = _dispatch(ctx, "get_http_history", {})
    assert ctx.limits.budgets["requests"].used == before

    assert result.ok, result.error
    assert result.data["total_exchanges"] == 1
    entry = result.data["entries"][0]
    assert entry["status_code"] == 200
    assert entry["requested_url"] == demo_server + "/"
    # Tool attribution is added by the orchestrator, which is what knows the trace index;
    # a bare dispatch through the registry legitimately leaves it blank.
    assert entry["tool"] in {"", "check_headers"}


@pytest.mark.integration
def test_get_http_history_is_empty_before_any_traffic(ctx_factory, demo_server: str) -> None:
    ctx = ctx_factory(demo_server)
    result = _dispatch(ctx, "get_http_history", {})
    assert result.ok
    assert result.data["total_exchanges"] == 0
    assert "check_headers" in result.summary


@pytest.mark.integration
def test_get_http_history_filters_by_host(ctx_factory, demo_server: str) -> None:
    ctx = ctx_factory(demo_server)
    _run_finding_tool(ctx, "check_headers", {"url": demo_server + "/"})
    matching = _dispatch(ctx, "get_http_history", {"host": "127.0.0.1"})
    assert matching.data["returned"] == 1
    missing = _dispatch(ctx, "get_http_history", {"host": "not-this-host.test"})
    assert missing.data["returned"] == 0


@pytest.mark.integration
def test_get_http_history_counts_redirects(ctx_factory, demo_server: str) -> None:
    ctx = ctx_factory(demo_server)
    _dispatch(ctx, "check_headers", {"url": demo_server + "/"})
    result = _dispatch(ctx, "get_http_history", {"redirects_only": True})
    assert result.ok
    # The demo target serves / directly, so nothing redirected.
    assert result.data["returned"] == 0
    assert result.data["redirects_followed"] == 0


def test_http_history_record_flags_a_blocked_redirect() -> None:
    from app.models.scan import HttpExchangeRecord

    blocked = HttpExchangeRecord(
        requested_url="https://a.test/",
        final_url="https://a.test/",
        error="redirect to https://evil.test/ refused: host 'evil.test' is not in scope",
    )
    assert blocked.crossed_scope_boundary is True
    clean = HttpExchangeRecord(requested_url="https://a.test/", final_url="https://a.test/")
    assert clean.crossed_scope_boundary is False


def test_http_history_is_capped() -> None:
    """A long scan must not grow the transaction log without bound."""
    from app.models.scan import AttackSurface, HttpExchangeRecord

    surface = AttackSurface()
    for index in range(AttackSurface.MAX_HTTP_HISTORY + 50):
        surface.record_exchange(
            HttpExchangeRecord(requested_url=f"https://a.test/{index}", final_url="")
        )
    assert len(surface.http_history) == AttackSurface.MAX_HTTP_HISTORY
    # The oldest entries are the ones evicted.
    assert surface.http_history[0].requested_url == "https://a.test/50"


def test_redirect_chains_are_detected() -> None:
    from app.models.scan import AttackSurface, HttpExchangeRecord

    surface = AttackSurface()
    surface.record_exchange(
        HttpExchangeRecord(
            requested_url="https://a.test/",
            final_url="https://a.test/home",
            redirect_chain=["https://a.test/", "https://a.test/home"],
        )
    )
    surface.record_exchange(
        HttpExchangeRecord(requested_url="https://a.test/x", final_url="https://a.test/x")
    )
    chains = surface.redirect_chains()
    assert len(chains) == 1
    assert chains[0].requested_url == "https://a.test/"
