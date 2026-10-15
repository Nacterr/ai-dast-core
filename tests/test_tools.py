"""Tool and dispatcher tests against the live local demo target.

These exercise the real Playwright browser and the real HTTP client, so they are the
tests that actually prove the six MVP tools work. They run entirely against
127.0.0.1 - no external system is ever contacted.
"""

from __future__ import annotations

import pytest

from app.models.scan import ScanConfig
from app.models.tools import ToolCall, ToolStatus
from app.policy.permissions import Capability, PermissionSet
from app.tools.html_fallback import (
    extract_forms_from_html,
    extract_links_from_html,
    extract_scripts_from_html,
)

pytestmark = pytest.mark.integration


# --------------------------------------------------------------------------- #
# HTML fallback parsers (no browser needed)
# --------------------------------------------------------------------------- #

SAMPLE_HTML = """
<html><head>
  <base href="https://example.com/app/">
  <link rel="stylesheet" href="/static/a.css">
  <script src="https://cdn.example-cdn.test/lib.js"></script>
  <script>fetch("/api/v1/items");</script>
</head><body>
  <a href="page2?x=1">Page two</a>
  <a href="https://other.test/out">Other</a>
  <form action="/submit" method="post" enctype="multipart/form-data">
    <input type="hidden" name="csrf_token" value="t">
    <input type="text" name="title" required>
    <input type="file" name="upload">
    <select name="kind"><option value="a">A</option><option value="b">B</option></select>
    <button type="submit">Go</button>
  </form>
</body></html>
"""


def test_html_fallback_resolves_links_against_base() -> None:
    links = extract_links_from_html(SAMPLE_HTML, "https://example.com/app/")
    urls = {link["url"] for link in links}
    assert "https://example.com/app/page2?x=1" in urls
    assert "https://other.test/out" in urls
    assert "https://cdn.example-cdn.test/lib.js" in urls
    assert "https://example.com/static/a.css" in urls
    assert all(link["url"].startswith("http") for link in links)


def test_html_fallback_extracts_forms_and_heuristics() -> None:
    forms = extract_forms_from_html(SAMPLE_HTML, "https://example.com/app/")
    assert len(forms) == 1
    form = forms[0]
    assert form["action"] == "https://example.com/submit"
    assert form["method"] == "post"
    assert form["is_upload_form"] is True
    assert form["has_csrf_token"] is True
    names = {field["name"] for field in form["fields"]}  # type: ignore[union-attr]
    assert {"csrf_token", "title", "upload", "kind"} <= names
    # Submit controls are not fields.
    assert "Go" not in names


def test_html_fallback_ignores_non_http_schemes() -> None:
    html = '<a href="mailto:a@b.test">m</a><a href="javascript:void(0)">j</a><a href="/ok">o</a>'
    links = extract_links_from_html(html, "https://example.com/")
    assert [link["url"] for link in links] == ["https://example.com/ok"]


def test_html_fallback_extracts_scripts() -> None:
    scripts = extract_scripts_from_html(SAMPLE_HTML, "https://example.com/app/")
    kinds = [script["kind"] for script in scripts]
    assert "external" in kinds and "inline" in kinds
    external = next(script for script in scripts if script["kind"] == "external")
    assert external["src"] == "https://cdn.example-cdn.test/lib.js"


# --------------------------------------------------------------------------- #
# browser_open
# --------------------------------------------------------------------------- #


def test_browser_open_captures_page(ctx_factory, demo_server: str) -> None:
    ctx = ctx_factory(demo_server)
    result = ctx_registry_dispatch(ctx, "browser_open", {"url": demo_server + "/"})

    assert result.ok, result.error
    data = result.data
    assert data["status_code"] == 200
    assert "Demo Shop" in data["title"]
    assert data["html_bytes"] > 500
    assert len(data["html_sha256"]) == 64
    assert data["page_id"]
    # The page record must also land in the harness's own surface model.
    assert data["page_id"] in ctx.session.surface.pages


def test_browser_open_reports_third_party_contact(ctx_factory, demo_server: str) -> None:
    """The demo page pulls a CDN stylesheet and posts telemetry to another host."""
    ctx = ctx_factory(demo_server)
    result = ctx_registry_dispatch(ctx, "browser_open", {"url": demo_server + "/"})
    assert result.ok

    notes = " ".join(result.data.get("notes", []))
    # Third-party subresources are permitted but disclosed; script-initiated calls to
    # other hosts are blocked.
    assert "third-party" in notes or "blocked" in notes


def test_browser_open_refuses_out_of_scope_url(ctx_factory, demo_server: str) -> None:
    ctx = ctx_factory(demo_server)
    result = ctx_registry_dispatch(ctx, "browser_open", {"url": "https://not-in-scope.test/"})
    assert result.status == ToolStatus.ERROR
    assert "out of scope" in (result.error or "").lower()
    # And nothing was opened.
    assert ctx.session.surface.pages == {}


def test_browser_open_accepts_static_capture_with_javascript_disabled(
    ctx_factory, demo_server: str
) -> None:
    ctx = ctx_factory(demo_server)
    result = ctx_registry_dispatch(
        ctx, "browser_open", {"url": demo_server + "/", "disable_javascript": True}
    )
    assert result.ok
    assert result.data["status_code"] == 200
    assert any("JavaScript disabled" in note for note in result.data["notes"])


def test_browser_open_rejects_invalid_arguments(ctx_factory, demo_server: str) -> None:
    ctx = ctx_factory(demo_server)
    result = ctx_registry_dispatch(
        ctx, "browser_open", {"url": demo_server + "/", "wait_until": "whenever"}
    )
    assert result.status == ToolStatus.DENIED
    assert "wait_until" in (result.denial_reason or "")


# --------------------------------------------------------------------------- #
# extract_*
# --------------------------------------------------------------------------- #


def test_extract_links_annotates_scope(ctx_factory, demo_server: str) -> None:
    ctx = ctx_factory(demo_server)
    opened = ctx_registry_dispatch(ctx, "browser_open", {"url": demo_server + "/"})
    assert opened.ok

    result = ctx_registry_dispatch(ctx, "extract_links", {"page_id": opened.data["page_id"]})
    assert result.ok, result.error
    data = result.data
    assert data["total_found"] > 0

    by_url = {link["url"]: link for link in data["links"]}
    search = next((url for url in by_url if "/search?" in url), None)
    assert search is not None, f"expected a search link, got {sorted(by_url)[:12]}"
    assert by_url[search]["in_scope"] is True
    assert by_url[search]["has_query"] is True
    assert "q" in by_url[search]["query_keys"]

    external = next((url for url in by_url if "example-external.test" in url), None)
    if external is not None:
        assert by_url[external]["in_scope"] is False
        assert by_url[external]["scope_reason"]


def test_extract_links_populates_the_attack_surface(ctx_factory, demo_server: str) -> None:
    ctx = ctx_factory(demo_server)
    opened = ctx_registry_dispatch(ctx, "browser_open", {"url": demo_server + "/"})
    ctx_registry_dispatch(ctx, "extract_links", {"page_id": opened.data["page_id"]})
    assert ctx.session.surface.links
    assert ctx.session.surface.in_scope_urls()


def test_extract_forms_reports_heuristics(ctx_factory, demo_server: str) -> None:
    ctx = ctx_factory(demo_server)
    opened = ctx_registry_dispatch(ctx, "browser_open", {"url": demo_server + "/"})
    result = ctx_registry_dispatch(ctx, "extract_forms", {"page_id": opened.data["page_id"]})
    assert result.ok, result.error

    forms = result.data["forms"]
    assert len(forms) >= 3
    assert result.data["ready_for_submit"] is False

    by_id = {form["form_id"]: form for form in forms}
    assert by_id["login"]["is_login_form"] is True
    assert by_id["login"]["has_csrf_token"] is True
    assert by_id["checkout"]["is_upload_form"] is True
    assert by_id["checkout"]["has_csrf_token"] is False
    # A state-changing form with no CSRF token must be flagged for the planner.
    assert any("CSRF" in note for note in by_id["checkout"]["notes"])


def test_extract_forms_honours_hidden_filter(ctx_factory, demo_server: str) -> None:
    ctx = ctx_factory(demo_server)
    opened = ctx_registry_dispatch(ctx, "browser_open", {"url": demo_server + "/"})
    result = ctx_registry_dispatch(
        ctx, "extract_forms", {"page_id": opened.data["page_id"], "include_hidden": False}
    )
    login = next(form for form in result.data["forms"] if form["form_id"] == "login")
    assert all(field["field_type"] != "hidden" for field in login["fields"])


def test_extract_scripts_harvests_endpoints_and_redacts_secrets(
    ctx_factory, demo_server: str
) -> None:
    ctx = ctx_factory(demo_server)
    opened = ctx_registry_dispatch(ctx, "browser_open", {"url": demo_server + "/"})
    result = ctx_registry_dispatch(ctx, "extract_scripts", {"page_id": opened.data["page_id"]})
    assert result.ok, result.error
    data = result.data

    assert data["external_count"] >= 1
    assert data["inline_count"] >= 1

    endpoints = " ".join(data["api_endpoints"])
    assert "/api/v1" in endpoints or "/api/v2" in endpoints or "/graphql" in endpoints
    # Only in-scope endpoints are surfaced to the planner.
    assert all(endpoint.startswith(("http://", "https://")) for endpoint in data["api_endpoints"])

    # The demo page contains an AWS-looking key: it must be reported as a hint only.
    assert data["secrets_hints"], "expected a redacted credential hint"
    assert not any("AKIAIOSFODNN7EXAMPLE1234" in hint for hint in data["secrets_hints"])


def test_extract_tools_require_an_opened_page(ctx_factory, demo_server: str) -> None:
    ctx = ctx_factory(demo_server)
    result = ctx_registry_dispatch(ctx, "extract_links", {})
    assert result.status == ToolStatus.ERROR
    assert "browser_open" in (result.error or "")


def test_extract_links_unknown_page_id_is_an_error(ctx_factory, demo_server: str) -> None:
    ctx = ctx_factory(demo_server)
    ctx_registry_dispatch(ctx, "browser_open", {"url": demo_server + "/"})
    result = ctx_registry_dispatch(ctx, "extract_links", {"page_id": "p-does-not-exist"})
    assert result.status == ToolStatus.ERROR
    assert "page_id" in (result.error or "")


# --------------------------------------------------------------------------- #
# check_headers
# --------------------------------------------------------------------------- #


def test_check_headers_finds_missing_headers_and_banners(
    ctx_factory, demo_server: str
) -> None:
    ctx = ctx_factory(demo_server)
    result = ctx_registry_dispatch(ctx, "check_headers", {"url": demo_server + "/"})
    assert result.ok, result.error

    report = result.data["reports"][0]
    assert report["status_code"] == 200
    assert report["missing_count"] > 5
    assert report["grade"] in {"D", "F"}

    checks = {check["header"]: check for check in report["checks"]}
    for header in ("strict-transport-security", "content-security-policy", "referrer-policy"):
        assert checks[header]["present"] is False
        assert checks[header]["status"] == "missing"

    # Banner disclosure must be noticed.
    assert "DemoShop" in report["server"] or "Express" in report["powered_by"]

    titles = " ".join(finding["title"] for finding in result.findings)
    assert "Content-Security-Policy" in titles or "Strict-Transport-Security" in titles

    # Every finding must carry traceable evidence.
    for finding in result.findings:
        assert finding["evidence"], f"finding without evidence: {finding['title']}"
        assert finding["url"]


def test_check_headers_does_not_duplicate_the_cors_assessment(ctx_factory, demo_server: str) -> None:
    """CORS moved to ``analyze_cors``, which can tell a reflection from a fixed value.

    A weaker check here would report the same misconfiguration twice, at two different
    severities. This asserts the handover actually happened.
    """
    ctx = ctx_factory(demo_server)
    result = ctx_registry_dispatch(ctx, "check_headers", {"url": demo_server + "/"})
    assert result.ok
    assert not any(
        "access-control" in finding["location"] for finding in result.findings
    ), "check_headers should no longer assess CORS"


def test_check_headers_findings_are_deduplicated_by_identity(
    ctx_factory, demo_server: str
) -> None:
    ctx = ctx_factory(demo_server)
    result = ctx_registry_dispatch(ctx, "check_headers", {"url": demo_server + "/"})
    keys = [finding["id"] for finding in result.findings]
    assert len(keys) == len(set(keys))


def test_check_headers_refuses_out_of_scope(ctx_factory, demo_server: str) -> None:
    ctx = ctx_factory(demo_server)
    result = ctx_registry_dispatch(ctx, "check_headers", {"url": "https://elsewhere.test/"})
    assert result.status == ToolStatus.ERROR
    assert "out of scope" in (result.error or "").lower()


# --------------------------------------------------------------------------- #
# check_cookies
# --------------------------------------------------------------------------- #


def test_check_cookies_reports_attribute_problems(ctx_factory, demo_server: str) -> None:
    ctx = ctx_factory(demo_server)
    result = ctx_registry_dispatch(ctx, "check_cookies", {"url": demo_server + "/"})
    assert result.ok, result.error

    summary = result.data["summaries"][0]
    cookies = {cookie["name"]: cookie for cookie in summary["cookies"]}
    # The demo sends three Set-Cookie headers, one with an Expires containing a comma,
    # which is the case naive splitters get wrong.
    assert {"sessionid", "theme", "csrftoken"} <= set(cookies)

    session_cookie = cookies["sessionid"]
    assert session_cookie["secure"] is False
    assert session_cookie["http_only"] is False
    assert session_cookie["same_site"] == "unspecified"

    theme = cookies["theme"]
    assert theme["domain"] == ".127.0.0.1"
    assert any("Domain=" in issue for issue in theme["issues"])

    csrf = cookies["csrftoken"]
    assert csrf["same_site"] == "strict"

    # Values must never be stored, only their length and a hash.
    for cookie in summary["cookies"]:
        assert cookie["value_length"] > 0
        assert len(cookie["value_sha256"]) == 64
        assert "value" not in cookie

    titles = " ".join(finding["title"] for finding in result.findings)
    assert "Secure" in titles
    assert "HttpOnly" in titles


def test_check_cookies_findings_are_grouped_not_per_cookie(
    ctx_factory, demo_server: str
) -> None:
    """Three cookies with three problems must not become nine findings."""
    ctx = ctx_factory(demo_server)
    result = ctx_registry_dispatch(ctx, "check_cookies", {"url": demo_server + "/"})
    assert len(result.findings) <= 6
    assert all(finding["evidence"] for finding in result.findings)


# --------------------------------------------------------------------------- #
# Dispatcher pipeline
# --------------------------------------------------------------------------- #


def test_unknown_tool_is_denied(ctx_factory, demo_server: str) -> None:
    ctx = ctx_factory(demo_server)
    result = ctx_registry_dispatch(ctx, "run_shell", {"command": "id"})
    assert result.status == ToolStatus.DENIED
    assert "unknown tool" in (result.denial_reason or "")


def test_roadmap_tool_is_not_implemented(ctx_factory, demo_server: str) -> None:
    ctx = ctx_factory(demo_server)
    result = ctx_registry_dispatch(ctx, "run_zap_baseline", {})
    assert result.status == ToolStatus.NOT_IMPLEMENTED


def test_capability_removal_denies_the_tool(ctx_factory, demo_server: str) -> None:
    permissions = PermissionSet()
    permissions.revoke(Capability.HTTP_EGRESS)
    ctx = ctx_factory(demo_server, permissions=permissions)
    result = ctx_registry_dispatch(ctx, "check_headers", {"url": demo_server + "/"})
    assert result.status == ToolStatus.DENIED
    assert "http_egress" in (result.denial_reason or "")


def test_argument_guard_blocks_a_smuggled_command(ctx_factory, demo_server: str) -> None:
    ctx = ctx_factory(demo_server)
    result = ctx_registry_dispatch(
        ctx, "check_headers", {"url": demo_server + "/", "command": "curl evil.test"}
    )
    assert result.status == ToolStatus.DENIED
    assert "reserved" in (result.denial_reason or "")


def test_tool_call_budget_is_enforced(ctx_factory, demo_server: str) -> None:
    config = ScanConfig(max_tool_calls=1, requests_per_second=50.0)
    ctx = ctx_factory(demo_server, config=config)
    first = ctx_registry_dispatch(ctx, "check_headers", {"url": demo_server + "/"})
    assert first.ok
    second = ctx_registry_dispatch(ctx, "check_headers", {"url": demo_server + "/"})
    assert second.status == ToolStatus.DENIED
    assert "budget" in (second.denial_reason or "").lower()


def test_second_request_is_refused_when_only_one_is_budgeted(
    ctx_factory, demo_server: str
) -> None:
    """The request budget is hard: the first request fits, the second is refused."""
    config = ScanConfig(max_requests=1, requests_per_second=50.0)
    ctx = ctx_factory(demo_server, config=config)
    first = ctx_registry_dispatch(ctx, "check_headers", {"url": demo_server + "/"})
    assert first.ok
    second = ctx_registry_dispatch(ctx, "check_cookies", {"url": demo_server + "/"})
    assert second.status == ToolStatus.DENIED
    assert "requests" in (second.denial_reason or "").lower()


def test_extra_unknown_arguments_are_rejected(ctx_factory, demo_server: str) -> None:
    """``extra='forbid'`` on every request model is a real defence, not decoration."""
    ctx = ctx_factory(demo_server)
    result = ctx_registry_dispatch(
        ctx, "check_headers", {"url": demo_server + "/", "follow_redirects": True, "evil": 1}
    )
    assert result.status == ToolStatus.DENIED
    assert "evil" in (result.denial_reason or "")


def test_confirmation_gate_blocks_when_declined(ctx_factory, demo_server: str) -> None:
    from app.policy.permissions import ConfirmationGate

    ctx = ctx_factory(demo_server)
    ctx.confirmation = ConfirmationGate(interactive=False)
    ctx.session.config.require_confirmation = True
    # browser_open does not require confirmation, so use a tool that does by declaring
    # it temporarily on the registry entry.
    from app.tools.catalog import CHECK_HEADERS

    original = CHECK_HEADERS.meta.requires_confirmation
    CHECK_HEADERS.meta.requires_confirmation = True
    try:
        result = ctx_registry_dispatch(ctx, "check_headers", {"url": demo_server + "/"})
        assert result.status == ToolStatus.DENIED
        assert "confirmation" in (result.denial_reason or "").lower()
    finally:
        CHECK_HEADERS.meta.requires_confirmation = original


# --------------------------------------------------------------------------- #
# Helper
# --------------------------------------------------------------------------- #


def ctx_registry_dispatch(ctx, tool: str, args: dict):
    """Dispatch through a fresh registry so each call sees the same policy path."""
    from app.tools.catalog import build_default_registry

    registry = build_default_registry()
    return registry.dispatch(ToolCall(tool=tool, args=args), ctx)
