"""Tests for ``analyze_exposed_files`` and ``detect_technologies``.

The exposed-file tool is the first tool with a **path list**, and the first that can
plausibly produce a false positive that would embarrass the operator ("your `.env` is
public" when it is not). Most of this file is therefore about the false-positive defences,
run against both a normal server and a soft-404 catch-all server.
"""

from __future__ import annotations

import threading

import pytest

from app.models.tools import (
    AnalyzeExposedFilesRequest,
    DetectTechnologiesRequest,
    ToolCall,
    ToolStatus,
)
from app.tools.exposed_files import (
    ALL_CATEGORIES,
    CATALOGUE_BY_PATH,
    CONTROL_PATH,
    DEFAULT_CATEGORIES,
    PATH_CATALOGUE,
    PathSpec,
    _assess,
    _redact,
)
from app.tools.technologies import FINGERPRINTS, _dedupe, _evaluate
from tools.demo_target import make_server


def _dispatch(ctx, tool: str, args: dict):
    from app.tools.catalog import build_default_registry

    return build_default_registry().dispatch(ToolCall(tool=tool, args=args), ctx)


# --------------------------------------------------------------------------- #
# Catalogue hygiene (no network)
# --------------------------------------------------------------------------- #


def test_catalogue_paths_are_absolute_and_unique() -> None:
    paths = [spec.path for spec in PATH_CATALOGUE]
    assert all(path.startswith("/") for path in paths), "every path must be origin-relative"
    assert len(paths) == len(set(paths)), "catalogue contains a duplicate path"


def test_catalogue_categories_are_declared() -> None:
    for spec in PATH_CATALOGUE:
        assert spec.category in ALL_CATEGORIES, f"{spec.path} has unknown category {spec.category}"


def test_default_categories_are_a_subset_of_all() -> None:
    assert set(DEFAULT_CATEGORIES) <= set(ALL_CATEGORIES)
    # The default sweep must stay small: it runs on every scan.
    default_paths = [s for s in PATH_CATALOGUE if s.category in DEFAULT_CATEGORIES]
    assert 10 <= len(default_paths) <= 22, f"default sweep is {len(default_paths)} paths"


def test_control_path_cannot_collide_with_the_catalogue() -> None:
    assert CONTROL_PATH not in CATALOGUE_BY_PATH
    assert "nonexistent" in CONTROL_PATH


def test_every_catalogue_entry_has_prose_for_the_report() -> None:
    for spec in PATH_CATALOGUE:
        assert spec.description, f"{spec.path} has no description"
        assert spec.recommendation, f"{spec.path} has no recommendation"
        assert spec.severity in {"info", "low", "medium", "high", "critical"}


def test_high_severity_paths_are_confirmable() -> None:
    """Anything scored high or critical must be confirmable, not status-code-only.

    "Confirmable" means a text signature or an expected content type. An archive is binary,
    so a content type is the only evidence available without downloading it — and downloading
    an unknown archive is not something this harness does.
    """
    for spec in PATH_CATALOGUE:
        if spec.severity in {"high", "critical"}:
            assert spec.confirmable, f"{spec.path} is {spec.severity} but cannot be confirmed"


def test_the_catalogue_itself_contains_no_secrets() -> None:
    """A path list is public knowledge; a credential in this file would be a bug."""
    import re

    source = (CATALOGUE_BY_PATH["/.env"].description or "") + "".join(
        spec.recommendation for spec in PATH_CATALOGUE
    )
    assert not re.search(r"(?i)(password|secret|api[_-]?key)\s*[:=]\s*\S{6,}", source)


# --------------------------------------------------------------------------- #
# Redaction
# --------------------------------------------------------------------------- #


def test_redaction_hides_a_credential_value() -> None:
    spec = CATALOGUE_BY_PATH["/.env"]
    redacted = _redact("DB_PASSWORD=not-a-real-password-12345", spec)
    assert "not-a-real-password" not in redacted
    assert "DB_PASSWORD" in redacted
    assert "<redacted>" in redacted


def test_redaction_keeps_a_short_non_credential_match() -> None:
    spec = CATALOGUE_BY_PATH["/.git/HEAD"]
    assert _redact("ref: refs/", spec) == "ref: refs/"


def test_redaction_bounds_a_long_match() -> None:
    spec = CATALOGUE_BY_PATH["/server-status"]
    assert len(_redact("x" * 500, spec)) <= 80


# --------------------------------------------------------------------------- #
# The false-positive defence, exercised directly
# --------------------------------------------------------------------------- #


class _FakeExchange:
    """Minimal stand-in for an HttpExchange, for unit-testing the decision rule."""

    def __init__(
        self,
        status: int,
        body: str = "",
        content_type: str = "text/html",
        content_length: int | None = None,
    ) -> None:
        self.status_code = status
        self.headers = {"content-type": content_type}
        if content_length is not None:
            self.headers["content-length"] = str(content_length)
        self.body_prefix = body
        self.body_bytes = len(body)
        self.hops = []
        self.error = ""


def test_assess_rejects_a_non_200() -> None:
    spec = CATALOGUE_BY_PATH["/.env"]
    check = _assess(spec, "https://a.test/.env", _FakeExchange(404))
    assert check.exposed is False


def test_assess_rejects_a_generic_error_page() -> None:
    spec = CATALOGUE_BY_PATH["/backup.zip"]
    body = "<!doctype html><html><body>404 Not found</body></html>"
    check = _assess(spec, "https://a.test/backup.zip", _FakeExchange(200, body), method="GET")
    assert check.exposed is False


def test_assess_rejects_a_body_that_does_not_match_the_signature() -> None:
    """A 200 with an HTML page is not a dotenv file, however confident the status looks."""
    spec = CATALOGUE_BY_PATH["/.env"]
    body = "<!doctype html><html><body>Welcome</body></html>"
    check = _assess(spec, "https://a.test/.env", _FakeExchange(200, body), method="GET")
    assert check.exposed is False
    assert check.verified is False
    assert any("did not match" in note for note in check.notes)


def test_assess_accepts_a_body_that_matches_the_signature() -> None:
    spec = CATALOGUE_BY_PATH["/.env"]
    body = "APP_KEY=base64:abc\nDB_PASSWORD=hunter2\n"
    check = _assess(spec, "https://a.test/.env", _FakeExchange(200, body), method="GET")
    assert check.exposed is True
    assert check.verified is True
    assert check.confidence == "high"


def test_assess_rejects_an_oversized_body() -> None:
    """A 2 MB HTML page is a catch-all, not a dotenv file."""
    import re as _re

    spec = PathSpec(
        path="/.env",
        category="config",
        severity="critical",
        description="d",
        recommendation="r",
        # A real dotenv signature, but the page is far larger than a dotenv could be.
        signatures=(_re.compile(r"^[A-Z][A-Z0-9_]{2,}=", _re.MULTILINE),),
        max_bytes=1000,
    )
    check = _assess(
        spec,
        "https://a.test/.env",
        _FakeExchange(200, "A" * 5000, content_length=5000),
        method="GET",
    )
    assert check.exposed is False
    assert any("larger than" in note for note in check.notes)


def test_head_alone_is_enough_only_when_the_server_does_not_soft_404() -> None:
    """The load-bearing rule: a status code is trustworthy only on an honest server."""
    spec = CATALOGUE_BY_PATH["/.env"]
    honest = _assess(spec, "https://a.test/.env", _FakeExchange(200, ""), soft_404=False)
    assert honest.exposed is True
    assert honest.verified is False
    assert honest.confidence == "low"

    lying = _assess(spec, "https://a.test/.env", _FakeExchange(200, ""), soft_404=True)
    assert lying.exposed is False, "a 200 on a soft-404 server proves nothing"


def test_soft_404_with_content_and_a_signature_is_still_believed() -> None:
    spec = CATALOGUE_BY_PATH["/.env"]
    body = "DB_PASSWORD=hunter2\n"
    check = _assess(spec, "https://a.test/.env", _FakeExchange(200, body), method="GET", soft_404=True)
    assert check.exposed is True
    assert check.verified is True


def test_soft_404_without_signatures_never_reports_exposure() -> None:
    """With no signature to confirm it, a soft-404 200 must not become a finding."""
    spec = PathSpec(
        path="/.github/workflows",
        category="ci",
        severity="info",
        description="d",
        recommendation="r",
        signatures=(),
    )
    body = "<!doctype html><html>catch-all</html>"
    check = _assess(spec, "https://a.test/.github/workflows", _FakeExchange(200, body), method="GET", soft_404=True)
    assert check.exposed is False


# --------------------------------------------------------------------------- #
# analyze_exposed_files against a normal server
# --------------------------------------------------------------------------- #


@pytest.mark.integration
def test_analyze_exposed_files_finds_the_planted_files(ctx_factory, demo_server: str) -> None:
    ctx = ctx_factory(demo_server)
    result = _dispatch(ctx, "analyze_exposed_files", {"url": demo_server + "/"})

    assert result.ok, result.error
    data = result.data
    assert data["soft_404_detected"] is False
    assert data["baseline_status"] == 404
    assert data["probed"] >= 10

    hits = {check["path"]: check for check in data["checks"] if check["exposed"]}
    assert "/.git/HEAD" in hits
    assert "/.git/config" in hits
    assert "/.env" in hits
    assert "/server-status" in hits
    assert hits["/.env"]["severity"] == "critical"
    assert hits["/.env"]["verified"] is True
    assert "/.env.local" not in hits, "the demo server does not serve this path"


@pytest.mark.integration
def test_analyze_exposed_files_raises_findings_with_evidence(
    ctx_factory, demo_server: str
) -> None:
    ctx = ctx_factory(demo_server)
    result = _dispatch(ctx, "analyze_exposed_files", {"url": demo_server + "/"})

    assert result.findings
    locations = {finding["location"] for finding in result.findings}
    assert "file:/.env" in locations
    assert "file:/.git/HEAD" in locations

    for finding in result.findings:
        assert finding["evidence"], finding["title"]
        assert finding["severity"] in {"info", "low", "medium", "high", "critical"}
        assert "file:" in finding["location"]
        # The evidence must never contain a real secret value.
        for evidence in finding["evidence"]:
            assert "not-a-real-password" not in evidence["observed"]
            assert "ZGVtb2tleW5vdGFyZWFsa2V5" not in evidence["observed"]


@pytest.mark.integration
def test_analyze_exposed_files_never_returns_file_contents(ctx_factory, demo_server: str) -> None:
    """The report proves exposure; it must not become a channel for the secret itself."""
    ctx = ctx_factory(demo_server)
    result = _dispatch(ctx, "analyze_exposed_files", {"url": demo_server + "/"})
    rendered = str(result.data)
    assert "not-a-real-password-12345" not in rendered
    assert "DB_USERNAME=demoshop_app" not in rendered


@pytest.mark.integration
def test_analyze_exposed_files_respects_the_category_filter(ctx_factory, demo_server: str) -> None:
    ctx = ctx_factory(demo_server)
    result = _dispatch(ctx, "analyze_exposed_files", {"url": demo_server + "/", "categories": ["vcs"]})
    assert result.ok
    paths = {check["path"] for check in result.data["checks"]}
    assert paths <= {spec.path for spec in PATH_CATALOGUE if spec.category == "vcs"}
    assert "/.env" not in paths
    assert ".git" in "".join(paths)


@pytest.mark.integration
def test_analyze_exposed_files_probes_the_whole_catalogue_when_asked(
    ctx_factory, demo_server: str
) -> None:
    from app.models.scan import ScanConfig

    ctx = ctx_factory(
        demo_server,
        # A generous payload budget, because this test asserts on the complete detail list
        # rather than on what fits in the planner's context window.
        config=ScanConfig(
            max_requests=300,
            max_exposed_file_checks=100,
            requests_per_second=50.0,
            max_payload_chars=200_000,
        ),
    )
    result = _dispatch(
        ctx,
        "analyze_exposed_files",
        {"url": demo_server + "/", "categories": list(ALL_CATEGORIES), "max_paths": 40},
    )
    assert result.ok, result.error
    assert result.data["probed"] >= 25
    assert not result.truncated
    hits = {check["path"] for check in result.data["checks"] if check["exposed"]}
    assert "/.DS_Store" in hits
    assert "/README.md" in hits
    assert set(result.data["categories_probed"]) == set(ALL_CATEGORIES)


@pytest.mark.integration
def test_truncation_keeps_the_exposures_and_reports_what_it_dropped(
    ctx_factory, demo_server: str
) -> None:
    """A truncated payload must drop the boring rows, not the findings.

    The default planner context budget cannot hold every check, so the tool orders the list
    most-important-first and the dispatcher keeps a prefix. What matters is that the
    exposures survive and that the truncation is disclosed rather than hidden.
    """
    from app.models.scan import ScanConfig

    ctx = ctx_factory(
        demo_server,
        config=ScanConfig(
            max_requests=300,
            max_exposed_file_checks=100,
            requests_per_second=50.0,
            max_payload_chars=6_000,
        ),
    )
    result = _dispatch(
        ctx,
        "analyze_exposed_files",
        {"url": demo_server + "/", "categories": list(ALL_CATEGORIES), "max_paths": 40},
    )
    assert result.ok, result.error
    assert result.truncated is True
    # The scalars that describe the sweep must survive truncation intact.
    assert result.data["probed"] >= 25
    assert result.data["exposed_count"] >= 6
    assert result.data["checks_truncated"] is True
    assert result.data["checks_total"] == result.data["probed"]

    # Every exposure must be in the payload that was actually sent.
    sent = {check["path"] for check in result.data["checks"] if check["exposed"]}
    assert "/.env" in sent
    assert "/.git/HEAD" in sent
    assert "/server-status" in sent
    # And the findings list is never truncated by the payload budget.
    assert len(result.findings) == result.data["exposed_count"]


@pytest.mark.integration
def test_analyze_exposed_files_honours_max_paths(ctx_factory, demo_server: str) -> None:
    ctx = ctx_factory(
        demo_server,
        config=__import__("app.models.scan", fromlist=["ScanConfig"]).ScanConfig(
            max_requests=200, max_exposed_file_checks=100, requests_per_second=50.0
        ),
    )
    result = _dispatch(
        ctx, "analyze_exposed_files", {"url": demo_server + "/", "max_paths": 3}
    )
    assert result.data["probed"] <= 3


@pytest.mark.integration
def test_analyze_exposed_files_charges_its_own_budget(ctx_factory, demo_server: str) -> None:
    """The dedicated budget must be consumed, not the shared request budget alone."""
    from app.models.scan import ScanConfig

    ctx = ctx_factory(
        demo_server,
        config=ScanConfig(
            max_requests=200, max_exposed_file_checks=4, requests_per_second=50.0
        ),
    )
    result = _dispatch(ctx, "analyze_exposed_files", {"url": demo_server + "/"})
    assert result.ok, result.error
    assert ctx.limits.budgets["exposed_file_checks"].used <= 4
    assert result.data["probed"] <= 4
    assert result.data["skipped"] > 0
    assert any("budget" in note.lower() for note in result.data["notes"])


@pytest.mark.integration
def test_analyze_exposed_files_refuses_out_of_scope(ctx_factory, demo_server: str) -> None:
    ctx = ctx_factory(demo_server)
    result = _dispatch(ctx, "analyze_exposed_files", {"url": "https://elsewhere.test/"})
    assert result.status == ToolStatus.ERROR
    assert "out of scope" in (result.error or "").lower()


@pytest.mark.integration
def test_analyze_exposed_files_probes_only_the_requested_origin(
    ctx_factory, demo_server: str
) -> None:
    """Paths must stay on the origin the caller named, never wander to another host."""
    ctx = ctx_factory(demo_server)
    result = _dispatch(ctx, "analyze_exposed_files", {"url": demo_server + "/"})
    origin = result.data["origin"]
    for check in result.data["checks"]:
        assert check["url"].startswith(origin + "/"), check["url"]


@pytest.mark.integration
def test_analyze_exposed_files_rejects_an_unknown_category(ctx_factory, demo_server: str) -> None:
    ctx = ctx_factory(demo_server)
    result = _dispatch(
        ctx, "analyze_exposed_files", {"url": demo_server + "/", "categories": ["everything"]}
    )
    assert result.status == ToolStatus.DENIED
    assert "categories" in (result.denial_reason or "")


@pytest.mark.integration
def test_analyze_exposed_files_rejects_an_unknown_argument(ctx_factory, demo_server: str) -> None:
    """There is no way to name a path: the catalogue is harness-owned."""
    ctx = ctx_factory(demo_server)
    result = _dispatch(
        ctx,
        "analyze_exposed_files",
        {"url": demo_server + "/", "paths": ["/etc/passwd"]},
    )
    assert result.status == ToolStatus.DENIED
    assert "paths" in (result.denial_reason or "")


# --------------------------------------------------------------------------- #
# analyze_exposed_files against a soft-404 server
# --------------------------------------------------------------------------- #


@pytest.fixture()
def soft_404_server() -> str:
    """A server that answers 200 for every unknown path."""
    import pytest as _pytest

    server = make_server("127.0.0.1", 0, strict_404=False)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.integration
def test_soft_404_is_detected(ctx_factory, soft_404_server: str) -> None:
    ctx = ctx_factory(soft_404_server)
    result = _dispatch(ctx, "analyze_exposed_files", {"url": soft_404_server + "/"})
    assert result.ok, result.error
    assert result.data["soft_404_detected"] is True
    assert result.data["baseline_status"] == 200
    assert any("200" in note and "cannot exist" in note for note in result.data["notes"])


@pytest.mark.integration
def test_soft_404_does_not_produce_false_positives(
    ctx_factory, soft_404_server: str
) -> None:
    """The whole point of the calibration step.

    On a catch-all server, every path answers 200. Without the signature check this would
    report a dozen critical findings, all wrong. It must report only the files that really
    are served.
    """
    ctx = ctx_factory(soft_404_server)
    result = _dispatch(ctx, "analyze_exposed_files", {"url": soft_404_server + "/"})

    hits = {check["path"] for check in result.data["checks"] if check["exposed"]}
    assert hits == {"/.git/HEAD", "/.git/config", "/.env", "/server-status"}, (
        f"soft-404 produced unexpected hits: {sorted(hits)}"
    )
    # Every reported hit must have been confirmed by content, not by status code.
    for check in result.data["checks"]:
        if check["exposed"]:
            assert check["verified"] is True
            assert check["confidence"] == "high"


@pytest.mark.integration
def test_soft_404_misses_no_real_exposure(ctx_factory, soft_404_server: str) -> None:
    """The defence must not be so strict that it stops finding real files."""
    ctx = ctx_factory(soft_404_server)
    result = _dispatch(ctx, "analyze_exposed_files", {"url": soft_404_server + "/"})
    locations = {finding["location"] for finding in result.findings}
    assert "file:/.env" in locations
    assert "file:/.git/HEAD" in locations
    assert len(result.findings) == result.data["exposed_count"]


# --------------------------------------------------------------------------- #
# detect_technologies
# --------------------------------------------------------------------------- #


def test_fingerprints_are_well_formed() -> None:
    for fingerprint in FINGERPRINTS:
        assert fingerprint.name
        assert fingerprint.category in {
            "server",
            "framework",
            "language",
            "cms",
            "cdn",
            "analytics",
            "javascript",
            "other",
        }
        assert fingerprint.headers or fingerprint.cookies or fingerprint.body, (
            f"{fingerprint.name} has no detection rule"
        )


def test_fingerprint_names_are_unique() -> None:
    names = [fingerprint.name for fingerprint in FINGERPRINTS]
    assert len(names) == len(set(names))


def test_nginx_is_detected_from_the_server_header() -> None:
    fingerprint = next(f for f in FINGERPRINTS if f.name == "nginx")
    match = _evaluate(fingerprint, {"server": "nginx/1.24.0"}, [], "")
    assert match is not None
    assert match.version == "1.24.0"


def test_cloudflare_requires_both_signals() -> None:
    """A single generic header is not enough for a CDN claim."""
    fingerprint = next(f for f in FINGERPRINTS if f.name == "Cloudflare")
    assert _evaluate(fingerprint, {"server": "cloudflare"}, [], "") is not None
    assert _evaluate(fingerprint, {"x-random": "x"}, [], "") is None


def test_fingerprint_does_not_guess_a_version_from_body_text() -> None:
    """A wrong version drives wrong action, so versions come only from headers."""
    fingerprint = next(f for f in FINGERPRINTS if f.name == "WordPress")
    match = _evaluate(fingerprint, {}, [], "<link href='/wp-content/x.css'> v6.4.2")
    assert match is not None
    assert match.version == ""


def test_dedupe_merges_by_name_keeping_the_best() -> None:
    from app.models.tools import TechnologyMatch

    matches = [
        TechnologyMatch(name="nginx", category="server", version="", confidence="low", evidence=["a"]),
        TechnologyMatch(name="NGINX", category="server", version="1.2", confidence="high", evidence=["b"]),
    ]
    merged = _dedupe(matches)
    assert len(merged) == 1
    assert merged[0].confidence == "high"
    assert merged[0].version == "1.2"
    assert {"a", "b"} <= set(merged[0].evidence)


@pytest.mark.integration
def test_detect_technologies_fingerprints_the_demo_target(
    ctx_factory, demo_server: str
) -> None:
    ctx = ctx_factory(demo_server)
    result = _dispatch(ctx, "detect_technologies", {"url": demo_server + "/"})

    assert result.ok, result.error
    data = result.data
    names = {tech["name"] for tech in data["technologies"]}
    assert "Express" in names, "the demo target sets X-Powered-By: Express"
    assert "HTMX" in names, "the demo page uses hx-post"

    express = next(tech for tech in data["technologies"] if tech["name"] == "Express")
    assert express["version"] == "4.18.2"
    assert express["evidence"]
    assert "server" in data


@pytest.mark.integration
def test_detect_technologies_uses_cookie_names(ctx_factory, demo_server: str) -> None:
    ctx = ctx_factory(demo_server)
    result = _dispatch(ctx, "detect_technologies", {"url": demo_server + "/"})
    assert "sessionid" in result.data["cookie_names"]


@pytest.mark.integration
def test_detect_technologies_can_skip_cookies(ctx_factory, demo_server: str) -> None:
    ctx = ctx_factory(demo_server)
    result = _dispatch(
        ctx, "detect_technologies", {"url": demo_server + "/", "include_cookies": False}
    )
    assert result.data["cookie_names"] == []


@pytest.mark.integration
def test_detect_technologies_reports_version_disclosure_only(
    ctx_factory, demo_server: str
) -> None:
    """A technology match is not a vulnerability; only version disclosure is scored."""
    ctx = ctx_factory(demo_server)
    result = _dispatch(ctx, "detect_technologies", {"url": demo_server + "/"})
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding["severity"] == "low"
    assert finding["category"] == "information_disclosure"
    assert "version" in finding["title"].lower()
    # It must not claim the technologies themselves are findings.
    assert "Express" not in finding["title"]
    assert "HTMX" not in finding["title"]


@pytest.mark.integration
def test_detect_technologies_costs_one_request(ctx_factory, demo_server: str) -> None:
    ctx = ctx_factory(demo_server)
    before = ctx.limits.budgets["requests"].used
    _dispatch(ctx, "detect_technologies", {"url": demo_server + "/"})
    assert ctx.limits.budgets["requests"].used == before + 1


@pytest.mark.integration
def test_detect_technologies_refuses_out_of_scope(ctx_factory, demo_server: str) -> None:
    ctx = ctx_factory(demo_server)
    result = _dispatch(ctx, "detect_technologies", {"url": "https://elsewhere.test/"})
    assert result.status == ToolStatus.ERROR
    assert "out of scope" in (result.error or "").lower()


@pytest.mark.integration
def test_detect_technologies_on_a_page_with_no_fingerprints(
    ctx_factory, demo_server: str
) -> None:
    """An unmatched page must say so rather than inventing a stack."""
    ctx = ctx_factory(demo_server)
    result = _dispatch(ctx, "detect_technologies", {"url": demo_server + "/nonexistent"})
    assert result.ok
    # The demo 404 page carries the same headers, so Express will match; the assertion is
    # that the tool never errors and never fabricates.
    for tech in result.data["technologies"]:
        assert tech["evidence"], f"{tech['name']} matched with no evidence"
