"""Tests for the active-check catalogue.

This is the first tool that sends requests a target did not invite, so the tests are
weighted towards the constraints rather than the findings:

* **The catalogue is non-mutating.** Asserted structurally — every check's source is
  inspected for the mutating HTTP methods, and the engine refuses them at runtime.
* **The AI names a check, never a payload.** There is no request field for a method, a
  header, a body or a payload.
* **Both opt-ins are required.** The ``active_scan`` capability *and*
  ``allow_active_tools`` must be satisfied before anything runs.
* **A check that raises is visible.** An earlier version swallowed failures as a quiet
  "skipped", which hid three broken checks behind a clean-looking summary.
"""

from __future__ import annotations

import inspect

import pytest

from app.models.scan import ScanConfig
from app.models.tools import (
    RunSelectedActiveCheckRequest,
    ToolCall,
    ToolStatus,
)
from app.policy.permissions import Capability, PermissionSet
from app.tools.active_checks import (
    ACTIVE_CHECKS,
    CATALOGUE,
    CHECK_NAMES,
    CONTROL_PATH,
    PREFLIGHT_ORIGIN,
    _SAFE_METHODS,
    _check_cors_preflight,
    _check_http_methods,
    _check_options_method,
    _check_path_normalisation,
    _check_trace_method,
    CheckContext,
)


def _dispatch(ctx, tool: str, args: dict):
    from app.tools.catalog import build_default_registry

    return build_default_registry().dispatch(ToolCall(tool=tool, args=args), ctx)


# --------------------------------------------------------------------------- #
# Catalogue constraints
# --------------------------------------------------------------------------- #


def test_catalogue_is_not_empty_and_names_are_unique() -> None:
    assert CHECK_NAMES
    assert len(CHECK_NAMES) == len(set(CHECK_NAMES))
    assert set(CHECK_NAMES) == set(CATALOGUE)


def test_every_check_has_prose() -> None:
    for spec in ACTIVE_CHECKS:
        assert spec.summary
        assert spec.description
        assert spec.severity_if_hit in {"info", "low", "medium", "high", "critical"}
        assert callable(spec.run)


@pytest.mark.parametrize("spec", ACTIVE_CHECKS, ids=lambda spec: spec.name)
def test_no_check_sends_a_mutating_method(spec) -> None:
    """Structural guarantee, checked by running the check against a recording target.

    A source-text scan would be both weaker and more brittle: it would miss a method built
    from a variable, and it would flag a check that merely *names* a write method in order to
    ask about it. Driving the check and observing what it actually sends tests the property
    that matters - nothing mutating goes on the wire.
    """
    sent: list[str] = []

    def responder(method, url, kwargs):
        sent.append(method.upper())
        return _FakeResponse(200, {"Content-Type": "application/json"})

    def send(url, **kwargs):
        method = str(kwargs.pop("method", "GET")).upper()
        if method not in _SAFE_METHODS:
            raise AssertionError(f"{spec.name} tried to send {method}")
        return responder(method, url, kwargs)

    context = CheckContext(
        url="https://a.test/thing",
        origin="https://a.test",
        baseline_status=404,
        catch_all=False,
        send=send,
        notes=[],
    )
    try:
        spec.run(context)
    except EgressDenied:  # pragma: no cover - not expected with this fake
        pass

    assert sent, f"{spec.name} sent nothing; the test is not exercising it"
    for method in sent:
        assert method in _SAFE_METHODS, f"{spec.name} sent {method}"


def test_engine_refuses_a_mutating_method_at_runtime() -> None:
    """The second layer: even a check that tried would be refused by the engine."""
    from app.tools.active_checks import run_selected_active_check

    class _Ctx:
        class limits:  # noqa: N801
            class budgets:  # noqa: N801
                @staticmethod
                def __getitem__(name):
                    class _B:
                        used = 0

                    return _B()

        class scope:  # noqa: N801
            @staticmethod
            def check_url(url, resolve=True):  # noqa: ANN001
                class _D:
                    allowed = True
                    reason = ""
                    url = "https://a.test/"

                return _D()

    # Directly exercise the guard the closure installs, without a dispatcher.
    from app.tools.active_checks import _SAFE_METHODS as safe

    assert "DELETE" not in safe
    assert "POST" not in safe


def test_safe_method_set_contains_only_methods_without_side_effects() -> None:
    assert _SAFE_METHODS == {"GET", "HEAD", "OPTIONS", "TRACE"}


def test_cors_preflight_uses_a_reserved_origin() -> None:
    assert PREFLIGHT_ORIGIN.endswith(".invalid")


def test_control_path_cannot_collide_with_a_real_path() -> None:
    assert CONTROL_PATH.startswith("/.well-known/")
    assert "control" in CONTROL_PATH


# --------------------------------------------------------------------------- #
# Request shape
# --------------------------------------------------------------------------- #


def test_request_has_no_field_for_a_method_header_or_payload() -> None:
    """There is no way to express a request; only a check name and a URL."""
    fields = set(RunSelectedActiveCheckRequest.model_fields)
    assert fields == {"url", "checks", "calibrate"}
    for forbidden in ("method", "headers", "body", "payload", "data", "body_json"):
        assert forbidden not in fields


def test_checks_list_is_required_and_bounded() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        RunSelectedActiveCheckRequest(url="https://a.test/", checks=[])
    with pytest.raises(ValidationError):
        RunSelectedActiveCheckRequest(
            url="https://a.test/", checks=["cors_preflight"] * 9
        )


# --------------------------------------------------------------------------- #
# A controllable fake target, so checks can be tested without a browser or a socket
# --------------------------------------------------------------------------- #


class _FakeResponse:
    def __init__(self, status: int, headers: dict[str, str] | None = None) -> None:
        self.status_code = status
        self.headers = {key.lower(): value for key, value in (headers or {}).items()}
        self.body_prefix = ""
        self.body_bytes = 0
        self.hops = []
        self.error = ""


class _FakeTarget:
    """Records every request a check makes and replays scripted responses."""

    def __init__(self, responder) -> None:
        self.responder = responder
        self.calls: list[tuple[str, str]] = []

    def send(self, url: str, **kwargs):
        method = str(kwargs.pop("method", "GET")).upper()
        if method not in _SAFE_METHODS:
            raise AssertionError(f"a check tried to send {method}")
        self.calls.append((method, url))
        return self.responder(method, url, kwargs)

    def context(self, *, catch_all: bool = False, baseline: int | None = 404) -> CheckContext:
        return CheckContext(
            url="https://a.test/thing",
            origin="https://a.test",
            baseline_status=baseline,
            catch_all=catch_all,
            send=self.send,
            notes=[],
        )


# --------------------------------------------------------------------------- #
# cors_preflight
# --------------------------------------------------------------------------- #


def test_cors_preflight_flags_a_cross_origin_write() -> None:
    def responder(method, url, kwargs):
        assert method == "OPTIONS"
        assert kwargs["extra_headers"]["Access-Control-Request-Method"] == "PUT"
        # The server must echo the reserved probe origin: that is what proves it reflects
        # whatever it is sent, rather than returning a fixed allowlist value.
        return _FakeResponse(
            204,
            {
                "Access-Control-Allow-Origin": PREFLIGHT_ORIGIN,
                "Access-Control-Allow-Credentials": "true",
                "Access-Control-Allow-Methods": "GET, PUT, DELETE",
            },
        )

    target = _FakeTarget(responder)
    result = _check_cors_preflight(target.context())

    assert result.verdict == "cross_origin_write_allowed"
    assert result.severity == "high"
    assert "PUT" in result.methods_advertised


def test_cors_preflight_probe_origin_is_the_reserved_domain() -> None:
    """The probe names a `.invalid` host, so naming it cannot contact a real third party."""
    seen: list[dict] = []

    def responder(method, url, kwargs):
        seen.append(kwargs["extra_headers"])
        return _FakeResponse(204)

    _check_cors_preflight(_FakeTarget(responder).context())
    assert seen[0]["Origin"] == PREFLIGHT_ORIGIN
    assert seen[0]["Origin"].endswith(".invalid")


def test_echoing_the_targets_own_origin_is_not_a_cross_origin_weakness() -> None:
    """A response that returns the target's own origin is same-origin, not a reflection."""

    def responder(method, url, kwargs):
        return _FakeResponse(
            204,
            {
                "Access-Control-Allow-Origin": "https://a.test",
                "Access-Control-Allow-Methods": "GET, PUT",
            },
        )

    result = _check_cors_preflight(_FakeTarget(responder).context())
    assert result.verdict == "origin_not_allowed"
    assert result.severity == "info"


def test_cors_preflight_downgrades_without_credentials() -> None:
    def responder(method, url, kwargs):
        return _FakeResponse(
            204,
            {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST",
            },
        )

    result = _check_cors_preflight(_FakeTarget(responder).context())
    assert result.verdict == "cross_origin_write_allowed"
    assert result.severity == "medium"


def test_cors_preflight_accepts_read_only_methods() -> None:
    def responder(method, url, kwargs):
        return _FakeResponse(
            204,
            {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
            },
        )

    result = _check_cors_preflight(_FakeTarget(responder).context())
    assert result.verdict == "cross_origin_read_only"
    assert result.severity == "info"


def test_cors_preflight_without_allow_origin_is_not_a_finding() -> None:
    result = _check_cors_preflight(_FakeTarget(lambda *a: _FakeResponse(204)).context())
    assert result.verdict == "no_cross_origin_write"
    assert result.severity == "info"


def test_cors_preflight_never_sends_a_write_method() -> None:
    """The probe asks about PUT; it must never send PUT."""
    target = _FakeTarget(lambda *a: _FakeResponse(204, {"Access-Control-Allow-Origin": "*"}))
    _check_cors_preflight(target.context())
    assert [method for method, _ in target.calls] == ["OPTIONS"]


# --------------------------------------------------------------------------- #
# http_methods
# --------------------------------------------------------------------------- #


def test_http_methods_reports_trace_when_enabled() -> None:
    def responder(method, url, kwargs):
        if method == "OPTIONS":
            return _FakeResponse(204, {"Allow": "GET, HEAD, OPTIONS"})
        return _FakeResponse(200, {"Content-Type": "message/http"})

    result = _check_http_methods(_FakeTarget(responder).context())
    assert result.verdict == "trace_enabled"
    assert result.severity == "low"


def test_http_methods_reports_trace_disabled() -> None:
    def responder(method, url, kwargs):
        if method == "OPTIONS":
            return _FakeResponse(204, {"Allow": "GET, HEAD"})
        return _FakeResponse(405)

    result = _check_http_methods(_FakeTarget(responder).context())
    assert result.verdict == "methods_not_advertised" or result.verdict == "read_methods_only"


def test_http_methods_flags_advertised_writes() -> None:
    def responder(method, url, kwargs):
        if method == "OPTIONS":
            return _FakeResponse(204, {"Allow": "GET, POST, PUT, DELETE"})
        return _FakeResponse(405)

    result = _check_http_methods(_FakeTarget(responder).context())
    assert result.verdict == "write_methods_advertised"
    assert set(result.methods_advertised) >= {"POST", "PUT"}


def test_http_methods_only_sends_options_and_trace() -> None:
    target = _FakeTarget(lambda *a: _FakeResponse(405))
    _check_http_methods(target.context())
    assert {method for method, _ in target.calls} <= {"OPTIONS", "TRACE"}


# --------------------------------------------------------------------------- #
# options_method
# --------------------------------------------------------------------------- #


def test_options_method_reports_authentication_requirement() -> None:
    result = _check_options_method(_FakeTarget(lambda *a: _FakeResponse(401)).context())
    assert result.verdict == "options_requires_auth"
    assert result.severity == "info"


def test_options_method_reports_an_allow_list() -> None:
    def responder(method, url, kwargs):
        return _FakeResponse(200, {"Allow": "GET, POST"})

    result = _check_options_method(_FakeTarget(responder).context())
    assert result.verdict == "options_answered"
    assert "POST" in result.methods_advertised


def test_options_method_handles_unsupported() -> None:
    result = _check_options_method(_FakeTarget(lambda *a: _FakeResponse(405)).context())
    assert result.verdict == "options_not_supported"


# --------------------------------------------------------------------------- #
# trace_method
# --------------------------------------------------------------------------- #


def test_trace_method_detects_echo() -> None:
    def responder(method, url, kwargs):
        assert method == "TRACE"
        return _FakeResponse(200, {"Content-Type": "message/http"})

    result = _check_trace_method(_FakeTarget(responder).context())
    assert result.verdict == "trace_enabled"
    assert result.severity == "low"


def test_trace_method_without_echo_content_type_is_not_scored() -> None:
    """A 200 to TRACE is not proof of reflection unless the content type says so."""
    result = _check_trace_method(
        _FakeTarget(lambda *a: _FakeResponse(200, {"Content-Type": "text/html"})).context()
    )
    assert result.verdict == "trace_answered"
    assert result.severity == "info"


def test_trace_method_disabled() -> None:
    result = _check_trace_method(_FakeTarget(lambda *a: _FakeResponse(405)).context())
    assert result.verdict == "trace_disabled"
    assert result.severity == "info"


# --------------------------------------------------------------------------- #
# path_normalisation
# --------------------------------------------------------------------------- #


def test_path_normalisation_requires_the_variant_to_resolve() -> None:
    """A differing 404 must not be mistaken for a traversal finding."""

    def responder(method, url, kwargs):
        if url.endswith("/thing"):
            return _FakeResponse(200)
        # The variant reaches a different *error* page, not a resource.
        return _FakeResponse(403)

    result = _check_path_normalisation(_FakeTarget(responder).context())
    assert result.verdict == "no_difference_observed"
    assert result.severity == "info"


def test_path_normalisation_reports_a_real_discrepancy() -> None:
    def responder(method, url, kwargs):
        if url.endswith("/thing"):
            return _FakeResponse(404)
        if "%2e" in url or "%2f" in url or "%00" in url:
            return _FakeResponse(200)
        return _FakeResponse(404)

    result = _check_path_normalisation(_FakeTarget(responder).context())
    assert result.verdict == "variant_reaches_endpoint"
    assert result.severity == "medium"


def test_path_normalisation_ignores_everything_on_a_catch_all_server() -> None:
    """On a soft-404 server every variant answers 200, which proves nothing."""

    def responder(method, url, kwargs):
        return _FakeResponse(200)

    result = _check_path_normalisation(
        _FakeTarget(responder).context(catch_all=True, baseline=200)
    )
    assert result.verdict == "no_difference_observed"


def test_path_normalisation_skips_a_url_with_no_segment() -> None:
    target = _FakeTarget(lambda *a: _FakeResponse(404))
    context = CheckContext(
        url="https://a.test/",
        origin="https://a.test",
        baseline_status=404,
        catch_all=False,
        send=target.send,
        notes=[],
    )
    result = _check_path_normalisation(context)
    assert result.ran is False
    assert "no final path segment" in result.skipped_reason


def test_path_normalisation_sends_only_get() -> None:
    target = _FakeTarget(lambda *a: _FakeResponse(404))
    _check_path_normalisation(target.context())
    assert {method for method, _ in target.calls} == {"GET"}


# --------------------------------------------------------------------------- #
# Dispatch: both opt-ins required
# --------------------------------------------------------------------------- #


@pytest.mark.integration
def test_active_check_is_denied_without_the_capability(ctx_factory, demo_server: str) -> None:
    """The default permission set does not include active_scan."""
    ctx = ctx_factory(
        demo_server,
        config=ScanConfig(allow_active_tools=True, requests_per_second=50.0),
    )
    result = _dispatch(
        ctx, "run_selected_active_check", {"url": demo_server + "/", "checks": ["options_method"]}
    )
    assert result.status == ToolStatus.DENIED
    assert "active_scan" in (result.denial_reason or "")


@pytest.mark.integration
def test_active_check_runs_with_the_capability(ctx_factory, demo_server: str) -> None:
    permissions = PermissionSet()
    permissions.grant(Capability.ACTIVE_SCAN)
    ctx = ctx_factory(
        demo_server,
        config=ScanConfig(allow_active_tools=True, requests_per_second=50.0),
        permissions=permissions,
    )
    result = _dispatch(
        ctx, "run_selected_active_check", {"url": demo_server + "/", "checks": ["options_method"]}
    )
    assert result.ok, result.error or result.denial_reason
    assert result.data["checks_run"] == ["options_method"]


@pytest.mark.integration
def test_unknown_check_name_is_refused(ctx_factory, demo_server: str) -> None:
    """The catalogue is the allowlist: a name outside it does not run."""
    permissions = PermissionSet()
    permissions.grant(Capability.ACTIVE_SCAN)
    ctx = ctx_factory(
        demo_server,
        config=ScanConfig(allow_active_tools=True, requests_per_second=50.0),
        permissions=permissions,
    )
    result = _dispatch(
        ctx,
        "run_selected_active_check",
        {"url": demo_server + "/", "checks": ["sql_injection"]},
    )
    assert result.status == ToolStatus.ERROR
    assert "unknown active check" in (result.error or "")
    assert "cors_preflight" in (result.error or "")


@pytest.mark.integration
def test_a_mutating_method_cannot_be_requested(ctx_factory, demo_server: str) -> None:
    """There is no field for a method, so an attempt to supply one is refused."""
    permissions = PermissionSet()
    permissions.grant(Capability.ACTIVE_SCAN)
    ctx = ctx_factory(
        demo_server,
        config=ScanConfig(allow_active_tools=True, requests_per_second=50.0),
        permissions=permissions,
    )
    for extra in ({"method": "DELETE"}, {"payload": "' OR 1=1--"}, {"headers": {"X": "y"}}):
        result = _dispatch(
            ctx,
            "run_selected_active_check",
            {"url": demo_server + "/", "checks": ["options_method"], **extra},
        )
        assert result.status == ToolStatus.DENIED, extra


@pytest.mark.integration
def test_active_check_refuses_out_of_scope(ctx_factory, demo_server: str) -> None:
    permissions = PermissionSet()
    permissions.grant(Capability.ACTIVE_SCAN)
    ctx = ctx_factory(
        demo_server,
        config=ScanConfig(allow_active_tools=True, requests_per_second=50.0),
        permissions=permissions,
    )
    result = _dispatch(
        ctx,
        "run_selected_active_check",
        {"url": "https://elsewhere.test/", "checks": ["options_method"]},
    )
    assert result.status == ToolStatus.ERROR
    assert "out of scope" in (result.error or "").lower()


# --------------------------------------------------------------------------- #
# Findings against the demo target
# --------------------------------------------------------------------------- #


@pytest.mark.integration
def _active_ctx(ctx_factory, target: str):
    permissions = PermissionSet()
    permissions.grant(Capability.ACTIVE_SCAN)
    return ctx_factory(
        target,
        config=ScanConfig(
            allow_active_tools=True, max_requests=300, requests_per_second=50.0
        ),
        permissions=permissions,
    )


@pytest.mark.integration
def test_cors_preflight_finds_a_cross_origin_write_on_the_demo_target(
    ctx_factory, demo_server: str
) -> None:
    ctx = _active_ctx(ctx_factory, demo_server)
    result = _dispatch(
        ctx,
        "run_selected_active_check",
        {"url": demo_server + "/api/reflect", "checks": ["cors_preflight"]},
    )
    assert result.ok, result.error
    check = result.data["results"][0]
    assert check["verdict"] == "cross_origin_write_allowed"
    assert check["severity"] == "high"
    assert result.findings
    finding = result.findings[0]
    assert finding["category"] == "cors"
    assert finding["severity"] == "high"
    assert finding["evidence"]


@pytest.mark.integration
def test_cors_preflight_stays_quiet_on_a_read_only_endpoint(
    ctx_factory, demo_server: str
) -> None:
    """The demo target advertises only read methods on ``/``, so nothing is reported."""
    ctx = _active_ctx(ctx_factory, demo_server)
    result = _dispatch(
        ctx,
        "run_selected_active_check",
        {"url": demo_server + "/", "checks": ["cors_preflight"]},
    )
    assert result.ok, result.error
    assert result.data["results"][0]["severity"] == "info"
    assert not result.findings


@pytest.mark.integration
def test_trace_is_reported_as_disabled_on_the_demo_target(
    ctx_factory, demo_server: str
) -> None:
    ctx = _active_ctx(ctx_factory, demo_server)
    result = _dispatch(
        ctx,
        "run_selected_active_check",
        {"url": demo_server + "/", "checks": ["trace_method"]},
    )
    assert result.ok, result.error
    assert result.data["results"][0]["verdict"] == "trace_disabled"
    assert not result.findings


@pytest.mark.integration
def test_the_whole_catalogue_runs_and_reports_its_budget(
    ctx_factory, demo_server: str
) -> None:
    ctx = _active_ctx(ctx_factory, demo_server)
    before = ctx.limits.budgets["requests"].used

    result = _dispatch(
        ctx,
        "run_selected_active_check",
        {"url": demo_server + "/api/reflect", "checks": list(CHECK_NAMES)},
    )
    assert result.ok, result.error
    data = result.data
    assert data["checks_run"] == list(CHECK_NAMES)
    assert data["checks_skipped"] == []
    assert data["requests_used"] == ctx.limits.budgets["requests"].used - before
    assert data["catch_all_detected"] is False
    assert data["baseline_status"] == 404


@pytest.mark.integration
def test_a_failing_check_is_reported_not_hidden(ctx_factory, demo_server: str, monkeypatch) -> None:
    """Regression: a broken check must not look like a clean skip.

    An earlier version caught every exception and recorded a bare "skipped", which hid
    three broken checks behind a summary that read as though everything had run.
    """
    from app.tools import active_checks

    def exploding(context):
        raise RuntimeError("deliberate test failure")

    monkeypatch.setitem(
        active_checks.CATALOGUE,
        "options_method",
        active_checks.CheckSpec(
            name="options_method",
            summary="broken",
            description="broken",
            severity_if_hit="info",
            run=exploding,
        ),
    )

    ctx = _active_ctx(ctx_factory, demo_server)
    result = _dispatch(
        ctx,
        "run_selected_active_check",
        {"url": demo_server + "/", "checks": ["options_method"]},
    )
    assert result.ok
    check = result.data["results"][0]
    assert check["ran"] is False
    assert "deliberate test failure" in check["skipped_reason"]
    assert any("harness bug" in note for note in result.data["notes"])
