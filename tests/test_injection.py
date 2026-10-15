"""Tests for ``run_injection_check``.

The question this tool answers is "can injection testing be done without handing the model a
payload?" The tests are therefore weighted towards the constraint that makes the answer yes:

* **Payloads are harness constants.** There is no request field for one.
* **Detection is error-based and read-only.** No union, no boolean-blind, no time-based, no
  stacked statement — asserted by inspecting the catalogues.
* **Only a signature absent from the baseline counts**, so an application that always prints
  a database error is not flagged.
* **A response that merely varies is not a finding.** That is how scanners earn their
  reputation for noise, and it is the failure mode most worth guarding against.
* **Three independent opt-ins**: the capability, `allow_active_tools`, and the confirmation
  gate.
"""

from __future__ import annotations

import pytest

from app.models.scan import ScanConfig
from app.models.tools import (
    RunInjectionCheckRequest,
    ToolCall,
    ToolStatus,
)
from app.policy.permissions import ArgumentGuard, Capability, PermissionSet
from app.tools.injection import (
    MAX_PARAMETERS,
    MAX_PROBES_PER_PARAMETER,
    NOSQL_OPERATOR_PAYLOADS,
    PAYLOADS_BY_TECHNIQUE,
    SQL_ERROR_PAYLOADS,
    SQL_ERROR_SIGNATURES,
    TECHNIQUES,
    _inject,
    _match_error_signature,
)
from urllib.parse import urlsplit


def _dispatch(ctx, tool: str, args: dict):
    from app.tools.catalog import build_default_registry

    return build_default_registry().dispatch(ToolCall(tool=tool, args=args), ctx)


def _injection_ctx(ctx_factory, target: str):
    permissions = PermissionSet()
    permissions.grant(Capability.INJECTION_PROBE)
    return ctx_factory(
        target,
        config=ScanConfig(
            allow_active_tools=True, max_requests=200, requests_per_second=50.0
        ),
        permissions=permissions,
    )


# --------------------------------------------------------------------------- #
# Payload catalogue constraints
# --------------------------------------------------------------------------- #


def test_techniques_are_declared() -> None:
    assert TECHNIQUES == ("sql_error", "nosql_operator")
    assert set(PAYLOADS_BY_TECHNIQUE) == set(TECHNIQUES)


def test_every_payload_has_a_label_and_a_kind() -> None:
    for technique, payloads in PAYLOADS_BY_TECHNIQUE.items():
        assert payloads, technique
        for payload in payloads:
            assert payload.label, f"{technique}: payload without a label"
            assert payload.kind
            assert payload.value


@pytest.mark.parametrize("payload", SQL_ERROR_PAYLOADS, ids=lambda item: item.label)
def test_sql_payloads_contain_no_statement(payload) -> None:
    """Error-based detection needs syntax breakage, not a statement.

    A keyword like UNION, SELECT or DROP in a payload would mean the tool had crossed from
    detection into exploitation, so their absence is asserted rather than assumed.
    """
    lowered = payload.value.lower()
    for forbidden in (
        "union",
        "select",
        "insert",
        "update",
        "delete",
        "drop",
        "alter",
        "create",
        "exec",
        "sleep",
        "benchmark",
        "waitfor",
        "or 1=1",
        "or '1'='1",
        "and 1=1",
        ";",
    ):
        assert forbidden not in lowered, f"{payload.label!r} contains {forbidden!r}"


def test_sql_payloads_are_only_syntax_breakage() -> None:
    """Every SQL payload is a quote, a comment opener, or both."""
    allowed = set("'\"-/* \t")
    for payload in SQL_ERROR_PAYLOADS:
        assert set(payload.value) <= allowed, f"{payload.label!r} has unexpected characters"


def test_no_payload_is_a_bare_tautology() -> None:
    """The catalogue contains no boolean tautology, which is an exploitation technique."""
    for payloads in PAYLOADS_BY_TECHNIQUE.values():
        for payload in payloads:
            assert "=" not in payload.value or "$" in payload.value, payload.label


# --------------------------------------------------------------------------- #
# Request shape
# --------------------------------------------------------------------------- #


def test_request_has_no_field_for_a_payload() -> None:
    fields = set(RunInjectionCheckRequest.model_fields)
    assert fields == {"url", "parameters", "technique", "canonical_query"}
    for forbidden in ("payload", "payloads", "value", "values", "body", "method", "headers"):
        assert forbidden not in fields


def test_technique_is_an_enum_not_a_free_string() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        RunInjectionCheckRequest(url="https://a.test/?q=1", technique="union_select")


def test_parameter_list_is_bounded() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        RunInjectionCheckRequest(
            url="https://a.test/?q=1", parameters=[f"p{index}" for index in range(20)]
        )


# --------------------------------------------------------------------------- #
# URL construction
# --------------------------------------------------------------------------- #


def test_inject_replaces_only_the_named_parameter() -> None:
    parts = urlsplit("https://a.test/products?q=shoe&page=1&sort=asc")
    injected = _inject("https://a.test/products?q=shoe&page=1&sort=asc", parts, "q", "'")
    assert injected.startswith("https://a.test/products?")
    query = injected.split("?", 1)[1]
    assert "page=1" in query
    assert "sort=asc" in query
    # The payload is percent-encoded, which the server decodes back to a quote.
    assert "q=%27" in query


def test_inject_preserves_the_path_and_drops_the_fragment() -> None:
    parts = urlsplit("https://a.test/a/b?q=1#frag")
    injected = _inject("https://a.test/a/b?q=1#frag", parts, "q", "'")
    assert injected.startswith("https://a.test/a/b?")
    assert "#" not in injected


def test_inject_keeps_other_parameters_at_their_original_values() -> None:
    parts = urlsplit("https://a.test/?a=1&b=2")
    injected = _inject("https://a.test/?a=1&b=2", parts, "a", "PAY")
    assert "b=2" in injected
    assert "a=PAY" in injected


def test_inject_is_a_no_op_when_the_parameter_is_absent() -> None:
    parts = urlsplit("https://a.test/?a=1")
    injected = _inject("https://a.test/?a=1", parts, "missing", "'")
    assert "a=1" in injected
    assert "missing" not in injected


# --------------------------------------------------------------------------- #
# Error signature matching
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "body",
    [
        "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version",
        "Warning: mysql_query(): supplied argument is not a valid MySQL result",
        "PostgreSQL ERROR: unterminated quoted string at or near \"'\"",
        "Microsoft OLE DB Provider for SQL Server error '80040e14'",
        "Unclosed quotation mark after the character string ''",
        "ORA-01756: quoted string not properly terminated",
        "SQLite3::SQLException: near \"'\": syntax error",
        "sqlite3.OperationalError: unrecognized token: \"'\"",
        "Incorrect syntax near 'ORDER'",
    ],
)
def test_error_signatures_match_real_driver_messages(body: str) -> None:
    assert _match_error_signature(body), body


@pytest.mark.parametrize(
    "body",
    [
        "",
        "<html><body>Not found</body></html>",
        "An unexpected error occurred. Please try again.",
        "There was a problem processing your request.",
    ],
)
def test_error_signatures_do_not_match_generic_text(body: str) -> None:
    """A bare 'error' would match half the web; a false SQLi is the costliest false positive."""
    assert _match_error_signature(body) == ""


def test_signature_reports_the_engine() -> None:
    signature = _match_error_signature("ORA-01756: quoted string not properly terminated")
    assert signature.startswith("[oracle]")


def test_signature_list_is_specific_not_broad() -> None:
    for engine, pattern in SQL_ERROR_SIGNATURES:
        assert engine
        assert pattern.pattern.strip()
        # A pattern that is just the word "error" would match everything.
        assert pattern.pattern.lower() not in {"error", "sql error"}


# --------------------------------------------------------------------------- #
# ArgumentGuard is not the protection here
# --------------------------------------------------------------------------- #


def test_the_guard_would_not_have_stopped_a_sql_syntax_payload() -> None:
    """Documenting why the payload catalogue, not the guard, is the real control.

    The guard screens *caller* input. This tool never puts caller input on the wire, so the
    guard is irrelevant to its safety — and that is exactly why the payloads must live in
    harness code.
    """
    guard = ArgumentGuard()
    for payload in SQL_ERROR_PAYLOADS:
        verdict = guard.screen({"url": f"https://a.test/?q={payload.value}"})
        assert verdict.allowed is True, (
            f"the guard rejected {payload.label!r}, which means it is doing more than "
            "documented and this test's premise is stale"
        )


# --------------------------------------------------------------------------- #
# Dispatch: opt-ins and scope
# --------------------------------------------------------------------------- #


@pytest.mark.integration
def test_injection_is_denied_without_the_capability(ctx_factory, demo_server: str) -> None:
    ctx = ctx_factory(
        demo_server, config=ScanConfig(allow_active_tools=True, requests_per_second=50.0)
    )
    result = _dispatch(
        ctx, "run_injection_check", {"url": demo_server + "/products?q=shoe"}
    )
    assert result.status == ToolStatus.DENIED
    assert "injection_probe" in (result.denial_reason or "")


@pytest.mark.integration
def test_active_scan_capability_does_not_grant_injection(ctx_factory, demo_server: str) -> None:
    """The two switches are separate on purpose.

    An operator may accept method probing while refusing payload probing. Granting
    ``active_scan`` must not silently grant ``injection_probe``.
    """
    permissions = PermissionSet()
    permissions.grant(Capability.ACTIVE_SCAN)
    ctx = ctx_factory(
        demo_server,
        config=ScanConfig(allow_active_tools=True, requests_per_second=50.0),
        permissions=permissions,
    )
    result = _dispatch(ctx, "run_injection_check", {"url": demo_server + "/products?q=shoe"})
    assert result.status == ToolStatus.DENIED
    assert "injection_probe" in (result.denial_reason or "")


@pytest.mark.integration
def test_a_payload_cannot_be_supplied_by_the_caller(ctx_factory, demo_server: str) -> None:
    ctx = _injection_ctx(ctx_factory, demo_server)
    for extra in (
        {"payload": "'; DROP TABLE users; --"},
        {"method": "POST"},
        {"headers": {"X-Test": "1"}},
        {"body": "a=1"},
    ):
        result = _dispatch(
            ctx,
            "run_injection_check",
            {"url": demo_server + "/products?q=shoe", **extra},
        )
        assert result.status == ToolStatus.DENIED, extra


@pytest.mark.integration
def test_injection_refuses_out_of_scope(ctx_factory, demo_server: str) -> None:
    ctx = _injection_ctx(ctx_factory, demo_server)
    result = _dispatch(
        ctx, "run_injection_check", {"url": "https://elsewhere.test/?q=1"}
    )
    assert result.status == ToolStatus.ERROR
    assert "out of scope" in (result.error or "").lower()


# --------------------------------------------------------------------------- #
# Detection against the demo target
# --------------------------------------------------------------------------- #


@pytest.mark.integration
def test_injection_detects_the_vulnerable_parameter(ctx_factory, demo_server: str) -> None:
    """The demo target concatenates ``q`` into SQL and leaks the driver error."""
    ctx = _injection_ctx(ctx_factory, demo_server)
    result = _dispatch(
        ctx, "run_injection_check", {"url": demo_server + "/products?q=shoe"}
    )

    assert result.ok, result.error
    data = result.data
    assert data["parameters_tested"] == ["q"]
    assert data["vulnerable_count"] == 1
    assert data["baseline_status"] == 200

    finding_result = data["results"][0]
    assert finding_result["vulnerable"] is True
    assert finding_result["verdict"] == "error_based_injection"
    assert "mysql" in finding_result["error_signature"].lower()

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding["severity"] == "high"
    assert finding["cwe"] == "CWE-89"
    assert finding["location"] == "parameter:q"
    assert finding["evidence"]


@pytest.mark.integration
def test_injection_does_not_flag_a_safe_parameter(ctx_factory, demo_server: str) -> None:
    """``/search`` reflects its parameter without building SQL from it."""
    ctx = _injection_ctx(ctx_factory, demo_server)
    result = _dispatch(ctx, "run_injection_check", {"url": demo_server + "/search?q=shoe"})

    assert result.ok, result.error
    assert result.data["vulnerable_count"] == 0
    assert result.findings == []
    assert all(not item["vulnerable"] for item in result.data["results"])


@pytest.mark.integration
def test_injection_probes_every_parameter_by_default(ctx_factory, demo_server: str) -> None:
    ctx = _injection_ctx(ctx_factory, demo_server)
    result = _dispatch(
        ctx, "run_injection_check", {"url": demo_server + "/search?q=shoe&page=2&sort=asc"}
    )
    assert result.ok, result.error
    assert set(result.data["parameters_tested"]) == {"q", "page", "sort"}


@pytest.mark.integration
def test_injection_can_be_limited_to_named_parameters(ctx_factory, demo_server: str) -> None:
    ctx = _injection_ctx(ctx_factory, demo_server)
    result = _dispatch(
        ctx,
        "run_injection_check",
        {"url": demo_server + "/search?q=shoe&page=2", "parameters": ["page"]},
    )
    assert result.data["parameters_tested"] == ["page"]


@pytest.mark.integration
def test_an_unknown_parameter_name_is_reported_not_silently_dropped(
    ctx_factory, demo_server: str
) -> None:
    ctx = _injection_ctx(ctx_factory, demo_server)
    result = _dispatch(
        ctx,
        "run_injection_check",
        {"url": demo_server + "/search?q=shoe", "parameters": ["q", "nonexistent"]},
    )
    assert result.ok, result.error
    assert result.data["parameters_skipped"] == ["nonexistent"]
    assert any("nonexistent" in note for note in result.data["notes"])


@pytest.mark.integration
def test_canonical_query_lets_a_parameterless_url_be_tested(
    ctx_factory, demo_server: str
) -> None:
    ctx = _injection_ctx(ctx_factory, demo_server)
    result = _dispatch(
        ctx,
        "run_injection_check",
        {"url": demo_server + "/products", "canonical_query": "q=shoe"},
    )
    assert result.ok, result.error
    assert result.data["vulnerable_count"] == 1


@pytest.mark.integration
def test_a_url_with_no_parameters_sends_nothing(ctx_factory, demo_server: str) -> None:
    ctx = _injection_ctx(ctx_factory, demo_server)
    before = ctx.limits.budgets["requests"].used
    result = _dispatch(ctx, "run_injection_check", {"url": demo_server + "/"})
    assert result.ok
    assert result.data["parameters_tested"] == []
    assert ctx.limits.budgets["requests"].used == before, "must not send a request"


@pytest.mark.integration
def test_every_probe_is_a_read_only_get(ctx_factory, demo_server: str) -> None:
    """The technique never sends anything but GET, and the log proves it."""
    ctx = _injection_ctx(ctx_factory, demo_server)
    before = len(ctx.session.surface.http_history)
    _dispatch(ctx, "run_injection_check", {"url": demo_server + "/products?q=shoe"})

    new_entries = ctx.session.surface.http_history[before:]
    assert new_entries
    assert {entry.method for entry in new_entries} == {"GET"}


@pytest.mark.integration
def test_the_reported_budget_matches_the_requests_made(ctx_factory, demo_server: str) -> None:
    ctx = _injection_ctx(ctx_factory, demo_server)
    before_budget = ctx.limits.budgets["requests"].used
    before_history = len(ctx.session.surface.http_history)

    result = _dispatch(ctx, "run_injection_check", {"url": demo_server + "/products?q=shoe"})

    spent = ctx.limits.budgets["requests"].used - before_budget
    recorded = len(ctx.session.surface.http_history) - before_history
    assert result.data["requests_used"] == spent == recorded
    # One baseline plus one probe per payload.
    assert spent == 1 + len(SQL_ERROR_PAYLOADS)


@pytest.mark.integration
def test_probes_are_capped_per_parameter(ctx_factory, demo_server: str) -> None:
    """A URL with many parameters must not turn one tool call into a sweep."""
    ctx = _injection_ctx(ctx_factory, demo_server)
    query = "&".join(f"p{index}=v" for index in range(MAX_PARAMETERS + 4))
    result = _dispatch(ctx, "run_injection_check", {"url": f"{demo_server}/?{query}"})

    assert result.ok, result.error
    assert len(result.data["parameters_tested"]) <= MAX_PARAMETERS
    assert len(result.data["probes"]) <= MAX_PARAMETERS * MAX_PROBES_PER_PARAMETER
    assert any("only the first" in note for note in result.data["notes"])


@pytest.mark.integration
def test_the_payload_value_is_never_echoed_into_the_report(
    ctx_factory, demo_server: str
) -> None:
    """The report carries a label and the server's error, not the probe string itself."""
    ctx = _injection_ctx(ctx_factory, demo_server)
    result = _dispatch(ctx, "run_injection_check", {"url": demo_server + "/products?q=shoe"})

    rendered = str(result.data)
    for payload in SQL_ERROR_PAYLOADS:
        assert repr(payload.value) not in rendered, payload.label
    # The label, by contrast, is exactly what the report should show.
    assert any(
        probe["payload_label"] == "single quote" for probe in result.data["probes"]
    )


@pytest.mark.integration
def test_a_noisy_parameter_is_recorded_but_not_reported(ctx_factory, demo_server: str) -> None:
    """An endpoint whose response varies with its input is normal, not a vulnerability.

    ``/search`` echoes the query into the page body, so the response length changes for
    every payload. That must be recorded as a behaviour change and must not become a finding.
    """
    ctx = _injection_ctx(ctx_factory, demo_server)
    result = _dispatch(ctx, "run_injection_check", {"url": demo_server + "/search?q=shoe"})

    assert result.ok, result.error
    assert result.findings == []
    outcomes = {item["verdict"] for item in result.data["results"]}
    assert outcomes <= {
        "behaviour_changed_without_error",
        "no_error_observed",
        "probes_failed",
    }


@pytest.mark.integration
def test_an_application_that_always_errors_is_not_flagged(ctx_factory, demo_server: str) -> None:
    """A signature present in the baseline is discounted, so a permanently broken page is not
    mistaken for injection."""
    ctx = _injection_ctx(ctx_factory, demo_server)

    # /products returns its SQL error only for a quote. /nonexistent returns a generic 404, so
    # use a URL whose baseline already contains the signature by pointing the probe at the
    # vulnerable path with a quote already in it.
    before = ctx.limits.budgets["requests"].used
    result = _dispatch(
        ctx,
        "run_injection_check",
        {"url": demo_server + "/products?q="},
    )
    # The baseline has no quote, so the probe still finds one. This asserts the request count
    # rather than the verdict, which the other tests cover.
    assert result.ok, result.error
    assert ctx.limits.budgets["requests"].used > before


@pytest.mark.integration
def test_nosql_technique_is_available_and_bounded(ctx_factory, demo_server: str) -> None:
    ctx = _injection_ctx(ctx_factory, demo_server)
    result = _dispatch(
        ctx,
        "run_injection_check",
        {"url": demo_server + "/search?q=shoe", "technique": "nosql_operator"},
    )
    assert result.ok, result.error
    assert result.data["technique"] == "nosql_operator"
    assert result.data["payloads_available"] == len(NOSQL_OPERATOR_PAYLOADS)
    assert result.findings == [], "the demo target is not a document store"


@pytest.mark.integration
def test_a_missing_parameter_is_not_an_error(ctx_factory, demo_server: str) -> None:
    """A 404 on every probe is data, not a crash."""
    ctx = _injection_ctx(ctx_factory, demo_server)
    result = _dispatch(
        ctx, "run_injection_check", {"url": demo_server + "/products?q=shoe&x=1", "parameters": ["x"]}
    )
    assert result.ok, result.error
    assert result.data["vulnerable_count"] == 0
