"""Tests for ``analyze_cors`` and ``check_tls``.

The CORS tests are driven end to end against the demo target, which serves three distinct
policies on purpose: a safe wildcard, a credible reflection with credentials, and a
``null`` origin.

The TLS tests are mostly unit tests over the pure summarisation and date-parsing functions,
because the interesting logic is there and it can be exercised without a socket. A fake
``ssl``-shaped object is a better test than a real handshake: it can produce the malformed
and partial inputs a real stack rarely emits but a security tool must survive.
"""

from __future__ import annotations

import re

import pytest

from app.models.tools import (
    AnalyzeCorsRequest,
    CheckTlsRequest,
    ToolCall,
    ToolStatus,
)
from app.tools.cors import (
    PROBE_ORIGIN,
    SECOND_PROBE_ORIGIN,
    _assess,
)
from app.tools.http_client import summarize_tls
from app.tools.tls import (
    DEFAULT_WARN_DAYS,
    _is_obsolete,
    _parse_certificate_date,
    common_name,
)


class _FakeExchange:
    """Stand-in for an HttpExchange carrying chosen CORS headers."""

    def __init__(self, headers: dict[str, str], status: int = 200) -> None:
        self.status_code = status
        self.headers = {key.lower(): value for key, value in headers.items()}
        self.body_prefix = ""
        self.body_bytes = 0
        self.hops = []
        self.error = ""
        self.tls = {}


def _dispatch(ctx, tool: str, args: dict):
    from app.tools.catalog import build_default_registry

    return build_default_registry().dispatch(ToolCall(tool=tool, args=args), ctx)


# --------------------------------------------------------------------------- #
# CORS verdicts (pure, no network)
# --------------------------------------------------------------------------- #


def test_no_allow_origin_is_safe() -> None:
    assessment = _assess("https://a.test/", _FakeExchange({}), PROBE_ORIGIN)
    assert assessment.verdict == "safe"
    assert assessment.severity == "info"


def test_wildcard_without_credentials_is_not_a_finding() -> None:
    """A public API returning ``*`` is configured correctly. Reporting it is noise."""
    assessment = _assess(
        "https://a.test/",
        _FakeExchange({"Access-Control-Allow-Origin": "*"}),
        PROBE_ORIGIN,
    )
    assert assessment.verdict == "wildcard_no_credentials"
    assert assessment.severity == "info"
    assert assessment.wildcard is True


def test_wildcard_with_credentials_is_broken_not_exploitable() -> None:
    assessment = _assess(
        "https://a.test/",
        _FakeExchange(
            {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"}
        ),
        PROBE_ORIGIN,
    )
    assert assessment.verdict == "wildcard_with_credentials"
    assert assessment.severity == "medium"


def test_reflected_origin_with_credentials_is_high() -> None:
    assessment = _assess(
        "https://a.test/",
        _FakeExchange(
            {
                "Access-Control-Allow-Origin": PROBE_ORIGIN,
                "Access-Control-Allow-Credentials": "true",
            }
        ),
        PROBE_ORIGIN,
    )
    assert assessment.verdict == "reflects_origin_with_credentials"
    assert assessment.severity == "high"
    assert assessment.reflects_arbitrary_origin is True


def test_reflected_origin_without_credentials_is_medium() -> None:
    assessment = _assess(
        "https://a.test/",
        _FakeExchange({"Access-Control-Allow-Origin": PROBE_ORIGIN}),
        PROBE_ORIGIN,
    )
    assert assessment.verdict == "reflects_origin"
    assert assessment.severity == "medium"


def test_null_origin_is_high() -> None:
    assessment = _assess(
        "https://a.test/",
        _FakeExchange(
            {"Access-Control-Allow-Origin": "null", "Access-Control-Allow-Credentials": "true"}
        ),
        PROBE_ORIGIN,
    )
    assert assessment.verdict == "null_origin"
    assert assessment.severity == "high"


def test_a_fixed_allowlist_value_is_not_a_reflection() -> None:
    """The server echoes something that is not our probe, so it has a real allowlist."""
    assessment = _assess(
        "https://a.test/",
        _FakeExchange({"Access-Control-Allow-Origin": "https://app.test"}),
        PROBE_ORIGIN,
    )
    assert assessment.verdict == "safe"
    assert assessment.reflects_arbitrary_origin is False


@pytest.mark.parametrize(
    "observed", ["https://origin-probe.invalid.evil.test", "https://ORIGIN-PROBE.INVALID"]
)
def test_only_an_exact_reflection_counts(observed: str) -> None:
    """A near-miss must not be treated as the probe echoing back."""
    assessment = _assess(
        "https://a.test/",
        _FakeExchange({"Access-Control-Allow-Origin": observed}),
        PROBE_ORIGIN,
    )
    if observed == PROBE_ORIGIN:
        assert assessment.reflects_arbitrary_origin is True
    else:
        assert assessment.reflects_arbitrary_origin is False


# --------------------------------------------------------------------------- #
# analyze_cors against the demo target
# --------------------------------------------------------------------------- #


@pytest.mark.integration
def test_analyze_cors_catches_a_credible_reflection(ctx_factory, demo_server: str) -> None:
    ctx = ctx_factory(demo_server)
    result = _dispatch(ctx, "analyze_cors", {"url": demo_server + "/api/reflect"})

    assert result.ok, result.error
    assessment = result.data["assessments"][0]
    assert assessment["verdict"] == "reflects_origin_with_credentials"
    assert assessment["severity"] == "high"
    assert assessment["allow_origin"] == PROBE_ORIGIN
    assert result.data["vulnerable_count"] == 1

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding["category"] == "cors"
    assert finding["severity"] == "high"
    assert finding["evidence"]


@pytest.mark.integration
def test_analyze_cors_confirms_a_reflection_with_a_second_origin(
    ctx_factory, demo_server: str
) -> None:
    """One probe could be a coincidence; the tool checks with a second one."""
    ctx = ctx_factory(demo_server)
    result = _dispatch(ctx, "analyze_cors", {"url": demo_server + "/api/reflect"})
    assert "second probe" in result.data["assessments"][0]["rationale"].lower()
    assert SECOND_PROBE_ORIGIN not in result.data["assessments"][0]["rationale"]


@pytest.mark.integration
def test_analyze_cors_catches_a_null_origin_policy(ctx_factory, demo_server: str) -> None:
    ctx = ctx_factory(demo_server)
    result = _dispatch(ctx, "analyze_cors", {"url": demo_server + "/api/null-origin"})
    assert result.ok, result.error
    assessment = result.data["assessments"][0]
    assert assessment["verdict"] == "null_origin"
    assert assessment["severity"] == "high"
    assert result.findings


@pytest.mark.integration
def test_analyze_cors_does_not_flag_a_safe_wildcard(ctx_factory, demo_server: str) -> None:
    """``/`` sends ``*`` together with credentials, which browsers reject.

    It is reported, but only as a broken configuration - and critically it is *not* reported
    as a reflection, because the response never echoes the probe.
    """
    ctx = ctx_factory(demo_server)
    result = _dispatch(ctx, "analyze_cors", {"url": demo_server + "/"})
    assert result.ok, result.error
    assessment = result.data["assessments"][0]
    assert assessment["verdict"] == "wildcard_with_credentials"
    assert assessment["reflects_arbitrary_origin"] is False
    assert "reflect" not in assessment["verdict"]


@pytest.mark.integration
def test_analyze_cors_preflight_reveals_methods(ctx_factory, demo_server: str) -> None:
    ctx = ctx_factory(demo_server)
    result = _dispatch(
        ctx, "analyze_cors", {"url": demo_server + "/api/reflect", "probe_preflight": True}
    )
    assert result.ok, result.error
    assessment = result.data["assessments"][0]
    assert assessment["preflight_status"] == 204
    assert "GET" in assessment["preflight_allow_methods"]
    assert assessment["preflight_allow_headers"]


@pytest.mark.integration
def test_analyze_cors_costs_one_or_two_requests(ctx_factory, demo_server: str) -> None:
    """Regression: the request budget must be charged once per request.

    An earlier version reserved the request in the tool *and* the HTTP client charged it
    again, so every CORS probe cost double and would have exhausted a budget twice as fast
    as the operator configured.
    """
    ctx = ctx_factory(demo_server)
    before = ctx.limits.budgets["requests"].used
    _dispatch(ctx, "analyze_cors", {"url": demo_server + "/api/null-origin"})
    # A null origin is not a reflection, so no confirmation probe is needed.
    assert ctx.limits.budgets["requests"].used == before + 1

    before = ctx.limits.budgets["requests"].used
    _dispatch(ctx, "analyze_cors", {"url": demo_server + "/api/reflect"})
    # A reflection triggers one confirmation probe with a second Origin.
    assert ctx.limits.budgets["requests"].used == before + 2

    before = ctx.limits.budgets["requests"].used
    _dispatch(
        ctx, "analyze_cors", {"url": demo_server + "/api/reflect", "probe_preflight": True}
    )
    assert ctx.limits.budgets["requests"].used == before + 3


@pytest.mark.integration
def test_analyze_cors_records_every_probe_in_the_history(ctx_factory, demo_server: str) -> None:
    """The transaction log must match the budget: one entry per request, not two."""
    ctx = ctx_factory(demo_server)
    before_history = len(ctx.session.surface.http_history)
    before_budget = ctx.limits.budgets["requests"].used

    _dispatch(ctx, "analyze_cors", {"url": demo_server + "/api/reflect"})

    spent = ctx.limits.budgets["requests"].used - before_budget
    recorded = len(ctx.session.surface.http_history) - before_history
    assert recorded == spent == 2


@pytest.mark.integration
def test_analyze_exposed_files_charges_each_request_once(
    ctx_factory, demo_server: str
) -> None:
    """Same regression, for the path-catalogue sweep."""
    ctx = ctx_factory(demo_server)
    before_budget = ctx.limits.budgets["requests"].used
    before_history = len(ctx.session.surface.http_history)

    _dispatch(ctx, "analyze_exposed_files", {"url": demo_server + "/", "max_paths": 3})

    spent = ctx.limits.budgets["requests"].used - before_budget
    recorded = len(ctx.session.surface.http_history) - before_history
    assert spent == recorded, f"budget counted {spent} but {recorded} requests were recorded"


@pytest.mark.integration
def test_analyze_cors_origin_header_cannot_be_supplied_by_the_caller(
    ctx_factory, demo_server: str
) -> None:
    """There is no Origin parameter, so the tool cannot be used as a request forger."""
    ctx = ctx_factory(demo_server)
    result = _dispatch(
        ctx,
        "analyze_cors",
        {"url": demo_server + "/api/reflect", "origin": "https://attacker.test"},
    )
    assert result.status == ToolStatus.DENIED
    assert "origin" in (result.denial_reason or "")


@pytest.mark.integration
def test_analyze_cors_refuses_out_of_scope(ctx_factory, demo_server: str) -> None:
    ctx = ctx_factory(demo_server)
    result = _dispatch(ctx, "analyze_cors", {"url": "https://elsewhere.test/"})
    assert result.status == ToolStatus.ERROR
    assert "out of scope" in (result.error or "").lower()


def test_probe_origins_are_reserved_names() -> None:
    """Naming a resolvable domain would mean contacting a third party we do not own."""
    for origin in (PROBE_ORIGIN, SECOND_PROBE_ORIGIN):
        assert origin.endswith(".invalid"), origin


# --------------------------------------------------------------------------- #
# TLS: certificate date parsing
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("raw", "expected_year", "expected_month"),
    [
        ("Sep  1 12:00:00 2026 GMT", 2026, 9),
        ("Sep 1 12:00:00 2026 GMT", 2026, 9),
        ("Jan 15 00:00:00 2027 GMT", 2027, 1),
        ("20260901120000Z", 2026, 9),
        ("Tue, 01 Sep 2026 12:00:00 GMT", 2026, 9),
        ("2026-09-01T12:00:00Z", 2026, 9),
        ("2026-09-01T12:00:00+00:00", 2026, 9),
    ],
)
def test_parse_certificate_date_formats(raw: str, expected_year: int, expected_month: int) -> None:
    """Different stacks report dates differently; all of them must parse."""
    parsed = _parse_certificate_date(raw)
    assert parsed is not None, raw
    assert parsed.year == expected_year
    assert parsed.month == expected_month


@pytest.mark.parametrize("raw", ["", "   ", "not a date", "32 Foo 2026"])
def test_parse_certificate_date_returns_none_on_garbage(raw: str) -> None:
    """An unparseable date must yield 'unknown', never a guessed expiry."""
    assert _parse_certificate_date(raw) is None


def test_common_name_extraction() -> None:
    assert common_name("commonName=example.com, organizationName=Example") == "example.com"
    assert common_name("organizationName=Example") == "Example"
    assert common_name("") == ""


# --------------------------------------------------------------------------- #
# TLS: obsolete protocol detection
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "protocol", ["SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLS 1.0", "TLSv1_0", "tlsv1", "TLSv1.1"]
)
def test_obsolete_protocols_are_recognised(protocol: str) -> None:
    """TLS 1.1 is included: deprecated by RFC 8996 and disabled in most stacks."""
    assert _is_obsolete(protocol) is True, protocol


@pytest.mark.parametrize("protocol", ["TLSv1.2", "TLSv1.3", "TLS 1.2", "TLSv1_3", "TLS 1.3", ""])
def test_modern_protocols_are_not_flagged(protocol: str) -> None:
    assert _is_obsolete(protocol) is False, protocol


def test_protocol_normalisation_collapses_the_spellings() -> None:
    """The same version is spelled several ways; all must reduce to one token."""
    from app.tools.tls import _normalize_protocol

    for variant in ("TLSv1.0", "TLS 1.0", "TLSv1_0", "tlsv1.0", "TLSV1.0"):
        assert _normalize_protocol(variant) == "tls10", variant
    for variant in ("TLSv1.2", "TLS 1.2", "TLSv1_2"):
        assert _normalize_protocol(variant) == "tls12", variant
    # A version separator is the only thing the 'v' rule may remove.
    assert _normalize_protocol("SSHv2") == "sshv2"


# --------------------------------------------------------------------------- #
# TLS: summarisation of an ssl-shaped object
# --------------------------------------------------------------------------- #


class _FakeSsl:
    """Minimal ``ssl.SSLObject`` stand-in."""

    def __init__(
        self,
        protocol: str = "TLSv1.3",
        cipher: tuple | None = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
        certificate: dict | None = None,
        raise_on_certificate: bool = False,
        raise_on_version: bool = False,
    ) -> None:
        self._protocol = protocol
        self._cipher = cipher
        self._certificate = certificate if certificate is not None else {}
        self._raise_certificate = raise_on_certificate
        self._raise_version = raise_on_version

    def version(self) -> str:
        if self._raise_version:
            raise RuntimeError("no version")
        return self._protocol

    def cipher(self) -> tuple | None:
        return self._cipher

    def getpeercert(self) -> dict:
        if self._raise_certificate:
            raise ValueError("certificate unavailable")
        return self._certificate


CERTIFICATE = {
    "subject": ((("commonName", "example.com"),), (("organizationName", "Example Ltd"),)),
    "issuer": ((("commonName", "R3"),), (("organizationName", "Let's Encrypt"),)),
    "notBefore": "Aug  1 00:00:00 2026 GMT",
    "notAfter": "Oct 30 23:59:59 2026 GMT",
    "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com")),
}


def test_summarize_tls_extracts_the_expected_fields() -> None:
    summary = summarize_tls(_FakeSsl(certificate=CERTIFICATE))
    assert summary["protocol"] == "TLSv1.3"
    assert summary["cipher"] == "TLS_AES_256_GCM_SHA384"
    assert "commonName=example.com" in summary["subject"]
    assert "Let's Encrypt" in summary["issuer"]
    assert summary["not_after"] == "Oct 30 23:59:59 2026 GMT"
    assert summary["subject_alt_names"] == ["example.com", "www.example.com"]


def test_summarize_tls_reports_absence_rather_than_guessing() -> None:
    summary = summarize_tls(_FakeSsl(certificate={}))
    assert summary["protocol"] == "TLSv1.3"
    assert "not exposed" in summary.get("note", "")
    assert "subject" not in summary


def test_summarize_tls_survives_a_broken_transport() -> None:
    """A partial API must degrade to unknown, not crash the scan."""
    summary = summarize_tls(_FakeSsl(certificate=CERTIFICATE, raise_on_certificate=True))
    assert summary["protocol"] == "TLSv1.3"
    assert "not exposed" in summary.get("note", "")


def test_summarize_tls_handles_a_missing_version() -> None:
    summary = summarize_tls(_FakeSsl(certificate=CERTIFICATE, raise_on_version=True))
    assert summary["protocol"] == ""
    assert summary["subject"]


def test_summarize_tls_handles_no_cipher() -> None:
    summary = summarize_tls(_FakeSsl(certificate=CERTIFICATE, cipher=None))
    assert summary["cipher"] == ""


# --------------------------------------------------------------------------- #
# check_tls against the demo target (plain HTTP)
# --------------------------------------------------------------------------- #


@pytest.mark.integration
def test_check_tls_declines_to_upgrade_a_plain_http_url(ctx_factory, demo_server: str) -> None:
    """Silently switching to https:// would contact an endpoint nobody authorised."""
    ctx = ctx_factory(demo_server)
    before = ctx.limits.budgets["requests"].used
    result = _dispatch(ctx, "check_tls", {"url": demo_server + "/"})

    assert result.ok, result.error
    assert result.data["used_https"] is False
    assert result.data["grade"] == "unknown"
    assert result.findings == []
    assert ctx.limits.budgets["requests"].used == before, "must not send a request"
    assert any("does not upgrade" in note for note in result.data["notes"])


@pytest.mark.integration
def test_check_tls_rejects_an_invalid_warn_days(ctx_factory, demo_server: str) -> None:
    ctx = ctx_factory(demo_server)
    result = _dispatch(ctx, "check_tls", {"url": demo_server + "/", "warn_days": 9999})
    assert result.status == ToolStatus.DENIED
    assert "warn_days" in (result.denial_reason or "")


@pytest.mark.integration
def test_check_tls_refuses_out_of_scope(ctx_factory, demo_server: str) -> None:
    ctx = ctx_factory(demo_server)
    result = _dispatch(ctx, "check_tls", {"url": "https://elsewhere.test/"})
    assert result.status == ToolStatus.ERROR
    assert "out of scope" in (result.error or "").lower()


def test_default_warn_days_is_sane() -> None:
    assert 7 <= DEFAULT_WARN_DAYS <= 60
