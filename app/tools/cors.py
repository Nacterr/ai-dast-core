"""``analyze_cors``: evaluate a target's CORS policy.

CORS misconfiguration is one of the few findings a passive scanner can produce that is
directly exploitable, and it is easy to get wrong in both directions: report a safe
wildcard as critical (noise), or miss a reflected origin with credentials (a real
account-takeover primitive).

The safety property of this tool is narrow and important: **the ``Origin`` header is a
harness constant**. There is no request field for it. A request-supplied ``Origin`` would be
an injection into a trust decision the browser makes on the user's behalf, which is exactly
the class of thing this harness refuses to expose.

The probe value is a reserved ``.invalid`` domain, so no real service is ever named, and a
reflection of it proves the server echoes whatever it is given.
"""

from __future__ import annotations

import re

from app.models.finding import Confidence, Evidence, Finding, FindingCategory, Severity
from app.models.tools import AnalyzeCorsData, AnalyzeCorsRequest, CorsAssessment
from app.tools.base import ToolOutcome, ok
from app.tools.findings import make_finding
from app.tools.http_client import EgressDenied, HttpExchange
from app.tools.shared import require_in_scope

# `.invalid` is reserved by RFC 2606 and can never resolve, so naming it cannot be mistaken
# for an attempt to reach a real third party.
PROBE_ORIGIN = "https://origin-probe.invalid"
SECOND_PROBE_ORIGIN = "https://second-probe.invalid"

# Headers worth reading off the response, in the order the report should show them.
_CORS_HEADERS = (
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "access-control-allow-methods",
    "access-control-allow-headers",
    "access-control-expose-headers",
    "access-control-max-age",
)

_NULL_ORIGIN = "null"


def analyze_cors(ctx, request: AnalyzeCorsRequest) -> ToolOutcome:
    """Evaluate the CORS policy of one in-scope URL."""
    decision = require_in_scope(ctx, request.url)
    origin = _origin_of(decision.url)

    assessments: list[CorsAssessment] = []
    notes: list[str] = []

    # Two probes with different Origin values. One reflection could be a fixed value that
    # happens to match; two different reflections prove the server echoes the header.
    first = _probe(ctx, decision.url, PROBE_ORIGIN, notes)
    if first is None:
        return ok(
            f"Could not obtain a response from {decision.url}; no CORS assessment was possible.",
            AnalyzeCorsData(origin=origin, probe_origin=PROBE_ORIGIN, notes=notes),
        )

    assessment = _assess(decision.url, first, PROBE_ORIGIN)

    if assessment.reflects_arbitrary_origin:
        second = _probe(ctx, decision.url, SECOND_PROBE_ORIGIN, notes)
        if second is not None:
            second_assessment = _assess(decision.url, second, SECOND_PROBE_ORIGIN)
            if second_assessment.reflects_arbitrary_origin:
                assessment.rationale += (
                    " A second probe with a different Origin was also reflected, which "
                    "confirms the server echoes whatever it is sent rather than returning a "
                    "fixed value."
                )
            else:
                # The first "reflection" was a coincidence: a fixed allowlist value that
                # matched our probe. Downgrade rather than cry wolf.
                assessment.reflects_arbitrary_origin = False
                assessment.rationale += (
                    " A second probe with a different Origin was NOT reflected, so the first "
                    "match was a fixed allowlist value rather than a reflection. Not reported "
                    "as a CORS misconfiguration."
                )
                if assessment.verdict in {
                    "reflects_origin",
                    "reflects_origin_with_credentials",
                }:
                    assessment.verdict = "safe"
                    assessment.severity = "info"

    if request.probe_preflight:
        preflight = _probe_preflight(ctx, decision.url, PROBE_ORIGIN, notes)
        if preflight is not None:
            assessment.preflight_status = preflight.status_code
            assessment.preflight_allow_methods = _header(preflight, "access-control-allow-methods")
            assessment.preflight_allow_headers = _header(preflight, "access-control-allow-headers")

    assessments.append(assessment)

    findings = _findings_for(assessment, decision.url)
    vulnerable = sum(1 for item in assessments if item.severity in {"medium", "high", "critical"})

    if assessment.verdict == "safe":
        summary = (
            f"CORS policy at {assessment.url} looks safe: {assessment.rationale} "
            "One probe request was sent with a reserved .invalid Origin."
        )
    else:
        summary = (
            f"CORS policy at {assessment.url} is misconfigured "
            f"({assessment.verdict}, severity {assessment.severity}): {assessment.rationale} "
            f"Allow-Origin was {assessment.allow_origin!r} and Allow-Credentials "
            f"{assessment.allow_credentials!r}."
        )

    data = AnalyzeCorsData(
        origin=origin,
        probe_origin=PROBE_ORIGIN,
        assessments=assessments,
        vulnerable_count=vulnerable,
        notes=notes,
    )
    return ok(summary, data, findings=findings, notes=notes)


# --------------------------------------------------------------------------- #
# Probing
# --------------------------------------------------------------------------- #


def _probe(ctx, url: str, origin: str, notes: list[str]) -> HttpExchange | None:
    """Send one request with the given harness-chosen Origin.

    The request budget is charged by ``SafeHttpClient`` itself, which is the single choke
    point for outbound traffic. Reserving here as well would count the request twice.
    """
    try:
        return ctx.http.request(
            url,
            method="GET",
            follow_redirects=False,
            read_body=False,
            extra_headers={"Origin": origin, "Sec-Fetch-Mode": "cors"},
        )
    except EgressDenied as exc:
        notes.append(f"request refused by the scope guard: {exc.reason}")
        return None
    except Exception as exc:  # noqa: BLE001 - a failed probe is data, not a crash
        notes.append(f"probe failed ({type(exc).__name__}): {exc}")
        return None


def _probe_preflight(ctx, url: str, origin: str, notes: list[str]) -> HttpExchange | None:
    """Send an OPTIONS preflight with fixed, harness-chosen method and header values."""
    try:
        return ctx.http.request(
            url,
            method="OPTIONS",
            follow_redirects=False,
            read_body=False,
            extra_headers={
                "Origin": origin,
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "content-type",
            },
        )
    except EgressDenied as exc:
        notes.append(f"preflight refused by the scope guard: {exc.reason}")
        return None
    except Exception as exc:  # noqa: BLE001
        notes.append(f"preflight failed ({type(exc).__name__}): {exc}")
        return None


def _header(exchange: HttpExchange, name: str) -> str:
    return str((exchange.headers or {}).get(name, ""))[:500]


# --------------------------------------------------------------------------- #
# Assessment
# --------------------------------------------------------------------------- #


def _assess(url: str, exchange: HttpExchange, probe_origin: str) -> CorsAssessment:
    """Decide whether the observed CORS headers constitute a misconfiguration."""
    allow_origin = _header(exchange, "access-control-allow-origin")
    allow_credentials = _header(exchange, "access-control-allow-credentials")
    credentials_allowed = allow_credentials.strip().lower() == "true"

    lowered_origin = allow_origin.strip().lower()
    wildcard = lowered_origin == "*"
    # A reflection must match the probe exactly; anything else is a fixed value.
    reflects = bool(allow_origin) and allow_origin.strip() == probe_origin
    null_origin = lowered_origin == _NULL_ORIGIN

    assessment = CorsAssessment(
        url=url,
        status_code=exchange.status_code,
        request_origin=probe_origin,
        allow_origin=allow_origin,
        allow_credentials=allow_credentials,
        allow_methods=_header(exchange, "access-control-allow-methods"),
        allow_headers=_header(exchange, "access-control-allow-headers"),
        expose_headers=_header(exchange, "access-control-expose-headers"),
        max_age=_header(exchange, "access-control-max-age"),
        reflects_arbitrary_origin=reflects,
        wildcard=wildcard,
        credentials_allowed=credentials_allowed,
    )

    if not allow_origin:
        assessment.verdict = "safe"
        assessment.severity = "info"
        assessment.rationale = (
            "No Access-Control-Allow-Origin header was returned, so the browser's "
            "same-origin policy blocks cross-origin reads."
        )
        return assessment

    if null_origin:
        assessment.verdict = "null_origin"
        assessment.severity = "high"
        assessment.rationale = (
            "Access-Control-Allow-Origin is 'null'. That value is sent by sandboxed iframes "
            "and local files, so any attacker who can get a victim to load a sandboxed frame "
            "can read this response."
        )
        return assessment

    if reflects and credentials_allowed:
        assessment.verdict = "reflects_origin_with_credentials"
        assessment.severity = "high"
        assessment.rationale = (
            "The response echoed the request Origin and also allows credentials. Any site "
            "can therefore make an authenticated cross-origin request and read the response, "
            "which is a direct account-takeover primitive."
        )
        return assessment

    if reflects:
        assessment.verdict = "reflects_origin"
        assessment.severity = "medium"
        assessment.rationale = (
            "The response echoed the request Origin. Without Allow-Credentials the impact is "
            "limited to unauthenticated data, but the policy is clearly an accidental "
            "allow-everything rule rather than a deliberate allowlist."
        )
        return assessment

    if wildcard and credentials_allowed:
        # Modern browsers reject this combination, so it is a broken configuration rather
        # than an exploitable one - but it signals a misunderstanding worth fixing.
        assessment.verdict = "wildcard_with_credentials"
        assessment.severity = "medium"
        assessment.rationale = (
            "Allow-Origin is '*' together with Allow-Credentials: true. Browsers reject "
            "this combination, so it does not currently work - but it means credentialed "
            "CORS is either broken for legitimate callers or about to be 'fixed' by "
            "reflecting the Origin, which would be exploitable."
        )
        return assessment

    if wildcard:
        assessment.verdict = "wildcard_no_credentials"
        assessment.severity = "info"
        assessment.rationale = (
            "Allow-Origin is '*' without credentials. That is the normal, safe configuration "
            "for a genuinely public API, so it is recorded for context and not reported as a "
            "finding."
        )
        return assessment

    assessment.verdict = "safe"
    assessment.severity = "info"
    assessment.rationale = (
        f"Access-Control-Allow-Origin is {allow_origin!r}, which is a fixed value rather "
        "than a reflection of the request Origin."
    )
    return assessment


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #

_ORIGIN_LIKE = re.compile(r"^https?://[A-Za-z0-9.\-]+(?::\d+)?$", re.IGNORECASE)


def _findings_for(assessment: CorsAssessment, requested_url: str) -> list[Finding]:
    """Raise a finding only for the verdicts that are genuinely exploitable or broken.

    ``wildcard_no_credentials`` is deliberately not a finding: a public API that returns
    ``Access-Control-Allow-Origin: *`` is configured correctly, and reporting it trains the
    reader to ignore CORS findings.
    """
    if assessment.verdict in {"safe", "wildcard_no_credentials"}:
        return []

    host = _origin_of(assessment.url)
    severity = Severity(assessment.severity)
    confidence = Confidence.HIGH

    if assessment.verdict == "reflects_origin_with_credentials":
        title = "CORS policy reflects any Origin and allows credentials"
    elif assessment.verdict == "reflects_origin":
        title = "CORS policy reflects any Origin"
    elif assessment.verdict == "null_origin":
        title = "CORS policy allows the 'null' Origin"
    else:
        title = "CORS policy combines a wildcard Origin with credentials"

    observed_parts = [f"Access-Control-Allow-Origin: {assessment.allow_origin}"]
    if assessment.allow_credentials:
        observed_parts.append(
            f"Access-Control-Allow-Credentials: {assessment.allow_credentials}"
        )

    return [
        make_finding(
            title=title,
            category=FindingCategory.CORS,
            severity=severity,
            confidence=confidence,
            description=assessment.rationale,
            impact=_impact_for(assessment),
            recommendation=_recommendation_for(assessment),
            url=assessment.url,
            host=host,
            location="access-control-allow-origin",
            owasp="A01:2021 - Broken Access Control",
            cwe="CWE-942",
            evidence=[
                Evidence(
                    tool="analyze_cors",
                    url=assessment.url,
                    location="cors-headers",
                    observed="; ".join(observed_parts),
                    expected="an explicit allowlist of trusted origins",
                    raw={
                        "probe_origin": assessment.request_origin,
                        "verdict": assessment.verdict,
                        "status_code": assessment.status_code,
                        "preflight_status": assessment.preflight_status,
                    },
                )
            ],
            references=[
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/11-Testing_Cross_Origin_Resource_Sharing"
            ],
            source_tools=["analyze_cors"],
            tags=["cors", "access-control", assessment.verdict],
        )
    ]


def _impact_for(assessment: CorsAssessment) -> str:
    if assessment.verdict == "reflects_origin_with_credentials":
        return (
            "Any website can make an authenticated request to this endpoint on behalf of a "
            "logged-in user and read the response. That is a direct path to account takeover "
            "or mass data exfiltration."
        )
    if assessment.verdict == "reflects_origin":
        return (
            "Any website can read this response cross-origin. If the response is ever "
            "personalised - by session cookie, by a token in a header, or by an unguessable "
            "URL - that data becomes readable by any site the user visits."
        )
    if assessment.verdict == "null_origin":
        return (
            "Any attacker who can get a victim to load a sandboxed iframe or a local file can "
            "read this response, and can do so with credentials."
        )
    return (
        "Credentialed cross-origin access does not work as configured today, but the policy "
        "signals that the intent is broader than the configuration safely allows."
    )


def _recommendation_for(assessment: CorsAssessment) -> str:
    if assessment.verdict in {"reflects_origin_with_credentials", "reflects_origin"}:
        return (
            "Replace the reflection with an explicit allowlist: read the request Origin, "
            "compare it against a fixed set of trusted origins, and echo it only on an exact "
            "match. Never derive the allowed origin from the request without validating it."
        )
    if assessment.verdict == "null_origin":
        return (
            "Remove 'null' from the allowed origins. If local files or sandboxed frames "
            "genuinely need access, give them a real origin and allowlist that instead."
        )
    return (
        "Decide which of the two behaviours you want: a public API with "
        "`Allow-Origin: *` and no credentials, or a private API with an explicit allowlist "
        "and credentials. The current combination is neither."
    )


def _origin_of(url: str) -> str:
    from urllib.parse import urlsplit

    parts = urlsplit(url)
    port = f":{parts.port}" if parts.port else ""
    return f"{parts.scheme.lower()}://{(parts.hostname or '').lower()}{port}"


__all__ = ["PROBE_ORIGIN", "SECOND_PROBE_ORIGIN", "_assess", "analyze_cors"]
