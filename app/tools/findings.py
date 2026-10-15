"""Findings factories and the security-header knowledge base.

Findings are built by harness code from observed evidence, never authored by the
model. The AI may later re-classify severity or add commentary, but it cannot
create a finding without a tool observation behind it, which is what keeps the
report free of hallucinated vulnerabilities.
"""

from __future__ import annotations

from app.models.finding import Confidence, Evidence, Finding, FindingCategory, Severity


def make_finding(
    *,
    title: str,
    category: FindingCategory,
    severity: Severity,
    confidence: Confidence = Confidence.HIGH,
    description: str = "",
    impact: str = "",
    recommendation: str = "",
    url: str = "",
    host: str = "",
    location: str = "",
    owasp: str = "",
    cwe: str = "",
    evidence: list[Evidence] | None = None,
    references: list[str] | None = None,
    source_tools: list[str] | None = None,
    tags: list[str] | None = None,
) -> Finding:
    """Build a finding with a stable, evidence-derived identity.

    ``host`` defaults to the host of ``url``. It is the unit of finding identity, so a
    missing header on four pages of one origin is one finding with four evidence rows
    rather than four near-identical findings.
    """
    resolved_host = host or Finding.host_of(url)
    if not resolved_host and evidence:
        for item in evidence:
            resolved_host = Finding.host_of(item.url)
            if resolved_host:
                break

    key = Finding.compute_dedup_key(category, location, resolved_host, title)
    return Finding(
        id=Finding.compute_id(key),
        title=title,
        category=category,
        severity=severity,
        confidence=confidence,
        description=description,
        impact=impact,
        recommendation=recommendation,
        url=url,
        host=resolved_host,
        location=location,
        owasp=owasp,
        cwe=cwe,
        evidence=list(evidence or []),
        references=list(references or []),
        source_tools=list(source_tools or []),
        tags=list(tags or []),
    )


def header_evidence(url: str, header: str, observed: str, expected: str) -> Evidence:
    return Evidence(
        tool="check_headers",
        url=url,
        location=header,
        observed=observed,
        expected=expected,
        raw={"header": header, "observed": observed[:300], "expected": expected[:300]},
    )


# --------------------------------------------------------------------------- #
# Security header knowledge base
# --------------------------------------------------------------------------- #

# Each entry: header name, check kind, severity when missing, severity when weak,
# prose for the planner and the report, and OWASP/CWE mapping.
#
# `check` semantics:
#   "required"   - absent means missing
#   "weak"       - present but must satisfy `valid_values`; a value outside the set
#                  is reported as weak (used for enumerated headers)
#   "value"      - present but must match `pattern`
#   "informational"- recorded, never scored
#   "attacker"   - set to a value that helps an attacker

HeaderSpec = dict[str, object]

HEADER_SPECS: tuple[HeaderSpec, ...] = (
    {
        "header": "strict-transport-security",
        "title": "HTTP Strict Transport Security (HSTS) is missing",
        "check": "weak",
        "severity_missing": Severity.MEDIUM,
        "severity_weak": Severity.MEDIUM,
        "description": (
            "The response does not set Strict-Transport-Security, so browsers will "
            "happily make the first request to this site over plain HTTP. That first "
            "request is what a network attacker intercepts."
        ),
        "impact": (
            "An attacker on the same network can strip TLS on the initial request, "
            "downgrade the session, and read or modify traffic that the user believes "
            "is encrypted."
        ),
        "recommendation": (
            "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` on "
            "every HTTPS response. Add `preload` only once you are certain every "
            "subdomain supports HTTPS."
        ),
        "owasp": "A02:2021 - Cryptographic Failures",
        "cwe": "CWE-319",
        "valid_values": ("max-age",),
        "pattern": r"max-age\s*=\s*(?P<age>\d+)",
        "min_max_age": 15_552_000,  # 180 days
        "references": ["https://owasp.org/www-project-secure-headers/"],
    },
    {
        "header": "content-security-policy",
        "title": "Content-Security-Policy is missing",
        "check": "required",
        "severity_missing": Severity.MEDIUM,
        "severity_weak": Severity.MEDIUM,
        "description": (
            "No Content-Security-Policy is set. CSP is the main browser-side defence "
            "against cross-site scripting: without it, any injected script executes "
            "with full access to the page."
        ),
        "impact": (
            "A single reflected or stored XSS becomes fully exploitable - session "
            "theft, credential capture, and actions performed as the victim."
        ),
        "recommendation": (
            "Adopt a policy that at minimum restricts `script-src` and `object-src` to "
            "trusted origins, and avoid `unsafe-inline`/`unsafe-eval`. Roll it out with "
            "`Content-Security-Policy-Report-Only` first to find breakage."
        ),
        "owasp": "A03:2021 - Injection",
        "cwe": "CWE-1021",
        "weak_patterns": (
            (r"unsafe-inline", "the policy allows 'unsafe-inline', which removes most of the XSS protection"),
            (r"unsafe-eval", "the policy allows 'unsafe-eval', which permits dynamic code execution"),
            (r"script-src[^;]*\*", "script-src allows any origin ('*')"),
            (r"default-src[^;]*\*", "default-src allows any origin ('*')"),
        ),
        "references": ["https://developer.mozilla.org/docs/Web/HTTP/CSP"],
    },
    {
        "header": "x-content-type-options",
        "title": "X-Content-Type-Options is missing",
        "check": "value",
        "severity_missing": Severity.LOW,
        "severity_weak": Severity.LOW,
        "pattern": r"^\s*nosniff\s*$",
        "valid_values": ("nosniff",),
        "description": (
            "Without `X-Content-Type-Options: nosniff`, browsers may ignore the "
            "declared Content-Type and guess instead."
        ),
        "impact": (
            "A file the server intends as data can be interpreted as script or HTML, "
            "turning an upload or download endpoint into a scripting vector."
        ),
        "recommendation": "Send `X-Content-Type-Options: nosniff` on every response.",
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-430",
        "references": ["https://owasp.org/www-project-secure-headers/"],
    },
    {
        "header": "x-frame-options",
        "title": "X-Frame-Options is missing",
        "check": "weak",
        "severity_missing": Severity.LOW,
        "severity_weak": Severity.LOW,
        "description": (
            "The response has no X-Frame-Options and, if CSP is also absent or lacks "
            "frame-ancestors, the page can be framed by any site."
        ),
        "impact": (
            "An attacker can overlay the page in an invisible frame and trick a "
            "logged-in user into clicking controls they cannot see (clickjacking)."
        ),
        "recommendation": (
            "Send `X-Frame-Options: DENY` (or `SAMEORIGIN`), or set "
            "`frame-ancestors 'none'` in Content-Security-Policy, which supersedes it."
        ),
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-1021",
        "valid_values": ("deny", "sameorigin"),
        "references": ["https://owasp.org/www-community/attacks/Clickjacking"],
    },
    {
        "header": "referrer-policy",
        "title": "Referrer-Policy is missing",
        "check": "required",
        "severity_missing": Severity.LOW,
        "severity_weak": Severity.LOW,
        "description": (
            "No Referrer-Policy is set, so browsers fall back to their default, which "
            "can leak the full URL of this page - including query parameters - to "
            "third-party sites."
        ),
        "impact": (
            "Sensitive values that live in URLs (tokens, identifiers, search terms) "
            "are disclosed to external origins through the Referer header."
        ),
        "recommendation": (
            "Send `Referrer-Policy: strict-origin-when-cross-origin` or "
            "`no-referrer`, whichever suits the application."
        ),
        "owasp": "A01:2021 - Broken Access Control",
        "cwe": "CWE-200",
        "references": ["https://developer.mozilla.org/docs/Web/HTTP/Headers/Referrer-Policy"],
    },
    {
        "header": "permissions-policy",
        "title": "Permissions-Policy is missing",
        "check": "required",
        "severity_missing": Severity.INFO,
        "severity_weak": Severity.INFO,
        "description": (
            "No Permissions-Policy is set, so powerful browser features (camera, "
            "microphone, geolocation) are governed only by the browser default."
        ),
        "impact": (
            "Embedded or injected content may be able to request capabilities the "
            "application never intended to expose."
        ),
        "recommendation": (
            "Send a Permissions-Policy that disables everything the application does "
            "not need, for example `geolocation=(), camera=(), microphone=()`."
        ),
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-693",
        "references": ["https://developer.mozilla.org/docs/Web/HTTP/Headers/Permissions-Policy"],
    },
    {
        "header": "cross-origin-opener-policy",
        "title": "Cross-Origin-Opener-Policy is missing",
        "check": "required",
        "severity_missing": Severity.INFO,
        "severity_weak": Severity.INFO,
        "description": (
            "Cross-Origin-Opener-Policy is not set, so this document may share a "
            "browsing context group with cross-origin windows it opens or is opened by."
        ),
        "impact": (
            "A cross-origin opener can retain a reference to this window and observe "
            "some of its state, weakening isolation between origins."
        ),
        "recommendation": "Send `Cross-Origin-Opener-Policy: same-origin`.",
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-346",
        "references": ["https://developer.mozilla.org/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy"],
    },
    {
        "header": "cross-origin-resource-policy",
        "title": "Cross-Origin-Resource-Policy is missing",
        "check": "required",
        "severity_missing": Severity.INFO,
        "severity_weak": Severity.INFO,
        "description": (
            "Cross-Origin-Resource-Policy is not set, so responses can be embedded by "
            "any origin."
        ),
        "impact": (
            "Cross-origin sites can load this resource, which enables side-channel "
            "inference (for example via timing or size) about its contents."
        ),
        "recommendation": "Send `Cross-Origin-Resource-Policy: same-origin` for private resources.",
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-346",
        "references": ["https://developer.mozilla.org/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy"],
    },
    {
        "header": "x-permitted-cross-domain-policies",
        "title": "X-Permitted-Cross-Domain-Policies is missing",
        "check": "required",
        "severity_missing": Severity.INFO,
        "severity_weak": Severity.INFO,
        "description": (
            "X-Permitted-Cross-Domain-Policies is not set, so legacy Adobe Flash and "
            "PDF clients may load cross-domain policy files by default."
        ),
        "impact": (
            "Mostly relevant to legacy clients, but it is a cheap hardening header "
            "with no compatibility cost."
        ),
        "recommendation": "Send `X-Permitted-Cross-Domain-Policies: none`.",
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-693",
        "references": ["https://owasp.org/www-project-secure-headers/"],
    },
)

# Informational headers whose presence is worth reporting but never scored as a gap.
INFORMATIONAL_HEADERS: tuple[tuple[str, str], ...] = (
    ("server", "Server banner is disclosed"),
    ("x-powered-by", "Technology stack is disclosed via X-Powered-By"),
    ("x-aspnet-version", "ASP.NET version is disclosed"),
    ("x-aspnetmvc-version", "ASP.NET MVC version is disclosed"),
    ("x-generator", "Generator is disclosed"),
    ("x-drupal-cache", "Drupal is disclosed"),
)

# Headers that are actively harmful when present.
#
# CORS is deliberately absent: `analyze_cors` owns that assessment now, because doing it
# properly needs a second probe with a different Origin to tell a fixed allowlist value
# apart from a reflection. Keeping a weaker version of the check here would report the same
# misconfiguration twice, at two different severities.
ATTACKER_HEADERS: tuple[tuple[str, Severity, str, str], ...] = (
    (
        "x-frame-options",
        Severity.MEDIUM,
        "X-Frame-Options is set to ALLOWALL",
        "X-Frame-Options: ALLOWALL explicitly permits framing by any origin.",
    ),
)

CSP_FRAME_ANCESTORS = r"frame-ancestors"


def severity_from_str(value: str) -> Severity:
    try:
        return Severity(value)
    except ValueError:
        return Severity.INFO


__all__ = [
    "ATTACKER_HEADERS",
    "CSP_FRAME_ANCESTORS",
    "HEADER_SPECS",
    "INFORMATIONAL_HEADERS",
    "HeaderSpec",
    "header_evidence",
    "make_finding",
    "severity_from_str",
]
