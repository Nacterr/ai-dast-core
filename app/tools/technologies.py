"""``detect_technologies``: fingerprint the stack from one response.

Passive: a single request, then pattern matching over the headers, the cookie names and the
first part of the body. No probing, no version-specific exploit paths.

**A technology match is not a vulnerability.** This tool produces no findings on its own
except a low-severity note about version disclosure, and even that is only raised when a
version number is actually exposed. The point is to inform the *planner*: knowing the stack
changes which of the other tools is worth running, and it makes the report easier to read.

The knowledge base is deliberately small and high-precision. A fingerprint that guesses
wrong is worse than no fingerprint, because the planner will act on it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.models.finding import Confidence, Evidence, Finding, FindingCategory, Severity
from app.models.tools import (
    DetectTechnologiesData,
    DetectTechnologiesRequest,
    TechnologyMatch,
)
from app.tools.base import ToolOutcome, ok
from app.tools.findings import make_finding
from app.tools.http_client import EgressDenied, HttpExchange
from app.tools.shared import require_in_scope

MAX_BODY_SCAN_BYTES = 120_000
_VENDOR_GENERIC = {"", "unknown", "cloudflare", "amazon", "nginx"}


@dataclass(frozen=True)
class Fingerprint:
    """One detection rule."""

    name: str
    category: str
    # Header rules: header name -> pattern that must match the value.
    headers: tuple[tuple[str, str], ...] = ()
    # Cookie names that indicate the technology.
    cookies: tuple[str, ...] = ()
    # Patterns over the first part of the body.
    body: tuple[str, ...] = ()
    # Optional version extraction from a header value.
    version_from_header: tuple[str, str] | None = None
    detail: str = ""
    min_confidence: str = "high"


def _fp(
    name: str,
    category: str,
    *,
    headers: tuple[tuple[str, str], ...] = (),
    cookies: tuple[str, ...] = (),
    body: tuple[str, ...] = (),
    version_from_header: tuple[str, str] | None = None,
    detail: str = "",
    min_confidence: str = "high",
) -> Fingerprint:
    return Fingerprint(
        name=name,
        category=category,
        headers=headers,
        cookies=cookies,
        body=body,
        version_from_header=version_from_header,
        detail=detail,
        min_confidence=min_confidence,
    )


# Header `Server` values are matched as substrings (case-insensitive) for robustness
# against the many ways the same product is spelled.
FINGERPRINTS: tuple[Fingerprint, ...] = (
    # -- servers --------------------------------------------------------- #
    _fp("nginx", "server", headers=(("server", r"nginx"),), version_from_header=("server", r"nginx/([\d.]+)")),
    _fp("Apache HTTP Server", "server", headers=(("server", r"apache"),), version_from_header=("server", r"apache/([\d.]+)")),
    _fp("Microsoft IIS", "server", headers=(("server", r"microsoft-iis"),), version_from_header=("server", r"microsoft-iis/([\d.]+)")),
    _fp("LiteSpeed", "server", headers=(("server", r"litespeed"),)),
    _fp("Caddy", "server", headers=(("server", r"caddy"),)),
    _fp("OpenResty", "server", headers=(("server", r"openresty"),)),
    _fp("gunicorn", "server", headers=(("server", r"gunicorn"),), version_from_header=("server", r"gunicorn/([\d.]+)")),
    _fp("Werkzeug", "server", headers=(("server", r"werkzeug"),), version_from_header=("server", r"werkzeug/([\d.]+)")),
    _fp("uvicorn", "server", headers=(("server", r"uvicorn"),)),
    _fp("Jetty", "server", headers=(("server", r"jetty"),)),
    _fp("Tomcat", "server", headers=(("server", r"tomcat|coyote"),)),
    _fp("Kestrel", "server", headers=(("server", r"kestrel"),)),
    # -- languages and runtimes ----------------------------------------- #
    _fp("PHP", "language", headers=(("x-powered-by", r"php"),), version_from_header=("x-powered-by", r"php/([\d.]+)")),
    _fp("ASP.NET", "framework", headers=(("x-powered-by", r"asp\.net"),), version_from_header=("x-powered-by", r"asp\.net")),
    _fp("ASP.NET MVC", "framework", headers=(("x-aspnetmvc-version", r".+"),), version_from_header=("x-aspnetmvc-version", r"^([\d.]+)$")),
    _fp("Express", "framework", headers=(("x-powered-by", r"express"),)),
    # -- frameworks ------------------------------------------------------ #
    _fp("Django", "framework", cookies=("csrftoken", "sessionid"), body=(r"csrfmiddlewaretoken",), min_confidence="medium", detail="Django defaults for the CSRF and session cookie names"),
    _fp("Ruby on Rails", "framework", cookies=("_rails_session", "_session_id"), body=(r"csrf-param", r"authenticity_token"), min_confidence="medium"),
    _fp("Laravel", "framework", cookies=("laravel_session", "XSRF-TOKEN"), body=(r"laravel",), min_confidence="medium"),
    _fp("Spring Boot", "framework", body=(r"whitelabel error page", r"org\.springframework"), min_confidence="medium"),
    _fp("Next.js", "framework", headers=(("x-powered-by", r"next\.js"),), body=(r"__NEXT_DATA__",), min_confidence="medium"),
    _fp("Nuxt", "framework", body=(r"__NUXT__",), min_confidence="medium"),
    _fp("Flask", "framework", cookies=("session",), headers=(("server", r"werkzeug"),), min_confidence="medium", detail="Werkzeug is Flask's development server"),
    # -- CMS and platforms ----------------------------------------------- #
    _fp("WordPress", "cms", body=(r"/wp-content/", r"/wp-includes/", r'name="generator"\s+content="WordPress'), min_confidence="high"),
    _fp("Drupal", "cms", headers=(("x-generator", r"drupal"),), body=(r"drupal-settings-json", r"/sites/default/files/"), min_confidence="high"),
    _fp("Joomla", "cms", body=(r"/media/jui/", r'content="Joomla'), min_confidence="medium"),
    _fp("Ghost", "cms", body=(r'content="Ghost', r"/assets/built/"), min_confidence="medium"),
    _fp("Shopify", "cms", headers=(("x-shopid", r".+"),), body=(r"cdn\.shopify\.com",), min_confidence="medium"),
    _fp("Magento", "cms", cookies=("frontend",), body=(r"/static/version\d+/frontend/", r"Magento"), min_confidence="medium"),
    # -- CDN and edge ----------------------------------------------------- #
    _fp("Cloudflare", "cdn", headers=(("cf-ray", r".+"), ("server", r"cloudflare")), min_confidence="high"),
    _fp("Amazon CloudFront", "cdn", headers=(("x-amz-cf-id", r".+"), ("via", r"cloudfront")), min_confidence="high"),
    _fp("Fastly", "cdn", headers=(("x-served-by", r"cache-"), ("x-fastly-request-id", r".+")), min_confidence="high"),
    _fp("Akamai", "cdn", headers=(("x-akamai-transformed", r".+"), ("server", r"akamaighost")), min_confidence="high"),
    _fp("Varnish", "cdn", headers=(("x-varnish", r".+"), ("via", r"varnish")), min_confidence="high"),
    # -- analytics and third parties -------------------------------------- #
    _fp("Google Analytics", "analytics", body=(r"google-analytics\.com|googletagmanager\.com",), min_confidence="high"),
    _fp("Google Tag Manager", "analytics", body=(r"googletagmanager\.com/gtm\.js",), min_confidence="high"),
    _fp("Hotjar", "analytics", body=(r"static\.hotjar\.com",), min_confidence="high"),
    _fp("Sentry", "analytics", body=(r"browser\.sentry-cdn\.com|sentry\.io",), min_confidence="high"),
    _fp("Cloudflare Insights", "analytics", body=(r"static\.cloudflareinsights\.com",), min_confidence="high"),
    # -- JavaScript ------------------------------------------------------- #
    _fp("React", "javascript", body=(r"data-reactroot", r"react(?:-dom)?[.\-][\w.]*\.js", r"__REACT_DEVTOOLS"), min_confidence="medium"),
    _fp("Vue.js", "javascript", body=(r"data-v-[0-9a-f]{8}", r"vue(?:\.runtime)?[.\-][\w.]*\.js"), min_confidence="medium"),
    _fp("Angular", "javascript", body=(r"ng-version=", r"angular[.\-][\w.]*\.js"), min_confidence="medium"),
    _fp("jQuery", "javascript", body=(r"jquery[.\-][\d.]+(?:\.min)?\.js",), min_confidence="high"),
    _fp("Bootstrap", "javascript", body=(r"bootstrap[.\-][\d.]+(?:\.min)?\.(?:css|js)",), min_confidence="high"),
    _fp("Tailwind CSS", "javascript", body=(r"tailwind",), min_confidence="low"),
    _fp("Alpine.js", "javascript", body=(r"x-data=", r"alpinejs"), min_confidence="medium"),
    _fp("HTMX", "javascript", body=(r"hx-get=|hx-post=|htmx\.org",), min_confidence="medium"),
)

_VERSION_IN_TEXT = re.compile(r"\b(\d+\.\d+(?:\.\d+)?)\b")


def detect_technologies(ctx, request: DetectTechnologiesRequest) -> ToolOutcome:
    """Fingerprint the stack behind one in-scope URL."""
    decision = require_in_scope(ctx, request.url)

    try:
        exchange = ctx.http.request(decision.url, method="GET", follow_redirects=True)
    except EgressDenied as exc:
        raise _denied(exc) from exc

    headers = exchange.headers or {}
    body = (exchange.body_prefix or "")[:MAX_BODY_SCAN_BYTES]
    cookie_names = _cookie_names(exchange) if request.include_cookies else []

    matches: list[TechnologyMatch] = []
    for fingerprint in FINGERPRINTS:
        match = _evaluate(fingerprint, headers, cookie_names, body)
        if match is not None:
            matches.append(match)

    # De-duplicate by name, keeping the most confident and merging evidence.
    matches = _dedupe(matches)
    matches.sort(key=lambda item: (-_confidence_rank(item.confidence), item.category, item.name))

    version_disclosure = [match for match in matches if match.version]
    findings = _findings_for(matches, exchange, decision.url) if version_disclosure else []

    notes: list[str] = []
    if not matches:
        notes.append(
            "No fingerprints matched. That usually means the server strips identifying headers "
            "and the page is served by a stack this knowledge base does not cover."
        )
    if version_disclosure:
        notes.append(
            f"{len(version_disclosure)} technology match(es) include a version number, which is "
            "reported separately as information disclosure."
        )

    data = DetectTechnologiesData(
        url=decision.url,
        final_url=exchange.final_url,
        status_code=exchange.status_code,
        technologies=matches,
        server=str(headers.get("server", ""))[:200],
        powered_by=str(headers.get("x-powered-by", ""))[:200],
        generator=str(headers.get("x-generator", ""))[:200],
        cookie_names=cookie_names,
        notes=notes,
    )

    if not matches:
        summary = (
            f"No technology fingerprints matched for {exchange.final_url or decision.url} "
            f"(HTTP {exchange.status_code}). A single request was sent."
        )
    else:
        rendered = ", ".join(
            f"{match.name}{' ' + match.version if match.version else ''}" for match in matches[:10]
        )
        summary = (
            f"Fingerprinted {exchange.final_url or decision.url} (HTTP {exchange.status_code}): "
            f"{rendered}. {len(matches)} match(es) from headers, cookies and body patterns. "
            "A technology match is not a vulnerability; it informs which checks are worth running."
        )
    return ok(summary, data, findings=findings, notes=notes)


# --------------------------------------------------------------------------- #
# Matching
# --------------------------------------------------------------------------- #


def _evaluate(
    fingerprint: Fingerprint,
    headers: dict[str, str],
    cookie_names: list[str],
    body: str,
) -> TechnologyMatch | None:
    """Return a match when the fingerprint's rules fire, else ``None``."""
    evidence: list[str] = []

    for header_name, pattern in fingerprint.headers:
        value = str(headers.get(header_name, ""))
        if value and re.search(pattern, value, re.IGNORECASE):
            evidence.append(f"header {header_name}: {value[:120]}")

    if fingerprint.cookies:
        lowered = {name.lower() for name in cookie_names}
        for cookie in fingerprint.cookies:
            if cookie.lower() in lowered:
                evidence.append(f"cookie present: {cookie}")

    for pattern in fingerprint.body:
        if re.search(pattern, body, re.IGNORECASE):
            evidence.append(f"body matched /{pattern}/")
            break

    if not evidence:
        return None

    version = ""
    if fingerprint.version_from_header is not None:
        header_name, pattern = fingerprint.version_from_header
        value = str(headers.get(header_name, ""))
        found = re.search(pattern, value, re.IGNORECASE)
        if found and found.groups():
            version = found.group(1)[:100]
    if not version:
        # Only take a version from the evidence text when the header carried one; guessing
        # from body text produces wrong versions, and a wrong version drives wrong action.
        header_evidence = " ".join(item for item in evidence if item.startswith("header "))
        if header_evidence:
            found = _VERSION_IN_TEXT.search(header_evidence)
            if found:
                version = found.group(1)[:100]

    # A single weak signal is a low-confidence match; several signals raise it.
    confidence = fingerprint.min_confidence
    if len(evidence) >= 2 and confidence != "high":
        confidence = "high" if len(evidence) >= 2 else confidence

    return TechnologyMatch(
        name=fingerprint.name,
        category=fingerprint.category,  # type: ignore[arg-type]
        version=version,
        confidence=confidence,  # type: ignore[arg-type]
        evidence=evidence[:4],
        detail=fingerprint.detail,
    )


def _confidence_rank(value: str) -> int:
    return {"low": 0, "medium": 1, "high": 2}.get(value, 0)


def _dedupe(matches: list[TechnologyMatch]) -> list[TechnologyMatch]:
    best: dict[str, TechnologyMatch] = {}
    for match in matches:
        existing = best.get(match.name.lower())
        if existing is None:
            best[match.name.lower()] = match
            continue
        if _confidence_rank(match.confidence) > _confidence_rank(existing.confidence):
            existing.confidence = match.confidence
        if not existing.version and match.version:
            existing.version = match.version
        for item in match.evidence:
            if item not in existing.evidence:
                existing.evidence.append(item)
    return list(best.values())


def _cookie_names(exchange: HttpExchange) -> list[str]:
    names: list[str] = []
    for raw in exchange.all_set_cookie():
        name = raw.split("=", 1)[0].strip()
        if name and name not in names:
            names.append(name[:100])
    return names[:40]


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #


def _findings_for(
    matches: list[TechnologyMatch], exchange: HttpExchange, requested_url: str
) -> list[Finding]:
    """Raise a low-severity finding when a version number is disclosed.

    Only version disclosure is scored. "This site runs React" is not a security defect, and
    reporting it as one would train the reader to ignore the report.
    """
    url = exchange.final_url or requested_url
    disclosed = [match for match in matches if match.version]
    if not disclosed:
        return []

    components = ", ".join(f"{match.name} {match.version}" for match in disclosed[:8])
    return [
        make_finding(
            title="Software versions are disclosed in HTTP responses",
            category=FindingCategory.INFORMATION_DISCLOSURE,
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            description=(
                f"Responses identify the following component versions: {components}. "
                "Version banners let an attacker skip straight to exploits that match the "
                "software in use."
            ),
            impact=(
                "Reconnaissance is faster and more accurate. This is rarely exploitable on its "
                "own, but it materially shortens the path to a real vulnerability."
            ),
            recommendation=(
                "Remove version strings from `Server` and `X-Powered-By`, and genericise "
                "generator meta tags. Keep the underlying software patched regardless."
            ),
            url=url,
            location="version-disclosure",
            owasp="A05:2021 - Security Misconfiguration",
            cwe="CWE-200",
            evidence=[
                Evidence(
                    tool="detect_technologies",
                    url=url,
                    location="headers-and-body",
                    observed=components,
                    expected="no specific version numbers",
                    raw={"components": [m.name for m in disclosed][:10]},
                )
            ],
            references=[
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01_Information_Gathering/02-Fingerprint_Web_Server"
            ],
            source_tools=["detect_technologies"],
            tags=["recon", "disclosure", "fingerprint"],
        )
    ]


def _denied(exc: EgressDenied):
    from app.tools.base import ToolExecutionError

    return ToolExecutionError(f"request refused by the scope guard: {exc.reason}")


__all__ = ["FINGERPRINTS", "Fingerprint", "detect_technologies"]
