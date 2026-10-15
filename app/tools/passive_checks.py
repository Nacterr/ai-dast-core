"""Passive analysis tools: security headers and cookie attributes.

Both tools make a single, ordinary request to an in-scope URL and then reason about
the response. Neither probes, fuzzes, or varies input, which is why they are
classified as passive: a target cannot distinguish them from a normal visit beyond
the User-Agent.

The findings they produce are derived deterministically from observed response
data. Severity and rationale come from the knowledge base in
:mod:`app.tools.findings`, not from the model.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import re
from http.cookies import SimpleCookie
from urllib.parse import urlsplit

from app.models.finding import Confidence, Evidence, Finding, FindingCategory, Severity
from app.models.tools import (
    CheckCookiesData,
    CheckCookiesRequest,
    CheckHeadersData,
    CheckHeadersRequest,
    CookieRecord,
    CookieSummary,
    HeaderCheck,
    HeaderReport,
)
from app.tools.base import ToolOutcome, ok
from app.tools.findings import (
    ATTACKER_HEADERS,
    HEADER_SPECS,
    INFORMATIONAL_HEADERS,
    HeaderSpec,
    header_evidence,
    make_finding,
)
from app.tools.http_client import EgressDenied, HttpExchange
from app.tools.shared import require_in_scope

VALID_SAME_SITE = {"strict", "lax", "none"}


# --------------------------------------------------------------------------- #
# check_headers
# --------------------------------------------------------------------------- #


def check_headers(ctx, request: CheckHeadersRequest) -> ToolOutcome:
    """Assess HTTP response security headers for one in-scope URL."""
    decision = require_in_scope(ctx, request.url)

    try:
        exchange = ctx.http.request(
            decision.url,
            method=request.method,
            follow_redirects=request.follow_redirects,
        )
    except EgressDenied as exc:
        raise _egress_error(exc) from exc

    report = _build_header_report(decision.url, exchange)
    findings = _header_findings(report, exchange, request.method)

    data = CheckHeadersData(
        reports=[report],
        total_missing=report.missing_count,
        total_weak=report.weak_count,
    )

    if exchange.error and report.status_code is None:
        summary = (
            f"Could not obtain a response from {decision.url}: {exchange.error}. "
            "No header assessment was possible."
        )
    else:
        summary = (
            f"Checked {len(exchange.hops)} response(s) for {report.final_url or decision.url} "
            f"(final HTTP {report.status_code}). Grade {report.grade}. "
            f"{report.missing_count} missing and {report.weak_count} weak "
            f"security header(s) out of {len(HEADER_SPECS)} checked."
        )
        if exchange.error:
            summary += f" Note: {exchange.error}."
    return ok(summary, data, findings=findings)


def _egress_error(exc: EgressDenied) -> Exception:
    from app.tools.base import ToolExecutionError

    return ToolExecutionError(f"request refused by the scope guard: {exc.reason}")


def _build_header_report(url: str, exchange: HttpExchange) -> HeaderReport:
    checks: list[HeaderCheck] = []
    headers = exchange.headers

    for spec in HEADER_SPECS:
        checks.append(_assess_header(spec, headers, exchange.final_url or url))

    # Informational banners.
    for header_name, rationale in INFORMATIONAL_HEADERS:
        value = exchange.header(header_name)
        if value:
            checks.append(
                HeaderCheck(
                    header=header_name,
                    present=True,
                    value=value[:500],
                    severity="info",
                    status="present",
                    rationale=rationale,
                    recommendation=(
                        "Remove or genericise this header so the technology stack is not "
                        "advertised to attackers."
                    ),
                )
            )

    # Actively harmful header values.
    #
    # Only X-Frame-Options: ALLOWALL is handled here. CORS is assessed by `analyze_cors`,
    # which probes with a fixed Origin and distinguishes a fixed allowlist value from a
    # reflection; a weaker check here would double-report the same issue.
    for header_name, severity, title, rationale in ATTACKER_HEADERS:
        value = exchange.header(header_name)
        if not value:
            continue
        if "allowall" in value.lower():
            checks.append(
                HeaderCheck(
                    header=header_name,
                    present=True,
                    value=value[:500],
                    severity=severity.value,
                    status="misconfigured",
                    rationale=rationale,
                    recommendation="Use `DENY` or `SAMEORIGIN` instead of `ALLOWALL`.",
                )
            )

    missing = sum(1 for check in checks if check.status == "missing")
    weak = sum(1 for check in checks if check.status in {"weak", "misconfigured"})

    return HeaderReport(
        url=url,
        final_url=exchange.final_url,
        status_code=exchange.status_code,
        server=exchange.header("server")[:200],
        powered_by=exchange.header("x-powered-by")[:200],
        checks=checks,
        missing_count=missing,
        weak_count=weak,
        grade=_grade(checks),
        redirect_chain=[hop.url for hop in exchange.hops],
    )


def _assess_header(spec: HeaderSpec, headers: dict[str, str], url: str) -> HeaderCheck:
    name = str(spec["header"])
    title = str(spec.get("title", name))
    check_kind = str(spec.get("check", "required"))
    severity_missing = spec.get("severity_missing", Severity.INFO)
    severity_weak = spec.get("severity_weak", severity_missing)
    value = headers.get(name, "")

    if not value:
        return HeaderCheck(
            header=name,
            present=False,
            value="",
            severity=_severity_value(severity_missing),
            status="missing",
            rationale=str(spec.get("description", title)),
            recommendation=str(spec.get("recommendation", "")),
        )

    # Present: decide whether the value is acceptable.
    weak_reason = _weak_reason(spec, value)
    if weak_reason:
        return HeaderCheck(
            header=name,
            present=True,
            value=value[:500],
            severity=_severity_value(severity_weak),
            status="weak",
            rationale=weak_reason,
            recommendation=str(spec.get("recommendation", "")),
        )

    return HeaderCheck(
        header=name,
        present=True,
        value=value[:500],
        severity="info",
        status="present",
        rationale=f"{name} is set with an acceptable value.",
        recommendation="",
    )


def _weak_reason(spec: HeaderSpec, value: str) -> str:
    """Return why a present header is still inadequate, or an empty string."""
    lowered = value.lower()

    for pattern, reason in spec.get("weak_patterns", ()):  # type: ignore[union-attr]
        if re.search(str(pattern), lowered):
            return str(reason)

    valid_values = spec.get("valid_values")
    if valid_values and str(spec.get("check")) == "weak":
        tokens = {token.strip() for token in lowered.split(",") if token.strip()}
        if tokens and not any(str(valid) in lowered for valid in valid_values):  # type: ignore[union-attr]
            return f"{spec['header']} is set to {value[:120]!r}, which is not a protective value"

    pattern = spec.get("pattern")
    if pattern and not re.search(str(pattern), lowered):
        return f"{spec['header']} is present but its value {value[:120]!r} does not satisfy the expected format"

    min_max_age = spec.get("min_max_age")
    if min_max_age:
        match = re.search(r"max-age\s*=\s*(\d+)", lowered)
        if match:
            age = int(match.group(1))
            if age < int(min_max_age):
                days = age // 86400
                required_days = int(min_max_age) // 86400
                return (
                    f"HSTS max-age is {age}s (~{days} day(s)); at least {required_days} days "
                    "is recommended so the protection survives a browser restart"
                )
        elif "max-age" not in lowered:
            return "HSTS is set without a max-age directive, which browsers ignore"

    return ""


def _severity_value(severity: object) -> str:
    return severity.value if isinstance(severity, Severity) else str(severity)


def _grade(checks: list[HeaderCheck]) -> str:
    """Letter grade driven by the worst gaps, not by a raw count.

    A site missing CSP and HSTS should not score the same as one missing two
    informational headers, so the penalties are severity-weighted.
    """
    penalties = {"critical": 40, "high": 25, "medium": 15, "low": 7, "info": 2}
    score = 100
    for check in checks:
        if check.status in {"missing", "weak", "misconfigured"}:
            score -= penalties.get(check.severity, 2)
    if score >= 90:
        return "A"
    if score >= 78:
        return "B"
    if score >= 62:
        return "C"
    if score >= 45:
        return "D"
    return "F"


def _header_findings(
    report: HeaderReport, exchange: HttpExchange, method: str
) -> list[Finding]:
    findings: list[Finding] = []
    url = report.final_url or report.url
    specs_by_name = {str(spec["header"]): spec for spec in HEADER_SPECS}

    for check in report.checks:
        spec = specs_by_name.get(check.header)

        # A header marked misconfigured is reported even though it is present. The only
        # entry left here is X-Frame-Options: ALLOWALL, because CORS moved to
        # `analyze_cors`, which can tell a reflection from a fixed value.
        if check.status == "misconfigured":
            findings.append(
                make_finding(
                    title=f"{check.header} is misconfigured",
                    category=FindingCategory.SECURITY_HEADERS,
                    severity=Severity(check.severity),
                    confidence=Confidence.HIGH,
                    description=check.rationale,
                    impact="The header provides no protection in its current configuration.",
                    recommendation=check.recommendation,
                    url=url,
                    location=check.header,
                    owasp="A05:2021 - Security Misconfiguration",
                    cwe="CWE-693",
                    evidence=[
                        header_evidence(
                            url=url,
                            header=check.header,
                            observed=check.value,
                            expected="a value that does not permit untrusted origins",
                        )
                    ],
                    source_tools=["check_headers"],
                    tags=["passive", "headers", "misconfiguration"],
                )
            )
            continue

        if spec is not None:
            if check.status in {"missing", "weak"}:
                severity = (
                    spec.get("severity_missing", Severity.INFO)
                    if check.status == "missing"
                    else spec.get("severity_weak", Severity.INFO)
                )
                findings.append(
                    make_finding(
                        title=(
                            str(spec.get("title"))
                            if check.status == "missing"
                            else f"{check.header} is present but weak"
                        ),
                        category=FindingCategory.SECURITY_HEADERS,
                        severity=severity if isinstance(severity, Severity) else Severity.INFO,
                        confidence=Confidence.HIGH,
                        description=(
                            str(spec.get("description", ""))
                            if check.status == "missing"
                            else (check.rationale or str(spec.get("description", "")))
                        ),
                        impact=str(spec.get("impact", "")),
                        recommendation=str(spec.get("recommendation", "")),
                        url=url,
                        location=check.header,
                        owasp=str(spec.get("owasp", "")),
                        cwe=str(spec.get("cwe", "")),
                        evidence=[
                            header_evidence(
                                url=url,
                                header=check.header,
                                observed=(
                                    "(header absent)"
                                    if check.status == "missing"
                                    else check.value
                                ),
                                expected=(
                                    str(spec.get("recommendation", ""))
                                    if check.status == "missing"
                                    else "a protective value"
                                ),
                            )
                        ],
                        references=[str(ref) for ref in spec.get("references", ())],  # type: ignore[union-attr]
                        source_tools=["check_headers"],
                        tags=["passive", "headers", f"http-{method.lower()}"],
                    )
                )
            elif check.status == "misconfigured":
                # Unreachable: misconfigured checks are handled above, before this
                # spec-driven branch. Kept out of the way rather than duplicated.
                continue
        else:
            # Informational banner disclosure.
            if check.header in {name for name, _ in INFORMATIONAL_HEADERS}:
                findings.append(
                    make_finding(
                        title=f"{check.header} discloses server technology",
                        category=FindingCategory.INFORMATION_DISCLOSURE,
                        severity=Severity.INFO,
                        confidence=Confidence.HIGH,
                        description=(
                            f"The response includes `{check.header}: {check.value}`, which "
                            "advertises the software stack to anyone who asks."
                        ),
                        impact=(
                            "Banner information speeds up an attacker's search for known "
                            "vulnerabilities in the specific version in use."
                        ),
                        recommendation=(
                            "Remove the header or replace its value with a generic token."
                        ),
                        url=url,
                        location=check.header,
                        owasp="A05:2021 - Security Misconfiguration",
                        cwe="CWE-200",
                        evidence=[
                            header_evidence(
                                url=url,
                                header=check.header,
                                observed=check.value,
                                expected="(header removed or genericised)",
                            )
                        ],
                        source_tools=["check_headers"],
                        tags=["passive", "headers", "disclosure"],
                    )
                )

    # A redirect chain that starts on HTTP is worth its own finding: it means the
    # first request is made in the clear even if the site redirects afterwards.
    if exchange.hops and exchange.hops[0].url.startswith("http://"):
        findings.append(
            make_finding(
                title="Plain HTTP is accepted and only redirected afterwards",
                category=FindingCategory.TRANSPORT_SECURITY,
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                description=(
                    f"The first request to {exchange.hops[0].url} was answered over plain "
                    "HTTP and only then redirected to HTTPS."
                ),
                impact=(
                    "The initial request and its response travel unencrypted, so a "
                    "network attacker can read or alter them before the redirect happens."
                ),
                recommendation=(
                    "Prefer HSTS with a long max-age and, where possible, refuse plain "
                    "HTTP at the listener rather than redirecting it."
                ),
                url=exchange.hops[0].url,
                location="transport",
                owasp="A02:2021 - Cryptographic Failures",
                cwe="CWE-319",
                evidence=[
                    Evidence(
                        tool="check_headers",
                        url=exchange.hops[0].url,
                        location="redirect chain",
                        observed=" -> ".join(hop.url for hop in exchange.hops),
                        expected="HTTPS from the first request",
                    )
                ],
                source_tools=["check_headers"],
                tags=["passive", "transport"],
            )
        )

    # Report what the transport actually negotiated, if it was HTTPS.
    tls = exchange.tls or {}
    protocol = str(tls.get("protocol") or "")
    if protocol and protocol.upper() in {"TLSV1", "TLSV1.1", "SSLv2", "SSLv3"}:
        findings.append(
            make_finding(
                title=f"Obsolete TLS version negotiated ({protocol})",
                category=FindingCategory.TRANSPORT_SECURITY,
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                description=(
                    f"The connection to {exchange.final_url} completed using {protocol}, "
                    "which is deprecated and no longer considered secure."
                ),
                impact=(
                    "Deprecated TLS versions have known cryptographic weaknesses that can "
                    "allow decryption or tampering with the session."
                ),
                recommendation="Require TLS 1.2 or newer and disable older protocol versions.",
                url=exchange.final_url,
                location="tls",
                owasp="A02:2021 - Cryptographic Failures",
                cwe="CWE-326",
                evidence=[
                    Evidence(
                        tool="check_headers",
                        url=exchange.final_url,
                        location="tls.version",
                        observed=protocol,
                        expected="TLSv1.2 or TLSv1.3",
                    )
                ],
                source_tools=["check_headers"],
                tags=["passive", "transport", "tls"],
            )
        )
    return findings


# --------------------------------------------------------------------------- #
# check_cookies
# --------------------------------------------------------------------------- #

# Cookie names that usually carry session state, used to rank findings.
_SESSION_NAME_HINTS = re.compile(
    r"(?i)(session|sess|sid|auth|token|jwt|login|remember|csrf|xsrf)"
)
# Cookie names that are conventionally not sensitive.
_BENIGN_NAME_HINTS = re.compile(
    r"(?i)^(_ga|_gid|_gat|_fbp|_gcl|__utm|_hj|_clck|_clsk|intercom|amplitude|mp_|ajs_)"
)


def check_cookies(ctx, request: CheckCookiesRequest) -> ToolOutcome:
    """Assess Set-Cookie attribute posture for one in-scope URL."""
    decision = require_in_scope(ctx, request.url)

    try:
        exchange = ctx.http.request(decision.url, method="GET", follow_redirects=True)
    except EgressDenied as exc:
        raise _egress_error(exc) from exc

    records = [
        record
        for raw in exchange.all_set_cookie()
        if (record := _parse_set_cookie(raw, decision.url)) is not None
    ]

    if request.include_browser_cookies and ctx.browser_started:
        records.extend(_browser_cookies(ctx, decision.url))

    records = _dedupe_cookies(records)
    summary_model = CookieSummary(
        url=urlsplit(decision.url).hostname or decision.url,
        final_url=exchange.final_url,
        total=len(records),
        insecure_count=sum(1 for record in records if _needs_secure(record)),
        no_httponly_count=sum(
            1 for record in records if _is_session_cookie(record) and not record.http_only
        ),
        no_samesite_count=sum(1 for record in records if record.same_site == "unspecified"),
        session_cookie_count=sum(1 for record in records if record.expires == "session"),
        cookies=records,
    )

    findings = _cookie_findings(summary_model, exchange)
    data = CheckCookiesData(
        summaries=[summary_model],
        total_cookies=len(records),
        total_issue_count=sum(len(record.issues) for record in records),
    )

    if exchange.error and not exchange.hops:
        summary = f"Could not read cookies from {decision.url}: {exchange.error}."
    else:
        summary = (
            f"Observed {len(records)} cookie(s) for {summary_model.final_url or decision.url}. "
            f"{summary_model.insecure_count} lack the Secure flag, "
            f"{summary_model.no_httponly_count} session cookie(s) lack HttpOnly, and "
            f"{summary_model.no_samesite_count} have no SameSite attribute. "
            "Cookie values are never stored; only their length and a hash are recorded."
        )
    return ok(summary, data, findings=findings)


def _needs_secure(record: CookieRecord) -> bool:
    return not record.secure


def _is_session_cookie(record: CookieRecord) -> bool:
    if _BENIGN_NAME_HINTS.search(record.name):
        return False
    return bool(_SESSION_NAME_HINTS.search(record.name)) or record.expires == "session"


def _parse_set_cookie(raw: str, url: str) -> CookieRecord | None:
    """Parse one ``Set-Cookie`` value into a :class:`CookieRecord`.

    Uses the stdlib parser for the name/value pair and then reads the attributes
    from the raw string, because ``SimpleCookie`` discards attributes we care about
    (and rejects some real-world cookies outright).
    """
    header = raw.strip()
    if not header:
        return None

    name = ""
    value = ""
    try:
        parsed = SimpleCookie()
        parsed.load(header)
        if parsed:
            key = next(iter(parsed))
            name, value = key, parsed[key].value
    except Exception:  # noqa: BLE001 - fall back to manual parsing
        pass

    if not name:
        pair = header.split(";", 1)[0].strip()
        if "=" not in pair:
            return None
        name, value = pair.split("=", 1)
        name, value = name.strip(), value.strip()

    attributes: dict[str, str] = {}
    parts = header.split(";")
    for part in parts[1:]:
        if "=" in part:
            key, _, val = part.partition("=")
            attributes[key.strip().lower()] = val.strip()
        else:
            attributes[part.strip().lower()] = ""

    domain = attributes.get("domain", "")
    path = attributes.get("path", "")
    secure = "secure" in attributes
    http_only = "httponly" in attributes

    same_site_raw = attributes.get("samesite", "").strip().lower()
    same_site = same_site_raw if same_site_raw in VALID_SAME_SITE else "unspecified"

    max_age: int | None = None
    if "max-age" in attributes:
        try:
            max_age = int(attributes["max-age"])
        except ValueError:
            max_age = None

    expires_raw = attributes.get("expires", "")
    expires = "session"
    if max_age is not None:
        if max_age <= 0:
            expires = "expired"
        else:
            expires = (
                _dt.datetime.now(_dt.UTC) + _dt.timedelta(seconds=max_age)
            ).isoformat(timespec="seconds")
    elif expires_raw:
        expires = expires_raw

    prefix: str = "none"
    if name.startswith("__Host-"):
        prefix = "__Host-"
    elif name.startswith("__Secure-"):
        prefix = "__Secure-"

    record = CookieRecord(
        name=name[:200],
        domain=domain[:255],
        path=path[:255] or "/",
        secure=secure,
        http_only=http_only,
        same_site=same_site,  # type: ignore[arg-type]
        expires=expires[:64],
        max_age=max_age,
        prefix=prefix,  # type: ignore[arg-type]
        value_length=len(value),
        value_sha256=hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest(),
        source="header",
        issues=[],
    )
    record.issues = _cookie_issues(record, url)
    return record


def _browser_cookies(ctx, url: str) -> list[CookieRecord]:
    records: list[CookieRecord] = []
    for cookie in ctx.browser.cookies():
        try:
            same_site_raw = str(cookie.get("sameSite", "")).lower()
            same_site = same_site_raw if same_site_raw in VALID_SAME_SITE else "unspecified"
            value = str(cookie.get("value", ""))
            name = str(cookie.get("name", ""))[:200]
            prefix = "none"
            if name.startswith("__Host-"):
                prefix = "__Host-"
            elif name.startswith("__Secure-"):
                prefix = "__Secure-"
            expires_value = cookie.get("expires")
            if expires_value in (None, -1, ""):
                expires = "session"
            else:
                try:
                    expires = _dt.datetime.fromtimestamp(
                        float(expires_value), _dt.UTC
                    ).isoformat(timespec="seconds")
                except (TypeError, ValueError, OSError):
                    expires = "unknown"

            record = CookieRecord(
                name=name,
                domain=str(cookie.get("domain", ""))[:255],
                path=str(cookie.get("path", "/"))[:255] or "/",
                secure=bool(cookie.get("secure", False)),
                http_only=bool(cookie.get("httpOnly", False)),
                same_site=same_site,  # type: ignore[arg-type]
                expires=expires[:64],
                max_age=None,
                prefix=prefix,  # type: ignore[arg-type]
                value_length=len(value),
                value_sha256=hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest(),
                source="browser",
                issues=[],
            )
            record.issues = _cookie_issues(record, url)
            records.append(record)
        except Exception:  # noqa: BLE001
            continue
    return records


def _cookie_issues(record: CookieRecord, url: str) -> list[str]:
    """Attribute-level problems for one cookie."""
    issues: list[str] = []
    is_https = url.lower().startswith("https://")

    if not record.secure:
        issues.append("missing Secure flag: the cookie can be sent over plain HTTP")
    if _is_session_cookie(record) and not record.http_only:
        issues.append("missing HttpOnly flag: JavaScript can read this cookie")
    if record.same_site == "unspecified":
        issues.append("no SameSite attribute: browsers will treat it as Lax by default")
    elif record.same_site == "none" and not record.secure:
        issues.append("SameSite=None without Secure is rejected by modern browsers")

    if record.prefix == "__Host-":
        if not record.secure:
            issues.append("__Host- prefix requires the Secure flag")
        if record.path != "/":
            issues.append("__Host- prefix requires Path=/")
        if record.domain:
            issues.append("__Host- prefix forbids the Domain attribute")
    elif record.prefix == "__Secure-" and not record.secure:
        issues.append("__Secure- prefix requires the Secure flag")

    if record.domain:
        # Any explicit Domain attribute widens the cookie's reach beyond the exact host
        # and lets sibling or parent hosts read and overwrite it.
        issues.append(
            f"explicit Domain={record.domain} widens the cookie beyond this host"
        )
    if record.path == "/" and record.domain == "" and is_https and not record.http_only:
        issues.append("broad scope (Path=/) combined with no HttpOnly")

    if record.max_age is not None and record.max_age >= 31_536_000 and not record.http_only:
        issues.append("lifetime of a year or more without HttpOnly")
    return issues


def _dedupe_cookies(records: list[CookieRecord]) -> list[CookieRecord]:
    """Keep one record per (name, domain, path), preferring the header source."""
    best: dict[tuple[str, str, str], CookieRecord] = {}
    for record in records:
        key = (record.name, record.domain, record.path)
        existing = best.get(key)
        if existing is None or (existing.source == "browser" and record.source == "header"):
            best[key] = record
    return sorted(best.values(), key=lambda item: (item.name.lower(), item.domain, item.path))


def _cookie_findings(summary: CookieSummary, exchange: HttpExchange) -> list[Finding]:
    """Turn cookie attribute problems into a small number of actionable findings.

    Findings are grouped by attribute on the host rather than emitted once per
    cookie: a site with forty session-less cookies should produce one clear finding,
    not forty lines of noise.
    """
    findings: list[Finding] = []
    if not summary.cookies:
        return findings

    host = summary.final_url or summary.url
    secure_missing = [cookie for cookie in summary.cookies if not cookie.secure]
    httponly_missing = [
        cookie for cookie in summary.cookies if _is_session_cookie(cookie) and not cookie.http_only
    ]
    samesite_missing = [cookie for cookie in summary.cookies if cookie.same_site == "unspecified"]
    prefix_violations = [
        cookie
        for cookie in summary.cookies
        if any("prefix" in issue for issue in cookie.issues)
    ]
    broad_domain = [
        cookie for cookie in summary.cookies if any("Domain=" in issue for issue in cookie.issues)
    ]

    if secure_missing:
        findings.append(
            make_finding(
                title=f"{len(secure_missing)} cookie(s) lack the Secure flag",
                category=FindingCategory.COOKIE_SECURITY,
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                description=(
                    "These cookies are not marked Secure, so the browser will include them "
                    "in requests made over plain HTTP."
                ),
                impact=(
                    "A network attacker who can force or observe a plain-HTTP request "
                    "captures the cookie and can replay it to impersonate the user."
                ),
                recommendation=(
                    "Add the `Secure` attribute to every cookie, and serve the application "
                    "over HTTPS only."
                ),
                url=host,
                location="Set-Cookie:Secure",
                owasp="A02:2021 - Cryptographic Failures",
                cwe="CWE-614",
                evidence=[
                    Evidence(
                        tool="check_cookies",
                        url=summary.final_url or summary.url,
                        location="Secure",
                        observed=f"missing on: {', '.join(c.name for c in secure_missing[:10])}",
                        expected="every cookie marked Secure",
                        raw={"count": len(secure_missing)},
                    )
                ],
                references=["https://owasp.org/www-community/controls/SecureCookieAttribute"],
                source_tools=["check_cookies"],
                tags=["passive", "cookies"],
            )
        )

    if httponly_missing:
        findings.append(
            make_finding(
                title=f"{len(httponly_missing)} session cookie(s) lack the HttpOnly flag",
                category=FindingCategory.SESSION_MANAGEMENT,
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                description=(
                    "Session-bearing cookies were returned without HttpOnly, so client-side "
                    "JavaScript can read them via `document.cookie`."
                ),
                impact=(
                    "Any cross-site scripting flaw on the site escalates from script "
                    "execution to full session theft, which is a much more serious outcome."
                ),
                recommendation=(
                    "Add `HttpOnly` to every cookie that carries session or authentication "
                    "state."
                ),
                url=host,
                location="Set-Cookie:HttpOnly",
                owasp="A07:2021 - Identification and Authentication Failures",
                cwe="CWE-1004",
                evidence=[
                    Evidence(
                        tool="check_cookies",
                        url=summary.final_url or summary.url,
                        location="HttpOnly",
                        observed=f"missing on: {', '.join(c.name for c in httponly_missing[:10])}",
                        expected="session cookies marked HttpOnly",
                        raw={"count": len(httponly_missing)},
                    )
                ],
                references=["https://owasp.org/www-community/HttpOnly"],
                source_tools=["check_cookies"],
                tags=["passive", "cookies", "session"],
            )
        )

    if samesite_missing:
        findings.append(
            make_finding(
                title=f"{len(samesite_missing)} cookie(s) have no SameSite attribute",
                category=FindingCategory.CSRF,
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                description=(
                    "These cookies do not declare a SameSite policy, leaving the behaviour "
                    "to the browser default rather than to an explicit decision."
                ),
                impact=(
                    "Cross-site requests may carry the cookie, which weakens the defence "
                    "against cross-site request forgery and cross-site information leaks."
                ),
                recommendation=(
                    "Set `SameSite=Lax` (or `Strict` for high-value cookies) explicitly, so "
                    "the behaviour does not depend on browser defaults."
                ),
                url=host,
                location="Set-Cookie:SameSite",
                owasp="A01:2021 - Broken Access Control",
                cwe="CWE-1275",
                evidence=[
                    Evidence(
                        tool="check_cookies",
                        url=summary.final_url or summary.url,
                        location="SameSite",
                        observed=f"unspecified on: {', '.join(c.name for c in samesite_missing[:10])}",
                        expected="an explicit SameSite policy",
                        raw={"count": len(samesite_missing)},
                    )
                ],
                references=["https://developer.mozilla.org/docs/Web/HTTP/Headers/Set-Cookie/SameSite"],
                source_tools=["check_cookies"],
                tags=["passive", "cookies", "csrf"],
            )
        )

    if prefix_violations:
        findings.append(
            make_finding(
                title="Cookie name prefixes are used incorrectly",
                category=FindingCategory.COOKIE_SECURITY,
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                description=(
                    "The `__Host-` or `__Secure-` prefix is present but the cookie does not "
                    "satisfy the requirements the prefix enforces, so browsers will reject it "
                    "or the intended guarantee does not hold."
                ),
                impact=(
                    "A cookie the developer believes is locked down may be settable or "
                    "overridable by a subdomain, defeating the prefix's purpose."
                ),
                recommendation=(
                    "For `__Host-`: set Secure, Path=/ and no Domain attribute. For "
                    "`__Secure-`: set Secure."
                ),
                url=host,
                location="Set-Cookie:prefix",
                owasp="A05:2021 - Security Misconfiguration",
                cwe="CWE-565",
                evidence=[
                    Evidence(
                        tool="check_cookies",
                        url=summary.final_url or summary.url,
                        location="prefix",
                        observed="; ".join(
                            f"{cookie.name}: {'; '.join(cookie.issues)}"
                            for cookie in prefix_violations[:5]
                        ),
                        expected="prefix requirements satisfied",
                    )
                ],
                source_tools=["check_cookies"],
                tags=["passive", "cookies"],
            )
        )

    if broad_domain:
        findings.append(
            make_finding(
                title="Cookie is scoped to more than the exact host",
                category=FindingCategory.COOKIE_SECURITY,
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                description=(
                    "A cookie is set with an explicit Domain attribute, which sends it to "
                    "every host under that domain rather than only the host that set it."
                ),
                impact=(
                    "Every sibling subdomain - including ones outside this application's "
                    "control - receives the cookie, and any compromised sibling can "
                    "overwrite it (session fixation)."
                ),
                recommendation=(
                    "Omit the Domain attribute so the cookie is host-only, or scope it to the "
                    "narrowest host that needs it."
                ),
                url=host,
                location="Set-Cookie:Domain",
                owasp="A05:2021 - Security Misconfiguration",
                cwe="CWE-565",
                evidence=[
                    Evidence(
                        tool="check_cookies",
                        url=summary.final_url or summary.url,
                        location="Domain",
                        observed="; ".join(
                            f"{cookie.name} domain={cookie.domain}" for cookie in broad_domain[:5]
                        ),
                        expected="host-only cookies",
                    )
                ],
                source_tools=["check_cookies"],
                tags=["passive", "cookies"],
            )
        )

    return findings
