"""``check_tls``: inspect the TLS configuration of an in-scope HTTPS URL.

One handshake, then report what the transport actually negotiated and what the certificate
actually says. Three findings can come out of it:

* an **obsolete protocol** (SSLv2/SSLv3/TLS 1.0/1.1) was negotiated;
* the certificate is **close to expiry**, or already expired;
* the certificate is **self-signed**, which for a public hostname means clients cannot
  authenticate it.

Two things this tool deliberately does *not* do:

* It does not attempt to connect to an ``http://`` URL over TLS. Silently upgrading the
  scheme would mean contacting an endpoint the caller did not name, and the operator did not
  authorise. It reports that there is no TLS to inspect instead.
* It does not enumerate cipher suites or drive a downgrade. That requires a TLS client of
  its own rather than the HTTP transport's connection, and it is a genuinely active
  technique. It is listed in the roadmap, not built here.
"""

from __future__ import annotations

import datetime as _dt
import re
from email.utils import parsedate_to_datetime

from app.models.finding import Confidence, Evidence, Finding, FindingCategory, Severity
from app.models.tools import CertificateInfo, CheckTlsData, CheckTlsRequest
from app.tools.base import ToolOutcome, ok
from app.tools.findings import make_finding
from app.tools.http_client import EgressDenied, HttpExchange
from app.tools.shared import require_in_scope

# Protocols that are no longer considered secure. Kept for documentation and for the report
# text; the matching itself goes through `_normalize_protocol`, because the same version is
# spelled several ways in the wild.
OBSOLETE_PROTOCOLS: frozenset[str] = frozenset(
    {"sslv2", "sslv3", "tlsv1", "tlsv1.0", "tls 1.0", "tls1", "tls 1"}
)

# A certificate that expires inside this window is worth flagging even though it is still
# valid, because it means an outage is scheduled.
DEFAULT_WARN_DAYS = 21

_SUBJECT_CN = re.compile(r"commonName=([^,]+)", re.IGNORECASE)
_SUBJECT_O = re.compile(r"organizationName=([^,]+)", re.IGNORECASE)


def check_tls(ctx, request: CheckTlsRequest) -> ToolOutcome:
    """Inspect TLS for one in-scope URL."""
    decision = require_in_scope(ctx, request.url)

    from urllib.parse import urlsplit

    parts = urlsplit(decision.url)
    scheme = (parts.scheme or "").lower()

    if scheme != "https":
        data = CheckTlsData(
            url=decision.url,
            scheme=scheme or "http",
            used_https=False,
            grade="unknown",
            notes=[
                "The URL uses plain HTTP, so there is no TLS session to inspect. The harness "
                "does not upgrade the scheme on its own: that would contact an endpoint the "
                "caller did not name. Use check_headers on the https:// URL instead if you "
                "want to know whether HTTPS is offered."
            ],
        )
        return ok(
            f"{decision.url} is served over plain HTTP, so there is no TLS configuration to "
            "inspect. Nothing was requested over TLS, and the scheme was not upgraded.",
            data,
        )

    try:
        exchange = ctx.http.request(
            decision.url, method="GET", follow_redirects=True, read_body=False
        )
    except EgressDenied as exc:
        from app.tools.base import ToolExecutionError

        raise ToolExecutionError(f"request refused by the scope guard: {exc.reason}") from exc

    tls = exchange.tls or {}
    protocol = str(tls.get("protocol") or "")
    cipher = str(tls.get("cipher") or "")
    certificate = _certificate_from(tls, request.warn_days)

    notes: list[str] = []
    if tls.get("note"):
        notes.append(str(tls["note"]))
    if not protocol and not certificate.available:
        notes.append(
            "The installed HTTP transport did not expose the TLS session, so protocol and "
            "certificate details could not be read. Reachability over HTTPS was still "
            "confirmed by the successful request."
        )
    if exchange.error:
        notes.append(f"request note: {exchange.error}")

    protocol_obsolete = _is_obsolete(protocol)
    grade = _grade(protocol, certificate, protocol_obsolete, exchange)

    data = CheckTlsData(
        url=decision.url,
        final_url=exchange.final_url,
        scheme=scheme,
        used_https=True,
        protocol=protocol,
        cipher=cipher,
        protocol_obsolete=protocol_obsolete,
        certificate_verified=bool(tls.get("certificate_verified", True)),
        certificate=certificate,
        grade=grade,
        notes=notes,
    )

    findings = _findings_for(data, exchange)

    pieces = [f"{decision.url} completed a TLS handshake"]
    if protocol:
        pieces.append(f"using {protocol}")
    if cipher:
        pieces.append(f"with cipher {cipher}")
    pieces.append(f"(HTTP {exchange.status_code})")
    if certificate.available:
        pieces.append(f"Certificate expires {certificate.not_after or 'unknown'}")
        if certificate.days_until_expiry is not None:
            pieces.append(f"({certificate.days_until_expiry} days)")
    else:
        pieces.append("Certificate details were not exposed by the transport")
    pieces.append(f"Grade {grade}.")
    return ok(" ".join(pieces), data, findings=findings, notes=notes)


# --------------------------------------------------------------------------- #
# Certificate handling
# --------------------------------------------------------------------------- #


def _certificate_from(tls: dict, warn_days: int) -> CertificateInfo:
    """Build the certificate view, computing expiry when the dates are parseable."""
    if not tls.get("subject") and not tls.get("not_after"):
        return CertificateInfo(available=False)

    subject = str(tls.get("subject") or "")
    issuer = str(tls.get("issuer") or "")
    not_after = str(tls.get("not_after") or "")

    days: int | None = None
    expiry = _parse_certificate_date(not_after)
    if expiry is not None:
        days = (expiry - _dt.datetime.now(_dt.UTC)).days

    return CertificateInfo(
        available=True,
        subject=subject[:1000],
        issuer=issuer[:1000],
        not_before=str(tls.get("not_before") or "")[:64],
        not_after=not_after[:64],
        days_until_expiry=days,
        subject_alt_names=[str(name)[:200] for name in (tls.get("subject_alt_names") or [])][:50],
        self_signed=bool(subject) and subject == issuer,
    )


def _parse_certificate_date(value: str) -> _dt.datetime | None:
    """Parse the several date formats different TLS stacks report.

    OpenSSL (Python's default) uses ``Sep  1 12:00:00 2026 GMT``; some stacks report RFC 2822
    or ISO 8601. A date we cannot parse yields ``None``, which downgrades the report to
    "unknown" rather than guessing an expiry.
    """
    text = value.strip()
    if not text:
        return None

    # OpenSSL's format, e.g. 'Sep  1 12:00:00 2026 GMT'. Note the double space for
    # single-digit days, which strptime tolerates via %d only with a padded value.
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y", "%Y%m%d%H%M%SZ"):
        try:
            return _dt.datetime.strptime(text, fmt).replace(tzinfo=_dt.UTC)
        except ValueError:
            continue

    # Tolerate the unpadded day OpenSSL actually emits.
    collapsed = " ".join(text.split())
    try:
        return _dt.datetime.strptime(collapsed, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=_dt.UTC)
    except ValueError:
        pass

    try:
        return parsedate_to_datetime(text).astimezone(_dt.UTC)
    except (TypeError, ValueError):
        pass

    try:
        return _dt.datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(_dt.UTC)
    except ValueError:
        return None


def _normalize_protocol(protocol: str) -> str:
    """Reduce a protocol name to a comparable token.

    Stacks spell the same thing several ways: ``TLSv1.0``, ``TLS 1.0``, ``TLSv1_0``,
    ``tls1``. Normalising to lowercase alphanumerics means ``TLSv1.0`` -> ``tlsv10`` and
    ``TLS 1.0`` -> ``tls10``, which still differ - so a leading ``v`` after the family name
    is dropped before comparison, collapsing both to ``tls10``.
    """
    normalized = re.sub(r"[^a-z0-9]", "", protocol.strip().lower())
    # 'tlsv10' -> 'tls10', 'sslv3' -> 'ssl3'. Only the version separator is affected.
    normalized = re.sub(r"^(tls|ssl)v", r"\1", normalized)
    return normalized


# Normalised forms that are no longer considered secure. TLS 1.0 and 1.1 are both included:
# RFC 8996 deprecates them, and most stacks have already disabled them.
_OBSOLETE_NORMALIZED: frozenset[str] = frozenset(
    {"ssl2", "sslv2", "ssl3", "sslv3", "tls1", "tls10", "tls11", "tlsv1"}
)


def _is_obsolete(protocol: str) -> bool:
    """Whether a negotiated protocol version is deprecated."""
    normalized = _normalize_protocol(protocol)
    if not normalized:
        return False
    return normalized in _OBSOLETE_NORMALIZED


def _grade(
    protocol: str,
    certificate: CertificateInfo,
    protocol_obsolete: bool,
    exchange: HttpExchange,
) -> str:
    if protocol_obsolete:
        return "F"
    if certificate.available and certificate.days_until_expiry is not None:
        if certificate.days_until_expiry < 0:
            return "F"
        if certificate.days_until_expiry <= 7:
            return "D"
        if certificate.days_until_expiry <= DEFAULT_WARN_DAYS:
            return "C"
    if certificate.available and certificate.self_signed:
        return "D"
    if not protocol and not certificate.available:
        return "unknown"
    if not exchange.error and exchange.status_code is not None:
        return "A"
    return "B"


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #


def _findings_for(data: CheckTlsData, exchange: HttpExchange) -> list[Finding]:
    findings: list[Finding] = []
    host = _host_of(data.final_url or data.url)
    url = data.final_url or data.url

    if data.protocol_obsolete:
        findings.append(
            make_finding(
                title=f"Obsolete TLS version negotiated ({data.protocol})",
                category=FindingCategory.TRANSPORT_SECURITY,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                description=(
                    f"The connection to {url} completed using {data.protocol}, which is "
                    "deprecated and no longer considered secure."
                ),
                impact=(
                    "Deprecated TLS versions have known cryptographic weaknesses that can "
                    "allow decryption or tampering with the session."
                ),
                recommendation="Require TLS 1.2 or newer and disable older protocol versions.",
                url=url,
                host=host,
                location="tls.protocol",
                owasp="A02:2021 - Cryptographic Failures",
                cwe="CWE-326",
                evidence=[
                    Evidence(
                        tool="check_tls",
                        url=url,
                        location="tls.protocol",
                        observed=f"{data.protocol} (cipher {data.cipher or 'unknown'})",
                        expected="TLSv1.2 or TLSv1.3",
                    )
                ],
                source_tools=["check_tls"],
                tags=["transport", "tls", "protocol"],
            )
        )

    days = data.certificate.days_until_expiry
    if data.certificate.available and days is not None:
        if days < 0:
            findings.append(
                make_finding(
                    title="TLS certificate has expired",
                    category=FindingCategory.TRANSPORT_SECURITY,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    description=(
                        f"The certificate presented by {host} expired "
                        f"{abs(days)} day(s) ago ({data.certificate.not_after})."
                    ),
                    impact=(
                        "Every client that validates certificates will refuse the connection, "
                        "and users who click through the warning are exposed to interception."
                    ),
                    recommendation="Renew the certificate immediately and automate renewal.",
                    url=url,
                    host=host,
                    location="tls.certificate.expiry",
                    owasp="A02:2021 - Cryptographic Failures",
                    cwe="CWE-298",
                    evidence=[
                        Evidence(
                            tool="check_tls",
                            url=url,
                            location="tls.certificate.not_after",
                            observed=data.certificate.not_after,
                            expected="a validity window covering today",
                        )
                    ],
                    source_tools=["check_tls"],
                    tags=["transport", "tls", "certificate"],
                )
            )
        elif days <= DEFAULT_WARN_DAYS:
            findings.append(
                make_finding(
                    title=f"TLS certificate expires in {days} day(s)",
                    category=FindingCategory.TRANSPORT_SECURITY,
                    severity=Severity.LOW if days > 7 else Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    description=(
                        f"The certificate presented by {host} expires on "
                        f"{data.certificate.not_after}, {days} day(s) from now."
                    ),
                    impact=(
                        "An unrenewed certificate turns into a full outage for every client "
                        "that validates it, and the failure happens at the worst possible "
                        "moment."
                    ),
                    recommendation=(
                        "Renew now, and automate renewal so a missed manual step cannot cause "
                        "an outage."
                    ),
                    url=url,
                    host=host,
                    location="tls.certificate.expiry",
                    owasp="A02:2021 - Cryptographic Failures",
                    cwe="CWE-298",
                    evidence=[
                        Evidence(
                            tool="check_tls",
                            url=url,
                            location="tls.certificate.not_after",
                            observed=f"{data.certificate.not_after} ({days} days)",
                            expected="more than 21 days of remaining validity",
                        )
                    ],
                    source_tools=["check_tls"],
                    tags=["transport", "tls", "certificate"],
                )
            )

    if data.certificate.available and data.certificate.self_signed:
        findings.append(
            make_finding(
                title="TLS certificate is self-signed",
                category=FindingCategory.TRANSPORT_SECURITY,
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                description=(
                    f"The certificate for {host} has an identical subject and issuer, which "
                    "means it is self-signed and no trusted authority vouches for it."
                ),
                impact=(
                    "Clients cannot authenticate the server, so a client that proceeds anyway "
                    "has no protection against an attacker presenting their own certificate. "
                    "If the request succeeded, something in the path is not validating."
                ),
                recommendation=(
                    "Install a certificate from a trusted authority. Self-signed certificates "
                    "belong on internal endpoints whose clients pin them explicitly, not on a "
                    "public hostname."
                ),
                url=url,
                host=host,
                location="tls.certificate.issuer",
                owasp="A02:2021 - Cryptographic Failures",
                cwe="CWE-295",
                evidence=[
                    Evidence(
                        tool="check_tls",
                        url=url,
                        location="tls.certificate",
                        observed=f"subject == issuer == {data.certificate.subject[:200]}",
                        expected="issued by a publicly trusted authority",
                    )
                ],
                source_tools=["check_tls"],
                tags=["transport", "tls", "certificate"],
            )
        )

    if exchange.hops and str(exchange.hops[0].url).lower().startswith("http://"):
        findings.append(
            make_finding(
                title="Plain HTTP was accepted before redirecting to HTTPS",
                category=FindingCategory.TRANSPORT_SECURITY,
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                description=(
                    f"The first request to {exchange.hops[0].url} was answered over plain HTTP "
                    "and only then redirected to HTTPS."
                ),
                impact=(
                    "The initial request and response travel unencrypted, so a network "
                    "attacker can read or alter them before the redirect happens."
                ),
                recommendation=(
                    "Prefer HSTS with a long max-age, and refuse plain HTTP at the listener "
                    "rather than redirecting it."
                ),
                url=exchange.hops[0].url,
                host=host,
                location="tls.transport",
                owasp="A02:2021 - Cryptographic Failures",
                cwe="CWE-319",
                evidence=[
                    Evidence(
                        tool="check_tls",
                        url=exchange.hops[0].url,
                        location="redirect chain",
                        observed=" -> ".join(hop.url for hop in exchange.hops),
                        expected="HTTPS from the first request",
                    )
                ],
                source_tools=["check_tls"],
                tags=["transport", "tls"],
            )
        )

    return findings


def _host_of(url: str) -> str:
    from app.models.finding import Finding

    return Finding.host_of(url)


def common_name(subject: str) -> str:
    """Extract the CN from a flattened distinguished name, for display."""
    match = _SUBJECT_CN.search(subject)
    if match:
        return match.group(1).strip()
    match = _SUBJECT_O.search(subject)
    return match.group(1).strip() if match else ""


__all__ = [
    "DEFAULT_WARN_DAYS",
    "OBSOLETE_PROTOCOLS",
    "_is_obsolete",
    "_parse_certificate_date",
    "check_tls",
    "common_name",
]
