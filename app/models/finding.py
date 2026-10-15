"""Finding model: the unit of security output.

Findings are *derived* deterministically by harness code from tool results. The
AI planner may classify and prioritise findings (severity, confidence, category),
but it can never invent evidence: ``evidence`` always points at a concrete tool
call recorded in the scan trace.
"""

from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import Any

from pydantic import Field

from app.models.tools import StrictModel


class Severity(StrEnum):
    """Impact-oriented severity scale, aligned with common DAST practice."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(StrEnum):
    """How sure the harness is that the finding is real."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class FindingStatus(StrEnum):
    """Lifecycle state after the planner has classified the finding."""

    OPEN = "open"
    TRIAGE = "triage"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"


class FindingCategory(StrEnum):
    """Coarse OWASP-flavoured taxonomy used by the MVP tools."""

    SECURITY_HEADERS = "security_headers"
    COOKIE_SECURITY = "cookie_security"
    TRANSPORT_SECURITY = "transport_security"
    INFORMATION_DISCLOSURE = "information_disclosure"
    CORS = "cors"
    AUTHENTICATION = "authentication"
    SESSION_MANAGEMENT = "session_management"
    INPUT_VALIDATION = "input_validation"
    CSRF = "csrf"
    CONFIGURATION = "configuration"
    OTHER = "other"


SEVERITY_ORDER: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

CONFIDENCE_ORDER: dict[Confidence, int] = {
    Confidence.LOW: 0,
    Confidence.MEDIUM: 1,
    Confidence.HIGH: 2,
}


class Evidence(StrictModel):
    """Traceable proof for a finding.

    ``tool`` and ``tool_call_index`` link the finding to the exact entry in the
    scan trace that produced it, so a human can always reproduce the result.
    """

    tool: str = Field(description="Tool that produced the evidence.")
    tool_call_index: int = Field(default=-1, ge=-1, description="Index in the scan trace.")
    url: str = Field(default="", description="URL the evidence was observed on.")
    location: str = Field(
        default="", description="Sub-location, e.g. header name, cookie name, form action."
    )
    observed: str = Field(default="", max_length=1000, description="What was observed.")
    expected: str = Field(default="", max_length=1000, description="What was expected instead.")
    raw: dict[str, Any] = Field(
        default_factory=dict, description="Small raw excerpt backing the observation."
    )


class Finding(StrictModel):
    """One security finding.

    Stable identity is ``category + host + location``. ``host`` - not the full URL -
    is the unit of identity, because the vast majority of configuration findings (a
    missing security header, a weak cookie flag, a broken CORS policy) are properties
    of the origin, not of one path. Using the full URL would report "CSP missing" once
    per page and bury the real issues in repetition. Per-URL observations are preserved
    as separate evidence entries, so nothing is lost.
    """

    id: str = Field(description="Stable id, derived from dedup_key.")
    title: str = Field(max_length=300, description="Human-readable title.")
    category: FindingCategory = Field(default=FindingCategory.OTHER)
    severity: Severity = Field(default=Severity.INFO)
    confidence: Confidence = Field(default=Confidence.MEDIUM)
    description: str = Field(default="", max_length=4000, description="What and why.")
    impact: str = Field(default="", max_length=2000, description="Concrete impact.")
    recommendation: str = Field(default="", max_length=2000, description="How to fix it.")
    url: str = Field(default="", description="Primary URL for the finding.")
    host: str = Field(
        default="",
        max_length=255,
        description="Host the finding belongs to; the unit of finding identity.",
    )
    location: str = Field(default="", max_length=300, description="Header, cookie, form, ...")
    owasp: str = Field(default="", max_length=100, description="OWASP Top 10 mapping, if known.")
    cwe: str = Field(default="", max_length=100, description="CWE id, if known.")
    cvss_vector: str = Field(default="", max_length=200, description="Optional CVSS vector.")
    evidence: list[Evidence] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    source_tools: list[str] = Field(
        default_factory=list, description="Tools that contributed to this finding."
    )
    duplicate_of: str | None = Field(
        default=None, description="Set by deduplicate_findings to the canonical finding id."
    )
    merged_from: int = Field(
        default=1,
        ge=1,
        description=(
            "How many raw observations were folded into this finding during "
            "deduplication. 1 means it was observed once."
        ),
    )
    ai_notes: str = Field(
        default="", max_length=2000, description="Planner commentary, never the sole evidence."
    )
    tags: list[str] = Field(default_factory=list)

    @staticmethod
    def host_of(url: str) -> str:
        """Extract the identity host from a URL.

        Scheme and port are excluded on purpose: the same host reached over http and
        https, or on a non-default port, is one origin from a remediation standpoint.
        """
        raw = str(url or "").strip()
        if not raw:
            return ""
        candidate = raw if "//" in raw else f"//{raw}"
        try:
            from urllib.parse import urlsplit

            host = urlsplit(candidate).hostname or ""
        except ValueError:
            return ""
        return host.strip().lower()[:255]

    @staticmethod
    def compute_dedup_key(
        category: FindingCategory | str,
        location: str,
        host: str = "",
        title: str = "",
    ) -> str:
        """Derive the stable identity of a finding.

        Identity is intentionally coarse: the same missing header on the same host is
        one finding no matter which path, which tool, or which query string it was seen
        on.
        """
        category_value = category.value if isinstance(category, FindingCategory) else str(category)
        location_key = (location or title).strip().lower()
        host_key = str(host or "").strip().lower()
        raw = f"{category_value}|{host_key}|{location_key}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    @staticmethod
    def compute_id(dedup_key: str) -> str:
        return f"F-{dedup_key[:12]}"

    def refresh_host(self) -> Finding:
        """Backfill :attr:`host` from :attr:`url` when it is missing, and re-id."""
        if not self.host and self.url:
            self.host = self.host_of(self.url)
        if not self.host:
            for evidence in self.evidence:
                derived = self.host_of(evidence.url)
                if derived:
                    self.host = derived
                    break
        return self

    def dedup_key(self) -> str:
        self.refresh_host()
        return self.compute_dedup_key(self.category, self.location, self.host, self.title)


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Sort findings by severity, then confidence, then title."""

    return sorted(
        findings,
        key=lambda f: (
            -SEVERITY_ORDER.get(f.severity, 0),
            -CONFIDENCE_ORDER.get(f.confidence, 0),
            f.title.lower(),
        ),
    )
