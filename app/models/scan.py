"""Scan-level models: configuration, scope, session state, attack surface, report.

``ScopePolicy`` is deliberately part of the *data* layer rather than buried in the
policy code: the resolved scope is rendered into the report and shown to the AI
planner, so the AI always knows exactly what it is allowed to touch.
"""

from __future__ import annotations

import datetime as _dt
from enum import StrEnum
from typing import Any, ClassVar, Literal

from pydantic import Field, field_validator

from app.models.finding import Finding, Severity
from app.models.tools import StrictModel


class ScanStatus(StrEnum):
    """Lifecycle state of a scan session."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    ABORTED = "aborted"
    FAILED = "failed"


class ScopePolicy(StrictModel):
    """Resolved, immutable target scope for one scan.

    Everything the harness is allowed to contact is described here. The scope guard
    validates every outbound action against this object; nothing else may widen it.
    """

    target: str = Field(description="Primary target URL supplied by the user.")
    allowed_hosts: list[str] = Field(
        description="Exact hostnames and '*.example.com' wildcard patterns that are in scope."
    )
    excluded_hosts: list[str] = Field(
        default_factory=list, description="Hosts and wildcard patterns explicitly denied."
    )
    allowed_ports: list[int] = Field(
        default_factory=lambda: [80, 443],
        description="TCP ports the harness may contact.",
    )
    allowed_schemes: list[str] = Field(
        default_factory=lambda: ["http", "https"],
        description="URL schemes the harness may use.",
    )
    path_prefixes: list[str] = Field(
        default_factory=lambda: ["/"],
        description="URL path prefixes in scope. Empty list means 'any path'.",
    )
    allow_private_addresses: bool = Field(
        default=False,
        description=(
            "Allow RFC1918 / loopback / link-local targets. Requires explicit "
            "operator opt-in because it enables SSRF-style reachability."
        ),
    )
    follow_redirects_out_of_scope: bool = Field(
        default=False,
        description="Never true in the MVP: an out-of-scope redirect is always blocked.",
    )
    max_redirects: int = Field(default=5, ge=0, le=20)
    authorized_by: str = Field(
        default="",
        max_length=200,
        description="Who confirmed authorisation to test this target.",
    )
    authorization_note: str = Field(
        default="",
        max_length=1000,
        description="Free-form note recorded as the audit trail for the authorisation.",
    )
    created_at: str = Field(
        default_factory=lambda: _dt.datetime.now(_dt.UTC).isoformat(timespec="seconds")
    )

    @field_validator("allowed_hosts", "excluded_hosts")
    @classmethod
    def _lowercase_hosts(cls, value: list[str]) -> list[str]:
        return [item.strip().lower() for item in value if item.strip()]

    def as_prompt_block(self) -> str:
        """Render the scope for the AI planner's system prompt."""
        lines = [
            f"- primary target: {self.target}",
            f"- in-scope hosts: {', '.join(self.allowed_hosts)}",
        ]
        if self.excluded_hosts:
            lines.append(f"- out-of-scope hosts: {', '.join(self.excluded_hosts)}")
        lines.append(f"- allowed ports: {', '.join(str(p) for p in self.allowed_ports)}")
        lines.append(f"- allowed schemes: {', '.join(self.allowed_schemes)}")
        if self.path_prefixes and self.path_prefixes != ["/"]:
            lines.append(f"- path prefixes: {', '.join(self.path_prefixes)}")
        lines.append(
            "- private/internal address ranges: "
            + ("ALLOWED" if self.allow_private_addresses else "DENIED")
        )
        lines.append("- out-of-scope redirects: always blocked")
        return "\n".join(lines)


class ScanConfig(StrictModel):
    """Hard resource and behaviour limits for one scan.

    These are enforced by the harness. The AI planner is told about them but can
    never raise them.
    """

    max_steps: int = Field(
        default=24, ge=1, le=200, description="Maximum AI planning steps before forced stop."
    )
    max_tool_calls: int = Field(
        default=80, ge=1, le=1000, description="Maximum tool executions per scan."
    )
    max_pages: int = Field(default=15, ge=1, le=200, description="Maximum distinct pages opened.")
    max_requests: int = Field(
        default=120, ge=1, le=5000, description="Maximum outbound HTTP requests."
    )
    max_exposed_file_checks: int = Field(
        default=40,
        ge=0,
        le=500,
        description=(
            "Maximum well-known-path probes that analyze_exposed_files may spend. Kept "
            "separate from max_requests so that content discovery cannot starve the "
            "passive checks that produce findings."
        ),
    )
    max_depth: int = Field(
        default=2, ge=0, le=10, description="Crawl depth the planner is allowed to request."
    )
    requests_per_second: float = Field(
        default=4.0, gt=0, le=100, description="Global rate limit for outbound requests."
    )
    request_timeout_s: float = Field(
        default=15.0, gt=0, le=120, description="Per-request timeout."
    )
    tool_timeout_s: float = Field(
        default=45.0, gt=0, le=600, description="Per-tool-call wall-clock timeout."
    )
    scan_timeout_s: float = Field(
        default=600.0, gt=0, le=7200, description="Whole-scan wall-clock timeout."
    )
    allow_active_tools: bool = Field(
        default=False,
        description="Allow tools that mutate target state. Off by default in the MVP.",
    )
    require_confirmation: bool = Field(
        default=True, description="Ask the human before any confirming tool runs."
    )
    max_payload_chars: int = Field(
        default=12_000,
        ge=1000,
        le=200_000,
        description="Character budget for one tool result handed to the AI.",
    )
    response_body_limit_bytes: int = Field(
        default=2_000_000,
        ge=10_000,
        le=20_000_000,
        description="Maximum response body the HTTP client will buffer.",
    )
    user_agent: str = Field(
        default="ai-dast-core/0.1 (+authorized-security-testing)",
        max_length=300,
    )


class LinkRecord(StrictModel):
    """Aggregated, de-duplicated link in the attack surface model."""

    url: str
    first_seen_page: str = ""
    in_scope: bool = True
    scope_reason: str = ""
    has_query: bool = False
    query_keys: list[str] = Field(default_factory=list)


class FormRecord(StrictModel):
    """Aggregated form in the attack surface model."""

    action: str
    method: str = "get"
    page_url: str = ""
    in_scope: bool = True
    is_login_form: bool = False
    is_upload_form: bool = False
    has_csrf_token: bool = False
    field_names: list[str] = Field(default_factory=list)
    hints: list[str] = Field(default_factory=list)


class ScriptRecord(StrictModel):
    """Aggregated script in the attack surface model."""

    url: str = ""
    kind: str = "inline"
    in_scope: bool = True
    sha256: str = ""
    length: int = 0
    first_seen_page: str = ""


class HttpExchangeRecord(StrictModel):
    """One HTTP exchange the harness performed, recorded for the result tools.

    This is the harness's own transaction log. It exists so ``get_http_history`` can answer
    "what did we actually request, and what came back?" without re-requesting anything, and
    so the report can show the redirect chains that were followed.
    """

    requested_url: str
    final_url: str = ""
    method: str = "GET"
    status_code: int | None = None
    redirect_chain: list[str] = Field(
        default_factory=list, description="Every hop including the final URL."
    )
    content_type: str = ""
    body_bytes: int = 0
    total_ms: int = Field(default=0, ge=0, description="Sum of the hop durations.")
    error: str = ""
    tool: str = Field(default="", description="Tool that made the request.")
    tool_call_index: int = Field(default=-1, ge=-1)

    @property
    def crossed_scope_boundary(self) -> bool:
        """True when a redirect was refused, so the chain stopped short."""
        return "refused" in self.error.lower() or "blocked" in self.error.lower()


class AttackSurface(StrictModel):
    """Everything discovered about the target so far.

    This is the harness's own structured memory. The AI planner reasons over the
    rendered form of it, but the authoritative copy lives here so reports and
    follow-up logic never depend on the LLM.
    """

    target: str = ""
    pages: dict[str, dict[str, Any]] = Field(
        default_factory=dict, description="page_id -> page facts."
    )
    links: dict[str, LinkRecord] = Field(default_factory=dict, description="url -> record.")
    forms: list[FormRecord] = Field(default_factory=list)
    scripts: dict[str, ScriptRecord] = Field(
        default_factory=dict, description="url or sha256 -> record."
    )
    api_endpoints: list[str] = Field(default_factory=list)
    technologies: list[str] = Field(default_factory=list)
    open_questions: list[str] = Field(
        default_factory=list, description="What the planner still does not know."
    )
    robots: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Structured result of the last read_robots call: well-known files found, "
            "disallow/allow rules, and sitemap entries."
        ),
    )
    http_history: list[HttpExchangeRecord] = Field(
        default_factory=list,
        description="Every HTTP exchange performed, in order. Capped by MAX_HTTP_HISTORY.",
    )
    tested_endpoints: dict[str, list[str]] = Field(
        default_factory=dict,
        description="url -> list of checks or tools executed on this endpoint.",
    )
    facts: list[str] = Field(
        default_factory=list,
        description="Distilled facts observed during the scan (stack, configs, findings).",
    )
    hints: list[str] = Field(
        default_factory=list,
        description="Targeted hints for follow-up planner actions.",
    )

    # Keeps the transaction log bounded: a long scan must not grow without limit.
    MAX_HTTP_HISTORY: ClassVar[int] = 300

    def mark_tested(self, url: str, check: str) -> None:
        """Record that a check or tool was executed on a target URL."""
        if not url:
            return
        checks = self.tested_endpoints.setdefault(url, [])
        if check not in checks:
            checks.append(check)

    def add_fact(self, fact: str) -> None:
        """Record a distilled fact observed by the harness."""
        if not fact or fact in self.facts:
            return
        self.facts.append(fact)
        if len(self.facts) > 25:
            del self.facts[: len(self.facts) - 25]

    def add_hint(self, hint: str) -> None:
        """Record an actionable hint for follow-up testing."""
        if not hint or hint in self.hints:
            return
        self.hints.append(hint)
        if len(self.hints) > 10:
            del self.hints[: len(self.hints) - 10]

    def to_asset_tree(self, findings: list[Any] | None = None) -> dict[str, Any]:
        """Convert attack surface into a hierarchical Asset Tree for graph visualization."""
        findings_map: dict[str, list[dict[str, str]]] = {}

        def _add_f(key: str, entry: dict[str, str]) -> None:
            if not key:
                return
            bucket = findings_map.setdefault(key, [])
            if not any(x["id"] == entry["id"] and x["title"] == entry["title"] for x in bucket):
                bucket.append(entry)

        if findings:
            for f in findings:
                if isinstance(f, dict):
                    f_url = str(f.get("url") or "")
                    f_loc = str(f.get("location") or "")
                    sev = f.get("severity", "medium")
                    sev_str = sev.value if hasattr(sev, "value") else str(sev)
                    title = str(f.get("title", "Vulnerability"))
                    fid = str(f.get("id", ""))
                else:
                    f_url = str(getattr(f, "url", None) or "")
                    f_loc = str(getattr(f, "location", None) or "")
                    sev = getattr(f, "severity", None)
                    sev_str = sev.value if hasattr(sev, "value") else str(sev or "medium")
                    title = str(getattr(f, "title", "Vulnerability"))
                    fid = str(getattr(f, "id", ""))
                entry = {"title": title, "severity": sev_str, "id": fid}
                primary_key = f_url or f_loc or self.target
                _add_f(primary_key, entry)
                if primary_key.endswith("/"):
                    _add_f(primary_key.rstrip("/"), entry)
                elif primary_key == self.target.rstrip("/"):
                    _add_f(primary_key + "/", entry)
                if f_loc and f_loc != primary_key:
                    _add_f(f_loc, entry)

        def _get_tested(u: str) -> list[str]:
            res: list[str] = []
            for k in (u, u.rstrip("/"), (u.rstrip("/") + "/" if u.rstrip("/") == self.target.rstrip("/") else "")):
                if not k:
                    continue
                for t in self.tested_endpoints.get(k, []):
                    if t not in res:
                        res.append(t)
            return res

        def _get_finds(u: str) -> list[dict[str, str]]:
            return list(findings_map.get(u) or findings_map.get(u.rstrip("/")) or [])

        pages_children: list[dict[str, Any]] = []
        for pid, facts in self.pages.items():
            u = str(facts.get("final_url") or facts.get("url") or pid)
            tested = _get_tested(u)
            finds = _get_finds(u)
            status = "vulnerable" if finds else ("tested" if tested else "untested")
            pages_children.append({
                "name": u.split("://", 1)[-1] if "://" in u else u,
                "url": u,
                "type": "page",
                "title": facts.get("title", ""),
                "status": status,
                "tested": tested,
                "findings": finds,
            })

        apis_children: list[dict[str, Any]] = []
        for api_url in self.api_endpoints:
            tested = _get_tested(api_url)
            finds = _get_finds(api_url)
            status = "vulnerable" if finds else ("tested" if tested else "untested")
            apis_children.append({
                "name": api_url.split("://", 1)[-1] if "://" in api_url else api_url,
                "url": api_url,
                "type": "api",
                "status": status,
                "tested": tested,
                "findings": finds,
            })

        forms_children: list[dict[str, Any]] = []
        for form in self.forms:
            action = form.action or "current_page"
            tested = _get_tested(action)
            finds = _get_finds(action)
            status = "vulnerable" if finds else ("tested" if tested else "untested")
            forms_children.append({
                "name": f"{form.method.upper()} {action}",
                "url": action,
                "type": "form",
                "fields": form.field_names,
                "status": status,
                "tested": tested,
                "findings": finds,
            })

        opened_set = {c["url"].rstrip("/") for c in pages_children}
        untested_urls = [
            u for u in self.in_scope_urls(30)
            if not _get_tested(u) and u.rstrip("/") not in opened_set
        ]
        untested_children = [
            {
                "name": u.split("://", 1)[-1] if "://" in u else u,
                "url": u,
                "type": "link",
                "status": "vulnerable" if _get_finds(u) else "untested",
                "tested": [],
                "findings": _get_finds(u),
            }
            for u in untested_urls[:15]
        ]

        target_finds = _get_finds(self.target)
        target_tested = _get_tested(self.target)
        target_status = "vulnerable" if target_finds else ("tested" if target_tested else "untested")

        children: list[dict[str, Any]] = []
        if pages_children:
            children.append({"name": f"Trang web đã mở ({len(pages_children)})", "type": "folder", "children": pages_children})
        if apis_children:
            children.append({"name": f"API Endpoints ({len(apis_children)})", "type": "folder", "children": apis_children})
        if forms_children:
            children.append({"name": f"Biểu mẫu Forms ({len(forms_children)})", "type": "folder", "children": forms_children})
        if untested_children:
            children.append({"name": f"Đường dẫn chờ quét ({len(untested_children)})", "type": "folder", "children": untested_children})

        return {
            "name": self.target or "Target",
            "url": self.target,
            "type": "target",
            "status": target_status,
            "tested": target_tested,
            "findings": target_finds,
            "facts": list(self.facts),
            "hints": list(self.hints),
            "children": children,
        }

    def add_link(self, record: LinkRecord) -> bool:
        """Add a link. Returns True when it is new."""
        if record.url in self.links:
            return False
        self.links[record.url] = record
        return True

    def add_script(self, record: ScriptRecord) -> bool:
        key = record.url or record.sha256
        if not key or key in self.scripts:
            return False
        self.scripts[key] = record
        return True

    def record_exchange(self, record: HttpExchangeRecord) -> None:
        """Append an HTTP exchange, evicting the oldest when the cap is reached."""
        self.http_history.append(record)
        if len(self.http_history) > self.MAX_HTTP_HISTORY:
            del self.http_history[: len(self.http_history) - self.MAX_HTTP_HISTORY]

    def redirect_chains(self, *, min_hops: int = 2) -> list[HttpExchangeRecord]:
        """Exchanges that actually followed a redirect."""
        return [entry for entry in self.http_history if len(entry.redirect_chain) >= min_hops]

    def in_scope_urls(self, limit: int = 50) -> list[str]:
        urls = [link.url for link in self.links.values() if link.in_scope]
        return urls[:limit]

    def to_prompt_block(self, max_items: int = 25) -> str:
        """Compact, bounded rendering of the surface for the AI planner."""
        lines: list[str] = [f"Target: {self.target}", f"Pages opened: {len(self.pages)}"]
        scoped = self.in_scope_urls(max_items)
        lines.append(f"Known in-scope URLs ({len(self.links)} total, showing {len(scoped)}):")
        lines.extend(f"  - {url}" for url in scoped)
        if self.forms:
            lines.append(f"Forms discovered: {len(self.forms)}")
            for form in self.forms[:10]:
                lines.append(
                    f"  - {form.method.upper()} {form.action} "
                    f"(fields: {', '.join(form.field_names[:8]) or 'none'})"
                )
        if self.api_endpoints:
            lines.append(f"API-looking endpoints: {len(self.api_endpoints)}")
            lines.extend(f"  - {url}" for url in self.api_endpoints[:10])
        if self.technologies:
            lines.append(f"Technologies: {', '.join(self.technologies[:15])}")
        if self.robots:
            discovered = self.robots.get("discovered_paths") or []
            if discovered:
                lines.append(
                    f"Paths disclosed by robots.txt/sitemap ({len(discovered)}, "
                    f"showing {min(8, len(discovered))}):"
                )
                lines.extend(f"  - {url}" for url in discovered[:8])
        if self.http_history:
            lines.append(f"HTTP exchanges recorded: {len(self.http_history)}")
        if self.facts:
            lines.append(f"Observed Facts ({len(self.facts)}):")
            lines.extend(f"  * {f}" for f in self.facts[-6:])
        if self.hints:
            lines.append(f"Investigation Hints ({len(self.hints)}):")
            lines.extend(f"  ! {h}" for h in self.hints[-4:])
        if self.tested_endpoints:
            tested_count = len(self.tested_endpoints)
            lines.append(f"Endpoints Already Tested ({tested_count}):")
            for u, checks in list(self.tested_endpoints.items())[:6]:
                lines.append(f"  v {u} (tested: {', '.join(checks[:4])})")
        return "\n".join(lines)


class ToolCallRecord(StrictModel):
    """Full audit-trail entry for one tool execution."""

    index: int = Field(ge=0, description="Position in the scan trace.")
    step: int = Field(default=0, ge=0, description="AI planning step that requested it.")
    tool: str
    args: dict[str, Any] = Field(default_factory=dict)
    reason: str = ""
    status: str = "ok"
    summary: str = ""
    error: str | None = None
    denial_reason: str | None = None
    duration_ms: int = 0
    findings_count: int = 0
    artifacts: list[str] = Field(default_factory=list)
    started_at: str = Field(
        default_factory=lambda: _dt.datetime.now(_dt.UTC).isoformat(timespec="seconds")
    )


class ScanSession(StrictModel):
    """Mutable state of one scan run."""

    scan_id: str
    status: ScanStatus = ScanStatus.PENDING
    scope: ScopePolicy
    config: ScanConfig
    surface: AttackSurface = Field(default_factory=AttackSurface)
    findings: list[Finding] = Field(default_factory=list)
    trace: list[ToolCallRecord] = Field(default_factory=list)
    started_at: str = Field(
        default_factory=lambda: _dt.datetime.now(_dt.UTC).isoformat(timespec="seconds")
    )
    finished_at: str | None = None
    stop_reason: str = ""
    counters: dict[str, int] = Field(default_factory=dict)
    planner_notes: list[str] = Field(
        default_factory=list, description="Short running notes emitted by the AI planner."
    )

    def add_trace(self, record: ToolCallRecord) -> None:
        self.trace.append(record)

    def next_tool_index(self) -> int:
        return len(self.trace)


class SeverityCounts(StrictModel):
    """Severity histogram used in reports."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0

    @classmethod
    def from_findings(cls, findings: list[Finding]) -> SeverityCounts:
        counts = cls()
        for finding in findings:
            match finding.severity:
                case Severity.CRITICAL:
                    counts.critical += 1
                case Severity.HIGH:
                    counts.high += 1
                case Severity.MEDIUM:
                    counts.medium += 1
                case Severity.LOW:
                    counts.low += 1
                case _:
                    counts.info += 1
        return counts

    @property
    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low + self.info


class ScanReport(StrictModel):
    """Final, self-contained JSON report. This is the primary deliverable."""

    report_version: str = "1.0"
    generator: str = "ai-dast-core"
    scan_id: str
    target: str
    status: ScanStatus
    started_at: str
    finished_at: str | None = None
    duration_s: float = Field(default=0.0, ge=0)
    authorization: dict[str, Any] = Field(default_factory=dict)
    scope: ScopePolicy
    config: ScanConfig
    planner: dict[str, Any] = Field(
        default_factory=dict, description="Planner identity and stop reason."
    )
    summary: str = Field(default="", description="Executive summary written by the planner.")
    severity_counts: SeverityCounts = Field(default_factory=SeverityCounts)
    findings: list[Finding] = Field(default_factory=list)
    merged_observations: list[dict[str, Any]] = Field(
        default_factory=list,
        description=(
            "Findings that collapsed more than one observation, with the number of "
            "observations behind each. Explains how much repetition deduplication removed."
        ),
    )
    attack_surface: dict[str, Any] = Field(default_factory=dict)
    checks_executed: list[str] = Field(
        default_factory=list, description="Tools that actually ran successfully."
    )
    checks_skipped: list[dict[str, str]] = Field(
        default_factory=list, description="Tools that were denied or failed, with reasons."
    )
    tool_trace: list[ToolCallRecord] = Field(default_factory=list)
    counters: dict[str, int] = Field(default_factory=dict)
    stop_reason: str = ""
    limitations: list[str] = Field(default_factory=list)
    disclaimer: str = Field(
        default=(
            "This report was produced by an automated, scope-restricted DAST harness. "
            "It is not a substitute for a manual penetration test. Only scan systems you "
            "are authorised to test."
        )
    )


class PlannerDecision(StrictModel):
    """One decision emitted by the AI planner.

    ``action`` controls the loop: call a tool, or stop. The planner cannot express
    any other kind of action, which is what keeps the AI inside the tool surface.
    """

    action: Literal["tool", "finish"] = Field(
        default="finish", description="Either run one tool or end the scan."
    )
    thought: str = Field(default="", max_length=2000, description="Planner reasoning summary.")
    tool: str = Field(default="", max_length=64, description="Tool to run when action='tool'.")
    args: dict[str, Any] = Field(default_factory=dict, description="Tool arguments.")
    notes: list[str] = Field(default_factory=list, description="Notes to persist on the session.")
    summary: str = Field(
        default="", max_length=4000, description="Executive summary when action='finish'."
    )
