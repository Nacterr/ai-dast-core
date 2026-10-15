"""HTTP API request/response contracts.

The API has a fundamentally different threat model from the CLI and the models reflect
that. On the command line the human *is* the operator: they choose the scope, the
budgets and the authorisation record, and everything they type is trusted.

Over HTTP the caller is **untrusted**. A caller supplies a target, some budget numbers
and an authorisation string. Everything else is decided by the operator at deployment
time and is not expressible in a request at all:

* the allowlist of hosts that may ever be scanned;
* whether private/loopback addresses are reachable at all;
* the hard ceiling on every budget;
* which planner exists and which API key it uses;
* whether active scanning is even loaded.

A request can therefore only ever *narrow* what the deployment already permits. There is
no field for "allowed hosts", no field for "permissions", and no field that could widen
scope - the same structural argument the tool layer makes, applied to the API.
"""

from __future__ import annotations

import datetime as _dt
from enum import StrEnum
from typing import Any, Literal

from pydantic import Field, field_validator

from app.models.scan import ScanReport
from app.models.tools import MAX_URL_LEN, StrictModel

MAX_AUTHORIZATION_FIELD = 200
MAX_NOTE_FIELD = 500


class JobState(StrEnum):
    """Lifecycle state of a scan job."""

    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


TERMINAL_STATES: frozenset[JobState] = frozenset(
    {JobState.COMPLETED, JobState.FAILED, JobState.CANCELLED}
)


# --------------------------------------------------------------------------- #
# Requests
# --------------------------------------------------------------------------- #


class ScanRequest(StrictModel):
    """A request to run one scan.

    Only these fields exist. In particular there is no field for scope, for
    capabilities, or for a raw tool call: the API cannot be used to drive individual
    tools, only to run a whole policy-bound scan.
    """

    target: str = Field(
        min_length=1,
        max_length=MAX_URL_LEN,
        description=(
            "Target URL to scan, for example https://staging.example.com. Must be inside "
            "the host allowlist the operator configured at deployment time."
        ),
    )
    authorized_by: str = Field(
        min_length=1,
        max_length=MAX_AUTHORIZATION_FIELD,
        description=(
            "Who authorised this test. Required: an unattributed scan is refused, because "
            "the authorisation record is the audit trail for the engagement."
        ),
    )
    authorization_note: str = Field(
        default="",
        max_length=MAX_NOTE_FIELD,
        description="Free-form note about the authorisation, recorded in the report.",
    )
    scope_hosts: list[str] = Field(
        default_factory=list,
        max_length=16,
        description=(
            "Additional hostnames to include in scope. Each must already be permitted by "
            "the deployment allowlist; a request cannot add a host the operator did not "
            "authorise."
        ),
    )
    planner: Literal["scripted", "llm"] = Field(
        default="scripted",
        description=(
            "scripted: deterministic recon playbook. llm: AI planner, only available if "
            "the deployment configured a model and API key or supplied in request."
        ),
    )
    ai_api_key: str | None = Field(
        default=None,
        max_length=500,
        description="Optional API key for LLM planner supplied directly in scan request.",
    )
    ai_model: str | None = Field(
        default=None,
        max_length=100,
        description="Optional model name for LLM planner (e.g. gpt-4o-mini, qwen2.5-coder:7b).",
    )
    ai_base_url: str | None = Field(
        default=None,
        max_length=500,
        description="Optional OpenAI-compatible base URL (e.g. http://localhost:11434/v1 for Ollama).",
    )
    max_steps: int | None = Field(
        default=None, ge=1, le=500, description="Planning step budget; capped by the deployment."
    )
    max_tool_calls: int | None = Field(
        default=None, ge=1, le=2000, description="Tool call budget; capped by the deployment."
    )
    max_pages: int | None = Field(
        default=None, ge=1, le=200, description="Page budget; capped by the deployment."
    )
    max_requests: int | None = Field(
        default=None, ge=1, le=5000, description="HTTP request budget; capped by the deployment."
    )
    requests_per_second: float | None = Field(
        default=None,
        gt=0,
        le=100,
        description="Outbound rate limit; capped by the deployment.",
    )
    enable_active: bool = Field(
        default=False,
        description="Enable active checks (CORS preflight, TRACE, HTTP methods, OpenAPI). Requires deployment permission.",
    )
    enable_injection: bool = Field(
        default=False,
        description="Enable error-based SQLi/NoSQLi probes. Requires deployment permission.",
    )

    @field_validator("target")
    @classmethod
    def _no_control_characters(cls, value: str) -> str:
        if any(character in value for character in "\r\n\t\x00"):
            raise ValueError("target must not contain control characters")
        return value

    @field_validator("scope_hosts")
    @classmethod
    def _clean_hosts(cls, value: list[str]) -> list[str]:
        cleaned: list[str] = []
        for entry in value:
            host = entry.strip().lower()
            if not host:
                continue
            if len(host) > 255:
                raise ValueError("hostname is too long")
            if any(character in host for character in "/@ \t\r\n"):
                raise ValueError(f"not a hostname: {entry!r}")
            if host not in cleaned:
                cleaned.append(host)
        return cleaned


# --------------------------------------------------------------------------- #
# Responses
# --------------------------------------------------------------------------- #


class ServerCapabilities(StrictModel):
    """What this deployment will and will not do.

    Published so a caller can discover the limits instead of guessing, and so an
    operator can point at one response when explaining what the service is allowed to
    touch.
    """

    service: str = "ai-dast-core"
    version: str
    auth_required: bool = Field(description="Whether an API key must be presented.")
    deploy_profile: Literal["local", "exposed"]
    allowed_hosts: list[str] = Field(description="Hosts this deployment may ever scan.")
    denied_hosts: list[str] = Field(default_factory=list)
    allowed_ports: list[int] = Field(default_factory=list)
    allowed_schemes: list[str] = Field(default_factory=list)
    private_addresses_allowed: bool = Field(
        description="Whether the caller may opt in to private/loopback targets."
    )
    active_scanning_loaded: bool = Field(
        description="Always false in this build: no active tool is implemented."
    )
    planners: list[str] = Field(description="Planner names this deployment offers.")
    llm_configured: bool = Field(description="Whether an AI planner is usable.")
    limits: dict[str, Any] = Field(
        default_factory=dict, description="Hard ceilings on every budget."
    )
    defaults: dict[str, Any] = Field(
        default_factory=dict, description="Values used when a request omits a budget."
    )
    max_concurrent_scans: int = 0
    limitations: list[str] = Field(
        default_factory=list, description="What this service deliberately does not do."
    )


class JobAccepted(StrictModel):
    """Returned immediately when a scan is queued."""

    job_id: str
    state: JobState
    target: str = Field(description="Target as resolved and authorised by the service.")
    queue_position: int = Field(
        ge=0, description="How many jobs are ahead of this one; 0 means it starts now."
    )
    status_url: str = Field(description="Where to poll for progress.")
    report_url: str = Field(description="Where the JSON report will appear.")
    submitted_at: str = Field(
        default_factory=lambda: _dt.datetime.now(_dt.UTC).isoformat(timespec="seconds")
    )


class JobStatus(StrictModel):
    """Current state of a scan job."""

    job_id: str
    state: JobState
    target: str
    authorized_by: str
    planner: str
    submitted_at: str
    started_at: str | None = None
    finished_at: str | None = None
    duration_s: float = Field(default=0.0, ge=0)
    progress: dict[str, Any] = Field(
        default_factory=dict, description="Steps and tool calls used against their budgets."
    )
    counters: dict[str, int] = Field(default_factory=dict)
    severity_counts: dict[str, int] = Field(default_factory=dict)
    finding_count: int = 0
    tool_call_count: int = 0
    stop_reason: str = ""
    error: str | None = None
    recent_events: list[str] = Field(
        default_factory=list, description="The tail of the live log, for progress display."
    )
    scope: dict[str, Any] = Field(
        default_factory=dict, description="The resolved scope this job actually ran under."
    )


class JobSummary(StrictModel):
    """One row in the job list."""

    job_id: str
    state: JobState
    target: str
    authorized_by: str
    submitted_at: str
    finished_at: str | None = None
    finding_count: int = 0
    severity_counts: dict[str, int] = Field(default_factory=dict)


class JobList(StrictModel):
    """The job history, newest first."""

    jobs: list[JobSummary] = Field(default_factory=list)
    total: int = 0
    queued: int = 0
    running: int = 0


class ReportEnvelope(StrictModel):
    """A completed report plus the metadata a caller needs to interpret it."""

    job_id: str
    state: JobState
    report: ScanReport

    @property
    def severity_counts(self) -> dict[str, int]:
        counts = self.report.severity_counts
        return {
            "critical": counts.critical,
            "high": counts.high,
            "medium": counts.medium,
            "low": counts.low,
            "info": counts.info,
        }


class ToolListing(StrictModel):
    """The tool catalogue exposed over HTTP."""

    tools: list[dict[str, Any]] = Field(default_factory=list)
    by_category: dict[str, list[str]] = Field(default_factory=dict)
    note: str = Field(
        default=(
            "The AI planner may only call tools from discovery and passive. Active tools "
            "are declared for the roadmap and refuse to run."
        )
    )


class ErrorResponse(StrictModel):
    """Uniform error body, so clients never have to parse a bare string."""

    error: str
    detail: str = ""
    category: Literal[
        "unauthorized",
        "forbidden_scope",
        "invalid_request",
        "not_found",
        "conflict",
        "service_unavailable",
        "internal",
    ] = "invalid_request"


__all__ = [
    "ErrorResponse",
    "JobAccepted",
    "JobList",
    "JobState",
    "JobStatus",
    "JobSummary",
    "ReportEnvelope",
    "ScanRequest",
    "ServerCapabilities",
    "TERMINAL_STATES",
    "ToolListing",
]
