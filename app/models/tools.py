"""Per-tool request/response schemas for the web DAST tool set.

Each tool has exactly one request model and one data model. The request model is
converted to JSON Schema and handed to the AI planner, so it is the *only* place
that defines what the AI is allowed to ask for. Field descriptions are written
for the LLM: they are part of the prompt.

Design rules:

* ``extra="forbid"`` everywhere - the AI cannot invent parameters.
* URL fields are plain strings here; the *scope guard* is what actually decides
  whether a URL may be fetched. The models only enforce shape and length.
* Every response carries ``url`` first so findings always tie back to a location.
* ``ToolResult`` is the single envelope every tool returns, so the planner loop
  never needs tool-specific error handling.

MVP coverage: browser_open, extract_links, extract_forms, extract_scripts,
check_headers, check_cookies.
"""

from __future__ import annotations

import json
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

MAX_URL_LEN = 2048


class StrictModel(BaseModel):
    """Base model that rejects undeclared fields on every input path."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


# --------------------------------------------------------------------------- #
# Envelope
# --------------------------------------------------------------------------- #


class ToolCategory(StrEnum):
    """Capability class of a tool. Drives confirmation policy and reporting."""

    DISCOVERY = "discovery"
    PASSIVE = "passive"
    ACTIVE = "active"
    RESULT = "result"


class ToolStatus(StrEnum):
    """Terminal state of a single tool invocation."""

    OK = "ok"
    DENIED = "denied"
    ERROR = "error"
    TIMEOUT = "timeout"
    SKIPPED = "skipped"
    NOT_IMPLEMENTED = "not_implemented"


class ToolMeta(StrictModel):
    """Static, machine-readable description of one tool.

    This is exactly what the registry publishes and what the AI planner sees.
    """

    name: str = Field(description="Unique tool name, snake_case.")
    category: ToolCategory = Field(description="Capability class of the tool.")
    summary: str = Field(description="One-line description shown to the AI planner.")
    description: str = Field(default="", description="Longer usage guidance for the planner.")
    request_model: str = Field(default="", description="Name of the Pydantic request model.")
    capabilities: tuple[str, ...] = Field(
        default=(),
        description=(
            "Permission capabilities required, e.g. 'http_egress' or 'browser'. "
            "The policy layer checks these before execution."
        ),
    )
    requires_confirmation: bool = Field(
        default=False, description="Whether a human must approve before this tool runs."
    )
    mutates_target: bool = Field(
        default=False, description="True if the tool may modify target state (active scanning)."
    )
    produces_findings: bool = Field(
        default=False, description="True if the tool yields findings for the report."
    )
    implemented: bool = Field(
        default=True, description="False for roadmap tools declared but not yet callable."
    )
    tags: tuple[str, ...] = Field(default=(), description="Free-form tags for grouping.")

    def to_llm_spec(self, json_schema: dict[str, Any]) -> dict[str, Any]:
        """Render this tool for an LLM tool-calling API."""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": f"[{self.category.value}] {self.summary}\n\n{self.description}".strip(),
                "parameters": json_schema,
            },
        }


class ToolCall(StrictModel):
    """A single tool invocation requested by the AI planner."""

    tool: str = Field(min_length=1, max_length=64, description="Name of a registered tool.")
    args: dict[str, Any] = Field(
        default_factory=dict,
        description="Arguments, validated against the tool's request model.",
    )
    reason: str = Field(
        default="",
        max_length=500,
        description="Short justification from the AI, kept in the audit trace.",
    )

    @field_validator("args")
    @classmethod
    def _bounded_args(cls, value: dict[str, Any]) -> dict[str, Any]:
        if len(value) > 32:
            raise ValueError("too many arguments for a single tool call")
        return value


class ToolResult(StrictModel):
    """Uniform result envelope returned by every tool.

    The AI planner only ever sees ``status``, ``summary`` and ``data``.
    ``denied`` is a normal, expected outcome rather than a crash: it teaches the
    planner that it tried to leave scope.
    """

    tool: str = Field(description="Tool that produced this result.")
    status: ToolStatus = Field(description="Terminal state of the invocation.")
    summary: str = Field(
        default="",
        max_length=2000,
        description="One-paragraph, AI-readable summary of what happened.",
    )
    data: dict[str, Any] = Field(
        default_factory=dict,
        description="Tool-specific payload, already trimmed to the token budget.",
    )
    error: str | None = Field(default=None, description="Error detail when status is not ok.")
    denial_reason: str | None = Field(
        default=None, description="Policy reason when status is denied."
    )
    duration_ms: int = Field(default=0, ge=0, description="Wall-clock execution time.")
    truncated: bool = Field(default=False, description="True when the payload was trimmed.")
    findings: list[dict[str, Any]] = Field(
        default_factory=list, description="Findings raised by this tool."
    )
    artifacts: list[str] = Field(
        default_factory=list, description="Relative paths of files written by this tool."
    )

    @property
    def ok(self) -> bool:
        return self.status == ToolStatus.OK

    def to_planner_message(self, budget_chars: int = 12000) -> str:
        """Serialize for the LLM conversation, bounded by a character budget."""
        payload: dict[str, Any] = {
            "tool": self.tool,
            "status": self.status.value,
            "summary": self.summary,
        }
        if self.error:
            payload["error"] = self.error
        if self.denial_reason:
            payload["denial_reason"] = self.denial_reason
        if self.data:
            payload["data"] = self.data
        if self.findings:
            payload["findings"] = self.findings
        text = json.dumps(payload, ensure_ascii=False, indent=2, default=str)
        if len(text) > budget_chars:
            text = text[:budget_chars] + "\n... [truncated by harness]"
        return text


# --------------------------------------------------------------------------- #
# Shared request shapes
# --------------------------------------------------------------------------- #


class EmptyRequest(StrictModel):
    """Request model for tools needing no arguments beyond the scan context."""


class ScopedRequest(StrictModel):
    """Request model for tools that operate on one already-known URL."""

    url: str = Field(
        min_length=1,
        max_length=MAX_URL_LEN,
        description="Absolute URL to operate on. Must be inside the scan scope.",
    )

    @field_validator("url")
    @classmethod
    def _no_control_chars(cls, value: str) -> str:
        if any(ch in value for ch in "\r\n\t\x00"):
            raise ValueError("url must not contain control characters")
        return value


# --------------------------------------------------------------------------- #
# 1. browser_open
# --------------------------------------------------------------------------- #


class BrowserOpenRequest(ScopedRequest):
    """Open a URL in the controlled headless browser."""

    wait_until: Literal["domcontentloaded", "load", "networkidle"] = Field(
        default="domcontentloaded",
        description="Playwright navigation wait condition. Prefer 'domcontentloaded'.",
    )
    wait_ms: int = Field(
        default=500,
        ge=0,
        le=10_000,
        description="Extra settle time after navigation, in milliseconds.",
    )
    screenshot: bool = Field(
        default=False, description="Also store a PNG screenshot artifact of the page."
    )
    full_page: bool = Field(
        default=False, description="With screenshot=true, capture the full scrollable page."
    )
    disable_javascript: bool = Field(
        default=False,
        description="Load with JavaScript disabled to inspect the no-JS surface.",
    )


class BrowserOpenData(StrictModel):
    """Result of opening a URL in the browser."""

    url: str = Field(description="URL that was requested.")
    final_url: str = Field(description="URL after redirects.")
    status_code: int | None = Field(default=None, description="HTTP status of the main document.")
    title: str = Field(default="", max_length=500, description="Document title.")
    content_type: str = Field(default="", max_length=200)
    html_bytes: int = Field(default=0, ge=0, description="Size of the rendered HTML in bytes.")
    html_sha256: str = Field(default="", description="SHA-256 of the rendered HTML.")
    redirect_chain: list[str] = Field(default_factory=list, description="Redirect hops, in order.")
    out_of_scope_redirect: str | None = Field(
        default=None,
        description="Set when a redirect left the scope and was therefore blocked.",
    )
    page_id: str | None = Field(default=None, description="Handle for follow-up extract_* tools.")
    screenshot_path: str | None = Field(default=None, description="Relative artifact path.")
    console_errors: list[str] = Field(
        default_factory=list, description="Page console errors, capped and sanitized."
    )
    notes: list[str] = Field(default_factory=list, description="Harness notes, e.g. JS disabled.")


# --------------------------------------------------------------------------- #
# 2. extract_links
# --------------------------------------------------------------------------- #


class ExtractLinksRequest(StrictModel):
    """Extract hyperlinks from an already-opened page."""

    page_id: str | None = Field(
        default=None,
        max_length=64,
        description="Page handle from browser_open. Defaults to the most recent page.",
    )
    same_origin_only: bool = Field(
        default=True, description="Drop links pointing outside the page origin."
    )
    include_out_of_scope: bool = Field(
        default=True,
        description="Keep out-of-scope links in the payload but flagged (recommended).",
    )
    max_links: int = Field(default=300, ge=1, le=2000, description="Hard cap on returned links.")


class ExtractedLink(StrictModel):
    """One hyperlink discovered on a page."""

    url: str = Field(description="Absolute URL after resolving against the base.")
    text: str = Field(default="", max_length=200, description="Visible anchor text.")
    rel: str = Field(default="", max_length=100, description="The anchor's rel attribute.")
    kind: Literal[
        "anchor", "form_action", "script_src", "stylesheet", "iframe", "image", "other"
    ] = Field(default="other", description="Where the URL came from.")
    in_scope: bool = Field(default=True, description="Whether the scope guard allows fetching it.")
    scope_reason: str = Field(default="", description="Why the URL is out of scope, if it is.")
    has_query: bool = Field(default=False, description="True if the URL carries a query string.")
    query_keys: list[str] = Field(
        default_factory=list,
        description="Names of query parameters - candidate injection points.",
    )


class ExtractLinksData(StrictModel):
    """Link inventory for one page."""

    page_url: str = Field(description="Page the links were extracted from.")
    total_found: int = Field(ge=0, description="Links found before capping.")
    returned: int = Field(ge=0, description="Links present in this payload.")
    in_scope_count: int = Field(ge=0, description="How many returned links are in scope.")
    links: list[ExtractedLink] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# 3. extract_forms
# --------------------------------------------------------------------------- #


class ExtractFormsRequest(StrictModel):
    """Extract HTML forms and their input fields."""

    page_id: str | None = Field(
        default=None, max_length=64, description="Page handle; defaults to the most recent page."
    )
    include_hidden: bool = Field(
        default=True, description="Include input[type=hidden] fields (CSRF tokens, state)."
    )
    max_forms: int = Field(default=50, ge=1, le=500, description="Hard cap on returned forms.")


class FormField(StrictModel):
    """One input field inside a form."""

    name: str = Field(default="", max_length=200, description="Field name attribute.")
    field_type: str = Field(default="text", max_length=50, description="Input type or tag name.")
    value: str = Field(default="", max_length=300, description="Pre-filled value, truncated.")
    required: bool = Field(default=False)
    placeholder: str = Field(default="", max_length=200)
    autocomplete: str = Field(default="", max_length=100)
    options: list[str] = Field(
        default_factory=list, description="For selects: option values, capped at 50."
    )


class ExtractedForm(StrictModel):
    """One form on the page, with its fields."""

    action: str = Field(description="Absolute action URL, resolved and scope-checked.")
    method: Literal["get", "post", "put", "patch", "delete", "other"] = Field(default="get")
    form_id: str = Field(default="", max_length=200)
    name: str = Field(default="", max_length=200)
    enctype: str = Field(default="", max_length=200)
    in_scope: bool = Field(default=True, description="Whether the action target is in scope.")
    scope_reason: str = Field(default="")
    is_login_form: bool = Field(default=False, description="Heuristic: has a password field.")
    is_upload_form: bool = Field(
        default=False, description="Heuristic: enctype is multipart/form-data."
    )
    has_csrf_token: bool = Field(
        default=False, description="Heuristic: hidden token-like field present."
    )
    fields: list[FormField] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list, description="Planner-facing hints.")


class ExtractFormsData(StrictModel):
    """Form inventory for one page."""

    page_url: str = Field(description="Page the forms were extracted from.")
    total_found: int = Field(ge=0)
    returned: int = Field(ge=0)
    forms: list[ExtractedForm] = Field(default_factory=list)
    ready_for_submit: bool = Field(
        default=False,
        description=(
            "Always false in the MVP: the harness never submits forms. Present so the "
            "planner does not assume it can."
        ),
    )


# --------------------------------------------------------------------------- #
# 4. extract_scripts
# --------------------------------------------------------------------------- #


class ExtractScriptsRequest(StrictModel):
    """Extract script sources, inline scripts and endpoint-like strings."""

    page_id: str | None = Field(
        default=None, max_length=64, description="Page handle; defaults to the most recent page."
    )
    include_inline: bool = Field(default=True, description="Include inline <script> blocks.")
    max_inline_chars: int = Field(
        default=1500,
        ge=0,
        le=20_000,
        description="Per-inline-script excerpt length returned to the AI.",
    )
    max_scripts: int = Field(default=100, ge=1, le=500, description="Hard cap on returned scripts.")


class ExtractedScript(StrictModel):
    """One script element."""

    kind: Literal["external", "inline", "module"] = Field(default="inline")
    url: str = Field(default="", description="Absolute URL for external scripts, else empty.")
    in_scope: bool = Field(default=True)
    scope_reason: str = Field(default="")
    sha256: str = Field(default="", description="Hash of the body, for change detection.")
    length: int = Field(default=0, ge=0, description="Full body length in characters.")
    excerpt: str = Field(default="", description="Bounded excerpt returned to the AI.")


class ExtractScriptsData(StrictModel):
    """Script inventory for one page."""

    page_url: str = Field(description="Page the scripts were extracted from.")
    total_found: int = Field(ge=0)
    returned: int = Field(ge=0)
    inline_count: int = Field(default=0, ge=0)
    external_count: int = Field(default=0, ge=0)
    scripts: list[ExtractedScript] = Field(default_factory=list)
    api_endpoints: list[str] = Field(
        default_factory=list,
        description="Absolute API-looking paths harvested from inline JS and HTML attributes.",
    )
    secrets_hints: list[str] = Field(
        default_factory=list,
        description="Redacted notices about likely hard-coded credentials in inline JS.",
    )


# --------------------------------------------------------------------------- #
# 5. check_headers
# --------------------------------------------------------------------------- #


class CheckHeadersRequest(ScopedRequest):
    """Check HTTP response security headers for a URL.

    Uses the harness HTTP client, not the browser, so the result reflects the raw
    transport response rather than a JS-mutated DOM.
    """

    method: Literal["GET", "HEAD"] = Field(
        default="GET", description="HEAD is lighter, but some servers answer it differently."
    )
    follow_redirects: bool = Field(
        default=True, description="Follow redirects; each hop is re-checked against the scope."
    )


class HeaderCheck(StrictModel):
    """Assessment of a single security header."""

    header: str = Field(description="Canonical header name.")
    present: bool = Field(description="Whether the header was returned.")
    value: str = Field(default="", max_length=500, description="Header value, truncated.")
    severity: Literal["info", "low", "medium", "high", "critical"] = Field(
        default="info", description="Severity when the header is missing or weak."
    )
    status: Literal["present", "missing", "weak", "misconfigured"] = Field(default="missing")
    rationale: str = Field(default="", description="Why this matters, in one sentence.")
    recommendation: str = Field(default="", description="Concrete fix.")


class HeaderReport(StrictModel):
    """Header posture of one URL."""

    url: str
    final_url: str = ""
    status_code: int | None = None
    server: str = Field(default="", max_length=200)
    powered_by: str = Field(default="", max_length=200)
    checks: list[HeaderCheck] = Field(default_factory=list)
    missing_count: int = Field(default=0, ge=0)
    weak_count: int = Field(default=0, ge=0)
    grade: Literal["A", "B", "C", "D", "F"] = Field(default="F")
    redirect_chain: list[str] = Field(default_factory=list)


class CheckHeadersData(StrictModel):
    """Payload of check_headers."""

    reports: list[HeaderReport] = Field(default_factory=list)
    total_missing: int = Field(default=0, ge=0)
    total_weak: int = Field(default=0, ge=0)


# --------------------------------------------------------------------------- #
# 6. check_cookies
# --------------------------------------------------------------------------- #


class CheckCookiesRequest(ScopedRequest):
    """Check cookie attributes (Set-Cookie flags) for a URL."""

    include_browser_cookies: bool = Field(
        default=False,
        description="Also merge cookies observed by the browser after JS execution.",
    )


class CookieRecord(StrictModel):
    """One cookie and its attribute posture. Cookie values are never stored."""

    name: str = Field(max_length=200)
    domain: str = Field(default="", max_length=255)
    path: str = Field(default="/", max_length=255)
    secure: bool = False
    http_only: bool = False
    same_site: Literal["strict", "lax", "none", "unspecified"] = "unspecified"
    expires: str = Field(default="", max_length=64, description="ISO-8601 expiry or 'session'.")
    max_age: int | None = None
    prefix: Literal["__Host-", "__Secure-", "none"] = "none"
    value_length: int = Field(default=0, ge=0, description="Length only.")
    value_sha256: str = Field(default="", description="Hash of the value, for change detection.")
    source: Literal["header", "browser"] = "header"
    issues: list[str] = Field(default_factory=list)


class CookieSummary(StrictModel):
    """Aggregate cookie posture of one URL."""

    url: str
    final_url: str = ""
    total: int = Field(default=0, ge=0)
    insecure_count: int = Field(default=0, ge=0)
    no_httponly_count: int = Field(default=0, ge=0)
    no_samesite_count: int = Field(default=0, ge=0)
    session_cookie_count: int = Field(default=0, ge=0)
    cookies: list[CookieRecord] = Field(default_factory=list)


class CheckCookiesData(StrictModel):
    """Payload of check_cookies."""

    summaries: list[CookieSummary] = Field(default_factory=list)
    total_cookies: int = Field(default=0, ge=0)
    total_issue_count: int = Field(default=0, ge=0)


# --------------------------------------------------------------------------- #
# Result tools: read-only views over what the scan has already learned
# --------------------------------------------------------------------------- #


class GetScanStatusRequest(StrictModel):
    """Ask the harness what the scan has done so far and how much budget is left.

    Costs nothing: it reads harness state and sends no traffic. Use it when you need to
    decide whether to keep going.
    """


class ScanStatusData(StrictModel):
    """Progress and budget picture for the running scan."""

    scan_id: str
    target: str
    status: str = Field(description="Lifecycle state of the scan.")
    elapsed_s: float = Field(default=0.0, ge=0)
    pages_opened: int = Field(default=0, ge=0)
    urls_known: int = Field(default=0, ge=0)
    urls_in_scope: int = Field(default=0, ge=0)
    forms_found: int = Field(default=0, ge=0)
    scripts_found: int = Field(default=0, ge=0)
    api_endpoints_found: int = Field(default=0, ge=0)
    http_exchanges: int = Field(default=0, ge=0)
    findings_total: int = Field(default=0, ge=0)
    findings_by_severity: dict[str, int] = Field(default_factory=dict)
    tools_used: list[str] = Field(
        default_factory=list, description="Distinct tools that ran successfully."
    )
    remaining: dict[str, int] = Field(
        default_factory=dict, description="Budget still available, by name."
    )
    suggestions: list[str] = Field(
        default_factory=list, description="Concrete, in-scope next steps the harness can see."
    )


class GetAlertsRequest(StrictModel):
    """Read the findings produced so far, optionally filtered. Costs nothing."""

    severity: Literal["info", "low", "medium", "high", "critical"] | None = Field(
        default=None, description="Only return findings at this severity or higher."
    )
    category: str | None = Field(
        default=None,
        max_length=64,
        description="Only return findings in this category, e.g. 'security_headers'.",
    )
    host: str | None = Field(
        default=None, max_length=255, description="Only return findings for this host."
    )
    limit: int = Field(default=25, ge=1, le=200, description="Maximum findings to return.")


class AlertSummary(StrictModel):
    """One finding, in the compact form the planner needs."""

    id: str
    title: str
    severity: str
    confidence: str
    category: str
    host: str = ""
    location: str = ""
    url: str = ""
    recommendation: str = ""
    evidence_count: int = Field(default=0, ge=0)


class GetAlertsData(StrictModel):
    """The filtered finding list."""

    total_findings: int = Field(default=0, ge=0, description="Findings before filtering.")
    matched: int = Field(default=0, ge=0, description="Findings after filtering.")
    returned: int = Field(default=0, ge=0)
    counts_by_severity: dict[str, int] = Field(default_factory=dict)
    alerts: list[AlertSummary] = Field(default_factory=list)


class GetHttpHistoryRequest(StrictModel):
    """Read the log of HTTP exchanges the harness performed. Costs nothing and sends
    nothing: it never re-requests a URL."""

    host: str | None = Field(
        default=None, max_length=255, description="Only return exchanges for this host."
    )
    redirects_only: bool = Field(
        default=False, description="Only return exchanges that followed at least one redirect."
    )
    limit: int = Field(default=25, ge=1, le=200, description="Maximum exchanges to return.")


class HttpHistoryEntry(StrictModel):
    """One recorded exchange."""

    requested_url: str
    final_url: str = ""
    method: str = "GET"
    status_code: int | None = None
    redirect_count: int = Field(default=0, ge=0)
    redirect_chain: list[str] = Field(default_factory=list)
    content_type: str = ""
    body_bytes: int = 0
    total_ms: int = Field(default=0, ge=0)
    error: str = ""
    tool: str = ""
    tool_call_index: int = Field(default=-1, ge=-1)


class GetHttpHistoryData(StrictModel):
    """The filtered transaction log."""

    total_exchanges: int = Field(default=0, ge=0)
    returned: int = Field(default=0, ge=0)
    redirects_followed: int = Field(default=0, ge=0)
    blocked_redirects: int = Field(
        default=0, ge=0, description="Exchanges where a redirect was refused by the scope guard."
    )
    entries: list[HttpHistoryEntry] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# read_robots
# --------------------------------------------------------------------------- #


class ReadRobotsRequest(ScopedRequest):
    """Read the well-known policy files at the target's origin.

    Fetches a fixed, harness-owned list of paths - ``/robots.txt``, ``/sitemap.xml``,
    ``/.well-known/security.txt`` - with one request each. The caller chooses the origin,
    never the path.
    """

    include_sitemap: bool = Field(
        default=True, description="Also fetch and parse /sitemap.xml."
    )


class RobotRule(StrictModel):
    """One parsed directive."""

    kind: Literal["disallow", "allow", "sitemap", "crawl-delay", "other"] = "other"
    value: str = Field(default="", max_length=500)
    user_agent: str = Field(default="", max_length=200, description="The User-agent block.")


class WellKnownFile(StrictModel):
    """One well-known file and what came back."""

    path: str
    url: str
    status_code: int | None = None
    found: bool = Field(default=False, description="True when the server returned content.")
    content_type: str = ""
    bytes: int = Field(default=0, ge=0)
    excerpt: str = Field(default="", max_length=2000)


class ReadRobotsData(StrictModel):
    """What the well-known files disclosed."""

    origin: str
    user_agents: list[str] = Field(default_factory=list)
    rules: list[RobotRule] = Field(default_factory=list)
    sitemap_urls: list[str] = Field(default_factory=list)
    discovered_paths: list[str] = Field(
        default_factory=list,
        description="Absolute, in-scope URLs built from Disallow/Allow rules and sitemap entries.",
    )
    files: list[WellKnownFile] = Field(default_factory=list)
    has_security_txt: bool = False
    crawl_delay_s: float | None = None
    notes: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# analyze_exposed_files
# --------------------------------------------------------------------------- #


class AnalyzeExposedFilesRequest(ScopedRequest):
    """Probe a fixed, harness-owned list of well-known paths for exposed files.

    The caller chooses the **origin** and, optionally, which **categories** of path to
    probe. The paths themselves are harness constants, so this cannot be turned into an
    arbitrary content-discovery scanner.
    """

    categories: list[
        Literal["vcs", "config", "backup", "server-info", "editor", "ci", "docs"]
    ] = Field(
        default_factory=list,
        max_length=7,
        description=(
            "Which path groups to probe. Default (empty) means a small, high-signal set. "
            "Available: vcs (repository metadata), config (.env and friends), backup "
            "(archives and dumps), server-info (status and debug endpoints), editor "
            "(editor and IDE leftovers), ci (pipeline config), docs (readme, licence)."
        ),
    )
    max_paths: int = Field(
        default=20,
        ge=1,
        le=60,
        description="Hard cap on how many paths to probe, regardless of categories.",
    )


class ExposedFileCheck(StrictModel):
    """The outcome of probing one path."""

    path: str
    url: str
    method: str = Field(default="HEAD", description="HEAD unless a body was needed.")
    status_code: int | None = None
    content_type: str = ""
    content_length: int | None = None
    exposed: bool = Field(
        default=False, description="True when the path returned real content."
    )
    verified: bool = Field(
        default=False,
        description=(
            "True when the body was actually inspected and matched this file type's "
            "signature. False means the hit rests on a status code alone and should be "
            "treated as a candidate."
        ),
    )
    severity: Literal["info", "low", "medium", "high", "critical"] = "info"
    confidence: Literal["low", "medium", "high"] = "medium"
    description: str = ""
    recommendation: str = ""
    evidence_excerpt: str = Field(
        default="", max_length=400, description="Redacted excerpt, never full file content."
    )
    notes: list[str] = Field(default_factory=list)


class AnalyzeExposedFilesData(StrictModel):
    """What the probe sweep found."""

    origin: str
    probed: int = Field(default=0, ge=0, description="Paths actually requested.")
    skipped: int = Field(default=0, ge=0, description="Paths skipped, e.g. budget ran out.")
    exposed_count: int = Field(default=0, ge=0)
    baseline_status: int | None = Field(
        default=None,
        description=(
            "Status of a known-nonexistent control path. Used to tell a real hit from a "
            "server that answers 200 to everything."
        ),
    )
    soft_404_detected: bool = Field(
        default=False,
        description=(
            "True when the server returns 200 for the control path, meaning status codes "
            "cannot be trusted and every hit was verified by content signature instead."
        ),
    )
    categories_probed: list[str] = Field(default_factory=list)
    checks: list[ExposedFileCheck] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# detect_technologies
# --------------------------------------------------------------------------- #


class DetectTechnologiesRequest(ScopedRequest):
    """Identify the software stack from an in-scope URL. Sends one request."""

    include_cookies: bool = Field(
        default=True, description="Use cookie names as additional fingerprints."
    )


class TechnologyMatch(StrictModel):
    """One detected technology and the evidence that identified it."""

    name: str
    category: Literal[
        "server", "framework", "language", "cms", "cdn", "analytics", "javascript", "other"
    ] = "other"
    version: str = Field(default="", max_length=100)
    confidence: Literal["low", "medium", "high"] = "medium"
    evidence: list[str] = Field(
        default_factory=list, description="Human-readable observations supporting the match."
    )
    detail: str = Field(default="", max_length=400)


class DetectTechnologiesData(StrictModel):
    """The fingerprint result for one URL."""

    url: str
    final_url: str = ""
    status_code: int | None = None
    technologies: list[TechnologyMatch] = Field(default_factory=list)
    server: str = Field(default="", max_length=200)
    powered_by: str = Field(default="", max_length=200)
    generator: str = Field(default="", max_length=200)
    cookie_names: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# analyze_cors
# --------------------------------------------------------------------------- #


class AnalyzeCorsRequest(ScopedRequest):
    """Probe the CORS policy of an in-scope URL.

    The harness sends the ``Origin`` header; the caller cannot supply one. That is the
    whole safety argument for this tool: a request-supplied ``Origin`` would be an
    injection into a trust decision, and there is no field for it.
    """

    probe_preflight: bool = Field(
        default=False,
        description=(
            "Also send an OPTIONS preflight request. Costs one extra request and reveals "
            "the allowed methods and headers, which a simple GET does not."
        ),
    )


class CorsAssessment(StrictModel):
    """One CORS evaluation of a URL."""

    url: str
    status_code: int | None = None
    request_origin: str = Field(
        description="The Origin the harness sent. Always a harness constant."
    )
    allow_origin: str = Field(default="", max_length=500)
    allow_credentials: str = Field(default="", max_length=100)
    allow_methods: str = Field(default="", max_length=500)
    allow_headers: str = Field(default="", max_length=500)
    expose_headers: str = Field(default="", max_length=500)
    max_age: str = Field(default="", max_length=100)
    reflects_arbitrary_origin: bool = Field(
        default=False,
        description="The response echoed the probe Origin instead of using a fixed value.",
    )
    wildcard: bool = Field(default=False, description="Allow-Origin is '*'.")
    credentials_allowed: bool = Field(
        default=False, description="Allow-Credentials is 'true'."
    )
    severity: Literal["info", "low", "medium", "high", "critical"] = "info"
    verdict: Literal[
        "safe",
        "wildcard_no_credentials",
        "wildcard_with_credentials",
        "reflects_origin",
        "reflects_origin_with_credentials",
        "null_origin",
        "invalid",
    ] = "safe"
    rationale: str = ""
    preflight_status: int | None = None
    preflight_allow_methods: str = Field(default="", max_length=500)
    preflight_allow_headers: str = Field(default="", max_length=500)


class AnalyzeCorsData(StrictModel):
    """Payload of analyze_cors."""

    origin: str
    probe_origin: str
    assessments: list[CorsAssessment] = Field(default_factory=list)
    vulnerable_count: int = Field(default=0, ge=0)
    notes: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# check_tls
# --------------------------------------------------------------------------- #


class CheckTlsRequest(ScopedRequest):
    """Inspect the TLS configuration of an in-scope HTTPS URL.

    One handshake. For an ``http://`` URL the tool reports that there is no TLS to inspect
    rather than attempting an upgrade the caller did not ask for.
    """

    check_expiry: bool = Field(
        default=True, description="Report certificate expiry and flag a near-term expiry."
    )
    warn_days: int = Field(
        default=21,
        ge=1,
        le=365,
        description="Flag the certificate when it expires within this many days.",
    )


class CertificateInfo(StrictModel):
    """Certificate facts, as far as the HTTP transport exposes them."""

    available: bool = Field(
        default=False,
        description=(
            "False when the installed HTTP transport does not expose the peer certificate. "
            "The tool says so rather than guessing."
        ),
    )
    subject: str = Field(default="", max_length=1000)
    issuer: str = Field(default="", max_length=1000)
    not_before: str = Field(default="", max_length=64)
    not_after: str = Field(default="", max_length=64)
    days_until_expiry: int | None = Field(
        default=None, description="Negative when the certificate has already expired."
    )
    subject_alt_names: list[str] = Field(default_factory=list)
    self_signed: bool = Field(
        default=False, description="True when subject and issuer are identical."
    )


class CheckTlsData(StrictModel):
    """Payload of check_tls."""

    url: str
    final_url: str = ""
    scheme: str = "http"
    used_https: bool = False
    protocol: str = Field(default="", max_length=50, description="Negotiated TLS version.")
    cipher: str = Field(default="", max_length=200)
    protocol_obsolete: bool = Field(
        default=False, description="True for SSLv2/SSLv3/TLS 1.0/TLS 1.1."
    )
    certificate_verified: bool | None = Field(
        default=None, description="None when verification result is unknown."
    )
    certificate: CertificateInfo = Field(default_factory=CertificateInfo)
    grade: Literal["A", "B", "C", "D", "F", "unknown"] = "unknown"
    notes: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# run_selected_active_check
# --------------------------------------------------------------------------- #


class RunSelectedActiveCheckRequest(ScopedRequest):
    """Run one or more named checks from the harness's fixed active-check catalogue.

    **You choose the check name, never the payload.** Every request is built in harness code
    from constants: no method, path, header value or body from this request reaches the wire
    beyond the URL and the check names. There is deliberately no parameter for a payload, a
    method, a header, or a body, because a tool that accepted one would be a raw-request
    primitive wearing a check's clothing.

    Every check in the catalogue is **non-mutating**: it uses only ``GET``, ``HEAD`` and
    ``OPTIONS``, and it never exercises a method it is enumerating. A check that could change
    target state does not exist here, and the confirmation gate plus the
    ``active_scan`` capability must both be satisfied before any of them runs.
    """

    checks: list[str] = Field(
        min_length=1,
        max_length=8,
        description=(
            "Names of checks to run. Available: "
            "`cors_preflight` (is a write method allowed cross-origin?), "
            "`http_methods` (which methods does the server advertise and accept?), "
            "`options_method` (is OPTIONS handled at all?), "
            "`trace_method` (is the TRACE method enabled? cross-site tracing), "
            "`path_normalisation` (do encoded traversal variants reach a different "
            "endpoint?). All are non-mutating."
        ),
    )
    calibrate: bool = Field(
        default=True,
        description=(
            "Send a baseline request to a path that cannot exist, so a catch-all server "
            "cannot make every check look like it succeeded. Recommended."
        ),
    )


class ActiveCheckResult(StrictModel):
    """Outcome of one named active check against one URL."""

    check: str
    url: str
    ran: bool = Field(default=False, description="False when the check was skipped.")
    skipped_reason: str = ""
    requests_sent: int = Field(default=0, ge=0)
    verdict: str = Field(default="inconclusive", max_length=100)
    severity: Literal["info", "low", "medium", "high", "critical"] = "info"
    confidence: Literal["low", "medium", "high"] = "medium"
    observed: str = Field(default="", max_length=1500)
    rationale: str = Field(default="", max_length=1500)
    recommendation: str = Field(default="", max_length=1500)
    methods_advertised: list[str] = Field(default_factory=list)
    methods_accepted: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class RunSelectedActiveCheckData(StrictModel):
    """Payload of run_selected_active_check."""

    url: str
    origin: str
    checks_requested: list[str] = Field(default_factory=list)
    checks_run: list[str] = Field(default_factory=list)
    checks_skipped: list[str] = Field(default_factory=list)
    baseline_status: int | None = Field(
        default=None, description="Status of the calibration path. A 200 means catch-all."
    )
    catch_all_detected: bool = Field(
        default=False,
        description=(
            "True when a path that cannot exist also returned 200, meaning status codes "
            "cannot be trusted and every check re-verified by content."
        ),
    )
    results: list[ActiveCheckResult] = Field(default_factory=list)
    findings_count: int = Field(default=0, ge=0)
    requests_used: int = Field(default=0, ge=0)
    notes: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# run_injection_check
# --------------------------------------------------------------------------- #


class RunInjectionCheckRequest(ScopedRequest):
    """Probe the URL's own query parameters for injection, using harness-owned payloads.

    **The AI chooses which technique and which parameter names, and nothing else.** The
    payloads are constants in harness code. There is no field for a payload, and that is the
    entire safety argument: the difference between "a scanner that probes for injection" and
    "a remote code execution primitive" is exactly who writes the bytes.

    Techniques available are limited to **error-based, read-only** detection:

    * ``sql_error`` - send a syntax-breaking character and look for a database error that was
      not present in the baseline. A syntax error reveals a query-construction flaw without
      extracting anything.
    * ``nosql_operator`` - send operator-shaped values and detect a behaviour change that a
      plain value does not produce.

    Nothing here extracts data, blinds a query, or writes. There is no union, no boolean-blind,
    no time-based probe, and no stacked statement, because those are exploitation rather than
    detection and because they are the ones that can damage a target.

    Every payload is a **read-only HTTP GET**: the technique works by making the *server's own
    query* malformed, never by adding a statement to it.
    """

    parameters: list[str] = Field(
        default_factory=list,
        max_length=16,
        description=(
            "Query parameter names to test, as they appear in the URL or in canonical_query. "
            "Leave empty to test every parameter already present in the URL."
        ),
    )
    technique: Literal["sql_error", "nosql_operator"] = Field(
        default="sql_error",
        description="Which detection technique to apply.",
    )
    canonical_query: str = Field(
        default="",
        max_length=2000,
        description=(
            "Optional canonical query string (for example 'q=test&page=1'). Use this when the "
            "URL in the attack surface carries no query, so the harness still knows which "
            "parameter names exist. Values here are only used to seed the baseline request."
        ),
    )


class InjectionProbe(StrictModel):
    """One payload sent to one parameter, and what came back."""

    parameter: str
    payload_index: int = Field(
        ge=0, description="Index into the technique's harness-owned payload list."
    )
    payload_label: str = Field(
        default="",
        max_length=100,
        description=(
            "A safe description of the payload, e.g. 'single quote'. The payload itself is "
            "never echoed into the report."
        ),
    )
    status_code: int | None = None
    baseline_status: int | None = None
    error_signature: str = Field(
        default="", max_length=300, description="The database error text that matched, if any."
    )
    length_delta: int | None = Field(
        default=None, description="Response size change against the baseline."
    )
    behaviour_changed: bool = Field(
        default=False, description="True when the response differed from the baseline."
    )


class InjectionFindingResult(StrictModel):
    """Conclusion for one parameter under one technique."""

    parameter: str
    technique: str
    vulnerable: bool = False
    verdict: str = Field(default="inconclusive", max_length=100)
    severity: Literal["info", "low", "medium", "high", "critical"] = "info"
    confidence: Literal["low", "medium", "high"] = "medium"
    description: str = Field(default="", max_length=1500)
    recommendation: str = Field(default="", max_length=1500)
    error_signature: str = Field(default="", max_length=300)
    probes_sent: int = Field(default=0, ge=0)
    baseline_requests: int = Field(default=0, ge=0)


class RunInjectionCheckData(StrictModel):
    """Payload of run_injection_check."""

    url: str
    technique: str
    parameters_tested: list[str] = Field(default_factory=list)
    parameters_skipped: list[str] = Field(default_factory=list)
    baseline_status: int | None = None
    baseline_length: int | None = None
    results: list[InjectionFindingResult] = Field(default_factory=list)
    probes: list[InjectionProbe] = Field(default_factory=list)
    vulnerable_count: int = Field(default=0, ge=0)
    requests_used: int = Field(default=0, ge=0)
    payloads_available: int = Field(default=0, ge=0)
    notes: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# run_openapi_scan
# --------------------------------------------------------------------------- #


class RunOpenApiScanRequest(ScopedRequest):
    """Scan and test API endpoints discovered via an OpenAPI or Swagger document.

    **The AI provides the spec URL (or lets the harness discover it at well-known paths).**
    The harness parses the spec, extracts endpoints, checks every URL against the scope
    guard, verifies security schemes (missing authentication, exposed admin routes), and
    optionally performs non-mutating validation probes (GET/OPTIONS).
    """

    spec_url: str = Field(
        default="",
        max_length=MAX_URL_LEN,
        description=(
            "Direct URL to the OpenAPI/Swagger JSON document. If empty, well-known paths "
            "like /openapi.json, /swagger.json, /v3/api-docs are checked at the target origin."
        ),
    )
    max_endpoints: int = Field(
        default=30,
        ge=1,
        le=100,
        description="Maximum number of endpoints from the spec to inspect and probe.",
    )
    probe_endpoints: bool = Field(
        default=True,
        description=(
            "Whether to probe endpoints with non-mutating requests (GET/OPTIONS) to test "
            "for missing authentication and information disclosure."
        ),
    )


class OpenApiEndpoint(StrictModel):
    """One endpoint discovered in the OpenAPI document."""

    path: str
    method: str
    summary: str = Field(default="", max_length=500)
    requires_auth: bool = False
    auth_schemes: list[str] = Field(default_factory=list)
    status_code: int | None = None
    in_scope: bool = True
    sensitive: bool = False
    issues: list[str] = Field(default_factory=list)


class RunOpenApiScanData(StrictModel):
    """Payload of run_openapi_scan."""

    url: str
    spec_url: str = ""
    title: str = Field(default="", max_length=200)
    openapi_version: str = Field(default="", max_length=50)
    total_endpoints_discovered: int = Field(default=0, ge=0)
    endpoints_tested: int = Field(default=0, ge=0)
    unauthenticated_endpoints_count: int = Field(default=0, ge=0)
    sensitive_endpoints_count: int = Field(default=0, ge=0)
    endpoints: list[OpenApiEndpoint] = Field(default_factory=list)
    findings_count: int = Field(default=0, ge=0)
    requests_used: int = Field(default=0, ge=0)
    notes: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# Registry of request models, keyed by tool name
# --------------------------------------------------------------------------- #

TOOL_REQUEST_MODELS: dict[str, type[StrictModel]] = {
    "browser_open": BrowserOpenRequest,
    "extract_links": ExtractLinksRequest,
    "extract_forms": ExtractFormsRequest,
    "extract_scripts": ExtractScriptsRequest,
    "check_headers": CheckHeadersRequest,
    "check_cookies": CheckCookiesRequest,
    "analyze_cors": AnalyzeCorsRequest,
    "check_tls": CheckTlsRequest,
    "read_robots": ReadRobotsRequest,
    "analyze_exposed_files": AnalyzeExposedFilesRequest,
    "detect_technologies": DetectTechnologiesRequest,
    "run_selected_active_check": RunSelectedActiveCheckRequest,
    "run_injection_check": RunInjectionCheckRequest,
    "run_openapi_scan": RunOpenApiScanRequest,
    "get_scan_status": GetScanStatusRequest,
    "get_alerts": GetAlertsRequest,
    "get_http_history": GetHttpHistoryRequest,
}
