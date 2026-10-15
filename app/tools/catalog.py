"""Tool registry construction.

:func:`build_default_registry` is the single definition of what the AI can do. The
six MVP tools are wired here with their metadata, capabilities and executors. Adding
a tool means adding an entry here - there is no discovery, no plugin loading and no
path by which the model can introduce a capability.

The four active tools from the roadmap are registered as *declared but not
implemented*. They appear in documentation and in ``describe()`` so the design is
visible, but the registry refuses to run them and does not offer them to the model.
"""

from __future__ import annotations

from app.models.tools import (
    AnalyzeCorsRequest,
    AnalyzeExposedFilesRequest,
    BrowserOpenRequest,
    CheckCookiesRequest,
    CheckHeadersRequest,
    CheckTlsRequest,
    DetectTechnologiesRequest,
    EmptyRequest,
    ExtractFormsRequest,
    ExtractLinksRequest,
    ExtractScriptsRequest,
    GetAlertsRequest,
    GetHttpHistoryRequest,
    GetScanStatusRequest,
    ReadRobotsRequest,
    RunInjectionCheckRequest,
    RunOpenApiScanRequest,
    RunSelectedActiveCheckRequest,
    ToolCategory,
    ToolMeta,
)
from app.tools.active_checks import run_selected_active_check
from app.tools.base import Tool
from app.tools.context import ToolContext
from app.tools.cors import analyze_cors
from app.tools.discovery import browser_open, extract_forms, extract_links, extract_scripts
from app.tools.exposed_files import analyze_exposed_files
from app.tools.injection import run_injection_check
from app.tools.openapi import run_openapi_scan
from app.tools.passive_checks import check_cookies, check_headers
from app.tools.registry import ToolRegistry
from app.tools.result_tools import get_alerts, get_http_history, get_scan_status
from app.tools.technologies import detect_technologies
from app.tools.tls import check_tls
from app.tools.well_known import read_robots


def _not_implemented(name: str):
    """Executor for roadmap tools: always refuses, with an explanatory message."""

    def executor(ctx: ToolContext, request: object):  # pragma: no cover - unreachable
        from app.tools.base import ToolExecutionError

        raise ToolExecutionError(
            f"{name} is declared in the roadmap but not implemented in this build. "
            "Active scanning requires explicit operator opt-in and is out of scope for the MVP."
        )

    return executor


# --------------------------------------------------------------------------- #
# Discovery tools
# --------------------------------------------------------------------------- #

BROWSER_OPEN = Tool(
    meta=ToolMeta(
        name="browser_open",
        category=ToolCategory.DISCOVERY,
        summary="Open an in-scope URL in the controlled headless browser and capture the page.",
        description=(
            "Use this first, and after choosing a new in-scope URL to explore. It performs "
            "exactly one navigation and returns a page_id that extract_links, extract_forms "
            "and extract_scripts use.\n\n"
            "The URL must be inside the authorised scope. Requests the page makes to other "
            "hosts are blocked by the harness and reported in the notes. JavaScript is "
            "enabled by default; set disable_javascript=true to inspect the no-JS surface "
            "(note that a no-JS page is captured as static HTML, so the extract_* tools fall "
            "back to parsing that HTML).\n\n"
            "Cost: one page from the page budget. Opening the same URL twice wastes budget - "
            "reuse the page_id instead."
        ),
        request_model="BrowserOpenRequest",
        capabilities=("browser",),
        requires_confirmation=False,
        mutates_target=False,
        produces_findings=False,
        tags=("recon", "core", "navigation"),
    ),
    request_model=BrowserOpenRequest,
    executor=browser_open,
)

EXTRACT_LINKS = Tool(
    meta=ToolMeta(
        name="extract_links",
        category=ToolCategory.DISCOVERY,
        summary="List the links, form actions, scripts, frames and images referenced by an opened page.",
        description=(
            "Reads from a page captured by browser_open; it never contacts the target "
            "itself. Every returned link is annotated with in_scope and scope_reason so you "
            "know which URLs you are actually allowed to open next.\n\n"
            "Links with query parameters include query_keys, which are candidate input "
            "points for later, active testing. Links marked in_scope=false must never be "
            "passed to browser_open - the harness will refuse them."
        ),
        request_model="ExtractLinksRequest",
        capabilities=(),
        mutates_target=False,
        produces_findings=False,
        tags=("recon", "core", "surface"),
    ),
    request_model=ExtractLinksRequest,
    executor=extract_links,
)

EXTRACT_FORMS = Tool(
    meta=ToolMeta(
        name="extract_forms",
        category=ToolCategory.DISCOVERY,
        summary="List the HTML forms on an opened page, with their fields and input hints.",
        description=(
            "Reads from a page captured by browser_open. Each form reports its action URL, "
            "method, field names and types, and three heuristics: whether it looks like a "
            "login form, an upload form, or a state-changing form with no CSRF token.\n\n"
            "This harness never submits forms, so a form is evidence about the attack "
            "surface, not something you can exploit. Do not ask to submit one: no tool "
            "offers that capability."
        ),
        request_model="ExtractFormsRequest",
        capabilities=(),
        mutates_target=False,
        produces_findings=False,
        tags=("recon", "core", "surface", "input"),
    ),
    request_model=ExtractFormsRequest,
    executor=extract_forms,
)

EXTRACT_SCRIPTS = Tool(
    meta=ToolMeta(
        name="extract_scripts",
        category=ToolCategory.DISCOVERY,
        summary="List scripts on an opened page and harvest API-looking endpoints from them.",
        description=(
            "Reads from a page captured by browser_open. Returns external script URLs, "
            "bounded excerpts of inline JavaScript, API endpoint candidates found in fetch "
            "calls and framework attributes, and redacted notices about likely hard-coded "
            "credentials (the credential values themselves are never returned).\n\n"
            "The api_endpoints list is a set of *candidates*, not confirmed routes. Only "
            "endpoints marked in scope appear in the list you are given."
        ),
        request_model="ExtractScriptsRequest",
        capabilities=(),
        mutates_target=False,
        produces_findings=False,
        tags=("recon", "core", "surface", "api"),
    ),
    request_model=ExtractScriptsRequest,
    executor=extract_scripts,
)

# --------------------------------------------------------------------------- #
# Passive analysis
# --------------------------------------------------------------------------- #

ANALYZE_CORS = Tool(
    meta=ToolMeta(
        name="analyze_cors",
        category=ToolCategory.PASSIVE,
        summary="Probe a URL's CORS policy and report exploitable misconfigurations.",
        description=(
            "Sends a request with a fixed, reserved `.invalid` Origin header and reads the "
            "Access-Control-* response headers. You cannot supply the Origin value: there is "
            "no parameter for it, because a caller-controlled Origin would be an injection "
            "into a trust decision the browser makes on the user's behalf.\n\n"
            "Two probes are sent when the first is reflected, so a fixed allowlist value that "
            "happens to match is not mistaken for a wildcard. The verdict distinguishes the "
            "cases that matter:\n"
            "- `reflects_origin_with_credentials` - high: any site can read authenticated "
            "responses, which is an account-takeover primitive;\n"
            "- `null_origin` - high: anything in a sandboxed frame can read the response;\n"
            "- `reflects_origin` - medium: any site can read the response;\n"
            "- `wildcard_no_credentials` - not a finding: that is the correct configuration "
            "for a genuinely public API.\n\n"
            "Cost: one or two HTTP requests (three with probe_preflight)."
        ),
        request_model="AnalyzeCorsRequest",
        capabilities=("http_egress",),
        mutates_target=False,
        produces_findings=True,
        tags=("passive", "core", "cors", "findings"),
    ),
    request_model=AnalyzeCorsRequest,
    executor=analyze_cors,
)

CHECK_TLS = Tool(
    meta=ToolMeta(
        name="check_tls",
        category=ToolCategory.PASSIVE,
        summary="Inspect the negotiated TLS version, cipher and certificate of an HTTPS URL.",
        description=(
            "One handshake. Reports what the transport actually negotiated and what the "
            "certificate actually says: protocol version, cipher, subject, issuer, validity "
            "window and subject alternative names.\n\n"
            "Findings it can raise: an obsolete protocol (SSLv2/SSLv3/TLS 1.0/1.1), a "
            "certificate that is expired or close to expiry, and a self-signed certificate on "
            "a public hostname.\n\n"
            "It does not upgrade an `http://` URL to HTTPS. Silently changing the scheme would "
            "contact an endpoint you did not name and the operator did not authorise; for a "
            "plain-HTTP URL the tool says there is no TLS session to inspect.\n\n"
            "Cipher enumeration and downgrade testing are not implemented: they need a TLS "
            "client of the harness's own rather than the HTTP transport's connection, and they "
            "are an active technique.\n\n"
            "Cost: one HTTP request."
        ),
        request_model="CheckTlsRequest",
        capabilities=("http_egress",),
        mutates_target=False,
        produces_findings=True,
        tags=("passive", "core", "tls", "transport", "findings"),
    ),
    request_model=CheckTlsRequest,
    executor=check_tls,
)

ANALYZE_EXPOSED_FILES = Tool(
    meta=ToolMeta(
        name="analyze_exposed_files",
        category=ToolCategory.PASSIVE,
        summary="Probe a fixed catalogue of well-known paths for publicly readable files.",
        description=(
            "Checks whether files that should never be public are downloadable: repository "
            "metadata (/.git/HEAD), dotenv files, database dumps, backups, and debug "
            "endpoints like /server-status or /actuator/env.\n\n"
            "You choose the origin and which categories to probe, never the paths: the "
            "catalogue is harness-owned, so this cannot be used to enumerate arbitrary "
            "content. Categories: vcs, config, backup, server-info, editor, ci, docs. "
            "Passing none probes a small high-signal default set.\n\n"
            "Hits are confirmed rather than assumed. The harness first probes a path that "
            "cannot exist; if that also returns 200, status codes are treated as meaningless "
            "and every hit must pass a content-signature check. File contents are never "
            "returned - only the fact of exposure and a redacted signature match.\n\n"
            "Cost: one HEAD per path plus a control probe, charged to a dedicated budget "
            "(`max_exposed_file_checks`) so this cannot starve the header and cookie checks."
        ),
        request_model="AnalyzeExposedFilesRequest",
        capabilities=("http_egress",),
        mutates_target=False,
        produces_findings=True,
        tags=("passive", "core", "disclosure", "findings"),
    ),
    request_model=AnalyzeExposedFilesRequest,
    executor=analyze_exposed_files,
)

DETECT_TECHNOLOGIES = Tool(
    meta=ToolMeta(
        name="detect_technologies",
        category=ToolCategory.PASSIVE,
        summary="Fingerprint the server, framework and front-end stack from one response.",
        description=(
            "Sends one request and matches headers, cookie names and body patterns against a "
            "small, high-precision knowledge base. Use it to decide which other checks are "
            "worth running, and to make the report easier to read.\n\n"
            "A technology match is NOT a vulnerability. The only finding this tool raises is "
            "a low-severity note when a version number is actually disclosed, because a "
            "version banner shortens an attacker's path to a real exploit.\n\n"
            "Cost: one HTTP request."
        ),
        request_model="DetectTechnologiesRequest",
        capabilities=("http_egress",),
        mutates_target=False,
        produces_findings=True,
        tags=("passive", "core", "fingerprint", "recon"),
    ),
    request_model=DetectTechnologiesRequest,
    executor=detect_technologies,
)

CHECK_HEADERS = Tool(
    meta=ToolMeta(
        name="check_headers",
        category=ToolCategory.PASSIVE,
        summary="Check HTTP response security headers for an in-scope URL and raise findings.",
        description=(
            "Makes one ordinary request with the harness HTTP client and grades the response "
            "headers against a fixed checklist (HSTS, CSP, X-Content-Type-Options, "
            "X-Frame-Options, Referrer-Policy, Permissions-Policy, COOP, CORP, "
            "X-Permitted-Cross-Domain-Policies), plus disclosure and CORS misconfiguration "
            "checks.\n\n"
            "Use it on every distinct origin and on any endpoint whose response headers "
            "matter (redirects, error pages). It decides nothing by itself: findings are "
            "derived from the observed headers, and each one carries the exact observed "
            "value as evidence.\n\n"
            "Cost: one HTTP request per redirect hop."
        ),
        request_model="CheckHeadersRequest",
        capabilities=("http_egress",),
        mutates_target=False,
        produces_findings=True,
        tags=("passive", "core", "headers", "findings"),
    ),
    request_model=CheckHeadersRequest,
    executor=check_headers,
)

CHECK_COOKIES = Tool(
    meta=ToolMeta(
        name="check_cookies",
        category=ToolCategory.PASSIVE,
        summary="Check Set-Cookie attribute posture for an in-scope URL and raise findings.",
        description=(
            "Makes one ordinary request and inspects every Set-Cookie header across the "
            "redirect chain for Secure, HttpOnly, SameSite, name-prefix compliance and "
            "over-broad Domain/Path scoping. Cookie values are never stored or returned - "
            "only the length and a hash.\n\n"
            "Set include_browser_cookies=true to also report cookies the browser observed "
            "after JavaScript ran; this requires browser_open to have been used first."
        ),
        request_model="CheckCookiesRequest",
        capabilities=("http_egress",),
        mutates_target=False,
        produces_findings=True,
        tags=("passive", "core", "cookies", "session", "findings"),
    ),
    request_model=CheckCookiesRequest,
    executor=check_cookies,
)

# --------------------------------------------------------------------------- #
# Well-known file discovery
# --------------------------------------------------------------------------- #

READ_ROBOTS = Tool(
    meta=ToolMeta(
        name="read_robots",
        category=ToolCategory.DISCOVERY,
        summary="Read robots.txt, sitemap.xml and security.txt at an origin for disclosed paths.",
        description=(
            "Use this early: robots.txt often maps paths the operator would rather you did "
            "not see, and a sitemap is the site's own index of its pages. It also checks "
            "for /.well-known/security.txt, which tells you where to report what you find.\n\n"
            "The harness chooses the paths (/robots.txt, /sitemap.xml, "
            "/.well-known/security.txt); you only choose the origin. Paths derived from "
            "Disallow/Allow rules and sitemap entries are returned as absolute URLs, "
            "filtered to what is actually in scope, and added to the known-URL list.\n\n"
            "A Disallow entry is a disclosure hint, not a vulnerability. Do not report it as "
            "one.\n\n"
            "Cost: up to three HTTP requests, one per well-known path."
        ),
        request_model="ReadRobotsRequest",
        capabilities=("http_egress",),
        mutates_target=False,
        produces_findings=False,
        tags=("recon", "core", "surface", "well-known"),
    ),
    request_model=ReadRobotsRequest,
    executor=read_robots,
)

# --------------------------------------------------------------------------- #
# Result tools: free, read-only views over what the scan already knows
# --------------------------------------------------------------------------- #

GET_SCAN_STATUS = Tool(
    meta=ToolMeta(
        name="get_scan_status",
        category=ToolCategory.RESULT,
        summary="Report progress, remaining budget and concrete next steps.",
        description=(
            "Costs nothing and sends no traffic. Use it when you need to decide whether to "
            "keep going: it returns pages opened, URLs and endpoints known, findings so far, "
            "which tools have run, and how much budget is left.\n\n"
            "It also returns `suggestions`: gaps the harness can see for itself, such as "
            "in-scope URLs whose headers have not been checked. These are derived from "
            "harness state, not from guesswork, and they are options - ignore them if you "
            "have a better plan."
        ),
        request_model="GetScanStatusRequest",
        capabilities=(),
        mutates_target=False,
        produces_findings=False,
        tags=("result", "core", "free"),
    ),
    request_model=GetScanStatusRequest,
    executor=get_scan_status,
)

GET_ALERTS = Tool(
    meta=ToolMeta(
        name="get_alerts",
        category=ToolCategory.RESULT,
        summary="Read the findings produced so far, filtered by severity, category or host.",
        description=(
            "Costs nothing and sends no traffic. Findings are produced by the harness from "
            "observed evidence; this tool only reads them back. Use it to see what you have "
            "before deciding whether more scanning would add anything.\n\n"
            "Every finding carries the tool call that produced it. You may classify and "
            "prioritise findings, but you cannot create one: if it is not in this list, no "
            "tool observed it."
        ),
        request_model="GetAlertsRequest",
        capabilities=(),
        mutates_target=False,
        produces_findings=False,
        tags=("result", "core", "findings", "free"),
    ),
    request_model=GetAlertsRequest,
    executor=get_alerts,
)

GET_HTTP_HISTORY = Tool(
    meta=ToolMeta(
        name="get_http_history",
        category=ToolCategory.RESULT,
        summary="Read the log of HTTP exchanges performed, including redirect chains.",
        description=(
            "Costs nothing and sends no traffic: it never re-requests a URL. Use it to see "
            "what was actually requested, what status came back, and which redirects were "
            "followed or refused by the scope guard.\n\n"
            "Useful for spotting that a URL redirected somewhere uninteresting, or that a "
            "redirect out of scope was blocked - both change what is worth doing next."
        ),
        request_model="GetHttpHistoryRequest",
        capabilities=(),
        mutates_target=False,
        produces_findings=False,
        tags=("result", "core", "http", "free"),
    ),
    request_model=GetHttpHistoryRequest,
    executor=get_http_history,
)

# --------------------------------------------------------------------------- #
# Active checks: the only tool that sends requests the target did not invite
# --------------------------------------------------------------------------- #

RUN_SELECTED_ACTIVE_CHECK = Tool(
    meta=ToolMeta(
        name="run_selected_active_check",
        category=ToolCategory.ACTIVE,
        summary="Run one or more named, non-mutating active checks against a URL.",
        description=(
            "You choose the check NAME, never the payload. Every request is built in harness "
            "code from constants; there is no parameter for a method, a header, a body or a "
            "payload, because a tool that accepted one would be a raw-request primitive.\n\n"
            "Available checks:\n"
            "- `cors_preflight` - sends an OPTIONS preflight naming PUT from a reserved "
            "`.invalid` origin, and reports whether a cross-origin caller may use a "
            "state-changing method. It never performs the write.\n"
            "- `http_methods` - reads the allowed methods from OPTIONS, plus a TRACE probe. "
            "Write methods are never sent.\n"
            "- `options_method` - whether OPTIONS is answered without authentication.\n"
            "- `trace_method` - whether TRACE is enabled (cross-site tracing). TRACE is "
            "defined to have no side effects.\n"
            "- `path_normalisation` - GET requests only; compares encoded traversal variants "
            "of the URL's own path against the plain path, and requires the variant to "
            "resolve to a real resource before reporting.\n\n"
            "**Every check is non-mutating.** Only GET, HEAD and OPTIONS are ever sent, and "
            "the engine refuses any other method outright. That is why this tool can be run "
            "against a production-adjacent target without changing anything - but it is still "
            "an active probe, so it requires the `active_scan` capability, an explicit "
            "operator opt-in, and confirmation.\n\n"
            "Cost: 1-2 requests per check, plus one for calibration."
        ),
        request_model="RunSelectedActiveCheckRequest",
        capabilities=("http_egress", "active_scan"),
        requires_confirmation=True,
        # False, and deliberately: no check in the catalogue can change target state.
        mutates_target=False,
        produces_findings=True,
        tags=("active", "checks", "methods", "cors", "findings"),
    ),
    request_model=RunSelectedActiveCheckRequest,
    executor=run_selected_active_check,
)

RUN_INJECTION_CHECK = Tool(
    meta=ToolMeta(
        name="run_injection_check",
        category=ToolCategory.ACTIVE,
        summary="Probe the URL's own query parameters for error-based SQL injection.",
        description=(
            "You choose the TECHNIQUE and the PARAMETER NAMES. The payloads are harness "
            "constants; there is no field for one, because a tool that accepted a payload "
            "would be a remote code execution primitive rather than a scanner.\n\n"
            "Techniques:\n"
            "- `sql_error` - sends minimal syntax-breaking characters (a single quote, a double "
            "quote, a quote with a comment opener) and looks for a database error that the "
            "baseline response did not contain. A syntax error proves the parameter reaches "
            "query construction unescaped, without extracting anything.\n"
            "- `nosql_operator` - sends operator-shaped values and detects a behaviour change.\n\n"
            "Every probe is a **read-only HTTP GET**. The technique works by making the "
            "server's own query malformed, never by adding a statement to it. This tool "
            "contains no union, no boolean-blind, no time-based and no stacked-statement "
            "probe, because those extract or destroy data.\n\n"
            "It only reports when a database error appears that was **absent from the "
            "baseline**, so an application that always prints errors is not flagged. A "
            "response that merely varies with its input is recorded but not reported: that is "
            "normal behaviour and treating it as injection is how scanners earn their "
            "reputation for noise.\n\n"
            "**Limitation:** error-based detection only finds injection that produces an "
            "error. An application that suppresses database errors will not be detected this "
            "way. Absence of a finding is not evidence of safety.\n\n"
            "Cost: one baseline request, plus up to 3 probes per parameter."
        ),
        request_model="RunInjectionCheckRequest",
        capabilities=("http_egress", "injection_probe"),
        requires_confirmation=True,
        # No payload here can change target state; the detection is error-based and read-only.
        mutates_target=False,
        produces_findings=True,
        tags=("active", "injection", "sqli", "findings"),
    ),
    request_model=RunInjectionCheckRequest,
    executor=run_injection_check,
)

RUN_OPENAPI_SCAN = Tool(
    meta=ToolMeta(
        name="run_openapi_scan",
        category=ToolCategory.ACTIVE,
        summary="Scan and test API endpoints discovered via an OpenAPI or Swagger document.",
        description=(
            "Fetches or discovers OpenAPI/Swagger JSON specifications, inventories all declared "
            "endpoints, validates server URLs against the scope guard, detects missing "
            "authentication on sensitive routes, and performs non-mutating validation probes (GET/OPTIONS).\n\n"
            "Cost: 1 request for spec discovery/fetch, plus 1 request per probed endpoint."
        ),
        request_model="RunOpenApiScanRequest",
        capabilities=("http_egress", "active_scan"),
        requires_confirmation=True,
        mutates_target=False,
        produces_findings=True,
        tags=("active", "api", "openapi", "swagger", "findings"),
    ),
    request_model=RunOpenApiScanRequest,
    executor=run_openapi_scan,
)

# --------------------------------------------------------------------------- #
# Roadmap tools: declared, documented, not callable
# --------------------------------------------------------------------------- #

ROADMAP_TOOLS: tuple[Tool, ...] = (
    Tool(
        meta=ToolMeta(
            name="run_zap_baseline",
            category=ToolCategory.ACTIVE,
            summary="Run an OWASP ZAP baseline scan against the in-scope target.",
            description=(
                "Roadmap. Would wrap the ZAP baseline scan behind the same scope guard, "
                "rate limits and confirmation gate as the rest of the tool set. Requires "
                "operator opt-in because it sends non-idempotent traffic."
            ),
            request_model="EmptyRequest",
            capabilities=("http_egress", "active_scan"),
            requires_confirmation=True,
            mutates_target=True,
            produces_findings=True,
            implemented=False,
            tags=("active", "scanner", "roadmap"),
        ),
        request_model=EmptyRequest,
        executor=_not_implemented("run_zap_baseline"),
    ),
    Tool(
        meta=ToolMeta(
            name="run_authenticated_crawl",
            category=ToolCategory.ACTIVE,
            summary="Crawl the application while authenticated with operator-supplied credentials.",
            description=(
                "Roadmap. Requires a credential store that keeps secrets out of the report, "
                "per-scan session isolation, a redaction layer over every tool result, and "
                "the rule that the planner never sees a credential value. It also requires "
                "the report to distinguish 'tested unauthenticated' from 'tested as user X'."
            ),
            request_model="EmptyRequest",
            capabilities=("browser", "http_egress", "active_scan"),
            requires_confirmation=True,
            mutates_target=True,
            produces_findings=True,
            implemented=False,
            tags=("active", "authenticated", "roadmap"),
        ),
        request_model=EmptyRequest,
        executor=_not_implemented("run_authenticated_crawl"),
    ),
)


def build_default_registry(*, include_roadmap: bool = True) -> ToolRegistry:
    """Build the registry offered to the AI planner.

    ``include_roadmap`` keeps the unimplemented tools visible in documentation and
    the CLI listing while ensuring :meth:`ToolRegistry.callable_tools` - and therefore
    the model's tool list - never contains them.
    """
    registry = ToolRegistry(
        [
            BROWSER_OPEN,
            EXTRACT_LINKS,
            EXTRACT_FORMS,
            EXTRACT_SCRIPTS,
            READ_ROBOTS,
            ANALYZE_EXPOSED_FILES,
            DETECT_TECHNOLOGIES,
            ANALYZE_CORS,
            CHECK_TLS,
            CHECK_HEADERS,
            CHECK_COOKIES,
            RUN_SELECTED_ACTIVE_CHECK,
            RUN_INJECTION_CHECK,
            RUN_OPENAPI_SCAN,
            GET_SCAN_STATUS,
            GET_ALERTS,
            GET_HTTP_HISTORY,
        ]
    )
    if include_roadmap:
        registry.extend(list(ROADMAP_TOOLS))
    return registry


__all__ = [
    "ANALYZE_CORS",
    "ANALYZE_EXPOSED_FILES",
    "BROWSER_OPEN",
    "CHECK_COOKIES",
    "CHECK_HEADERS",
    "CHECK_TLS",
    "DETECT_TECHNOLOGIES",
    "EXTRACT_FORMS",
    "EXTRACT_LINKS",
    "EXTRACT_SCRIPTS",
    "GET_ALERTS",
    "GET_HTTP_HISTORY",
    "GET_SCAN_STATUS",
    "READ_ROBOTS",
    "ROADMAP_TOOLS",
    "RUN_INJECTION_CHECK",
    "RUN_OPENAPI_SCAN",
    "RUN_SELECTED_ACTIVE_CHECK",
    "build_default_registry",
]
