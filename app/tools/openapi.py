"""``run_openapi_scan``: probe and analyze endpoints declared in an OpenAPI/Swagger spec.

The harness fetches or discovers the API specification, parses it defensively, validates
all paths and server URLs against the scope guard, and identifies:
1. Publicly exposed OpenAPI/Swagger specification documents (attack surface disclosure).
2. API endpoints missing authentication declarations.
3. Sensitive endpoints (admin, management, debug, data mutation) accessible unauthenticated.

All probing is strictly non-mutating: only GET and OPTIONS are ever sent.
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urljoin, urlsplit

from app.models.finding import Confidence, Evidence, Finding, FindingCategory, Severity
from app.models.tools import OpenApiEndpoint, RunOpenApiScanData, RunOpenApiScanRequest
from app.tools.base import ToolOutcome, ok
from app.tools.findings import make_finding
from app.tools.http_client import EgressDenied, HttpExchange
from app.tools.shared import require_in_scope

WELL_KNOWN_SPEC_PATHS: tuple[str, ...] = (
    "/openapi.json",
    "/swagger.json",
    "/v3/api-docs",
    "/api-docs",
    "/api/openapi.json",
    "/api/v1/openapi.json",
    "/swagger/v1/swagger.json",
)

SENSITIVE_PATH_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"/(?:admin|manage|internal|debug|actuator|metrics|env|config|secrets)\b", re.IGNORECASE),
    re.compile(r"/(?:users?|accounts?|credentials?|keys?|tokens?)\b", re.IGNORECASE),
    re.compile(r"/(?:backup|export|dump|upload|delete|reset)\b", re.IGNORECASE),
)

MAX_SPEC_BYTES = 2_000_000


def _is_sensitive_path(path: str) -> bool:
    return any(pattern.search(path) for pattern in SENSITIVE_PATH_PATTERNS)


def run_openapi_scan(ctx, request: RunOpenApiScanRequest) -> ToolOutcome:
    """Fetch/discover an OpenAPI spec, inventory its surface, and check for authentication flaws."""
    decision = require_in_scope(ctx, request.url)
    notes: list[str] = []
    findings: list[Finding] = []

    spec_data: dict[str, Any] | None = None
    spec_url: str = ""

    # 1. Fetch or discover spec
    if request.spec_url.strip():
        explicit_url = request.spec_url.strip()
        spec_decision = ctx.scope.check_url(explicit_url, resolve=False)
        if not spec_decision.allowed:
            return ok(
                f"The provided spec URL {explicit_url} was refused by the scope guard: {spec_decision.reason}",
                RunOpenApiScanData(url=decision.url, notes=[f"Scope refusal: {spec_decision.reason}"]),
            )
        exchange = _fetch_url(ctx, explicit_url, notes)
        if exchange and exchange.ok:
            spec_data = _parse_json(exchange.body_prefix)
            if spec_data:
                spec_url = explicit_url
            else:
                notes.append(f"Content at {explicit_url} is not valid JSON or YAML OpenAPI spec")
    else:
        # Probe well-known paths
        base_origin = f"{urlsplit(decision.url).scheme}://{urlsplit(decision.url).netloc}"
        for candidate_path in WELL_KNOWN_SPEC_PATHS:
            candidate_url = urljoin(base_origin, candidate_path)
            candidate_decision = ctx.scope.check_url(candidate_url, resolve=False)
            if not candidate_decision.allowed:
                continue
            exchange = _fetch_url(ctx, candidate_url, notes)
            if exchange and exchange.ok and exchange.status_code == 200:
                parsed = _parse_json(exchange.body_prefix)
                if parsed and ("openapi" in parsed or "swagger" in parsed or "paths" in parsed):
                    spec_data = parsed
                    spec_url = candidate_url
                    notes.append(f"Discovered OpenAPI spec at {candidate_url}")
                    break

    if not spec_data:
        return ok(
            f"No OpenAPI or Swagger specification could be retrieved at {decision.url}.",
            RunOpenApiScanData(
                url=decision.url,
                spec_url=spec_url,
                notes=notes or ["No valid spec found at provided URL or well-known paths."],
            ),
            notes=notes,
        )

    # 2. Inspect spec metadata
    openapi_version = str(spec_data.get("openapi") or spec_data.get("swagger") or "unknown")
    info = spec_data.get("info") if isinstance(spec_data.get("info"), dict) else {}
    title = str(info.get("title") or "API Specification")

    global_security = spec_data.get("security")
    has_global_security = isinstance(global_security, list) and len(global_security) > 0

    # Finding: Publicly exposed OpenAPI documentation
    findings.append(
        make_finding(
            title="OpenAPI / Swagger specification is publicly accessible",
            category=FindingCategory.INFORMATION_DISCLOSURE,
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            description=(
                f"The application exposes an OpenAPI/Swagger document at {spec_url} without authentication. "
                "This discloses complete API routing, parameter names, expected data types, and internal endpoints."
            ),
            impact="Shortens attacker reconnaissance time by providing a machine-readable map of the attack surface.",
            recommendation="Restrict access to API documentation in production environments or place it behind authentication.",
            url=spec_url,
            owasp="A01:2021-Broken Access Control",
            cwe="CWE-200",
            evidence=[
                Evidence(
                    tool="run_openapi_scan",
                    url=spec_url,
                    location="OpenAPI Document",
                    observed=f"Valid {openapi_version} spec titled {title!r} fetched with HTTP 200",
                    expected="API documentation should be restricted in production",
                    raw={"title": title, "version": openapi_version, "spec_url": spec_url},
                )
            ],
            source_tools=["run_openapi_scan"],
            tags=["openapi", "swagger", "api", "disclosure"],
        )
    )

    # 3. Extract endpoints
    raw_paths = spec_data.get("paths") if isinstance(spec_data.get("paths"), dict) else {}
    discovered_endpoints: list[OpenApiEndpoint] = []
    unauth_sensitive_count = 0

    base_url = decision.url
    servers = spec_data.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict) and "url" in servers[0]:
        candidate_server = str(servers[0]["url"])
        if candidate_server.startswith("http"):
            server_decision = ctx.scope.check_url(candidate_server, resolve=False)
            if server_decision.allowed:
                base_url = candidate_server

    for path_str, path_item in raw_paths.items():
        if not isinstance(path_item, dict):
            continue
        for method_str in ("get", "post", "put", "patch", "delete", "options", "head"):
            operation = path_item.get(method_str)
            if not isinstance(operation, dict):
                continue

            summary = str(operation.get("summary") or operation.get("description") or "")[:200]
            op_security = operation.get("security")

            # In OpenAPI: operation.security overrides global. An empty list [] explicitly disables auth!
            requires_auth = False
            auth_schemes: list[str] = []

            if isinstance(op_security, list):
                if len(op_security) > 0:
                    requires_auth = True
                    for sec_obj in op_security:
                        if isinstance(sec_obj, dict):
                            auth_schemes.extend(sec_obj.keys())
                else:
                    requires_auth = False  # Explicitly overridden to no auth
            else:
                requires_auth = has_global_security

            is_sensitive = _is_sensitive_path(path_str) or method_str in {"delete", "put", "patch"}
            endpoint_issues: list[str] = []

            if not requires_auth:
                endpoint_issues.append("no_auth_declared")
                if is_sensitive:
                    unauth_sensitive_count += 1
                    endpoint_issues.append("sensitive_without_auth")

            discovered_endpoints.append(
                OpenApiEndpoint(
                    path=path_str,
                    method=method_str.upper(),
                    summary=summary,
                    requires_auth=requires_auth,
                    auth_schemes=auth_schemes,
                    sensitive=is_sensitive,
                    issues=endpoint_issues,
                )
            )

    # 4. Probe endpoints if requested (non-mutating only: GET and OPTIONS)
    probed_count = 0
    if request.probe_endpoints:
        to_probe = discovered_endpoints[: request.max_endpoints]
        for ep in to_probe:
            clean_path = re.sub(r"\{[a-zA-Z0-9_]+\}", "1", ep.path)
            probe_target = urljoin(base_url, clean_path)

            probe_decision = ctx.scope.check_url(probe_target, resolve=False)
            if not probe_decision.allowed:
                ep.in_scope = False
                continue

            # Non-mutating probe: GET for GET, OPTIONS for others
            probe_method = "GET" if ep.method == "GET" else "OPTIONS"
            try:
                exchange = ctx.http.request(
                    probe_target,
                    method=probe_method,
                    follow_redirects=False,
                    read_body=True,
                )
                ep.status_code = exchange.status_code
                probed_count += 1

                # If an endpoint without auth returns 200 on sensitive path
                if not ep.requires_auth and ep.sensitive and ep.status_code == 200:
                    findings.append(
                        make_finding(
                            title=f"Sensitive API endpoint accessible without authentication ({ep.path})",
                            category=FindingCategory.AUTHENTICATION,
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            description=(
                                f"The API endpoint `{ep.method} {ep.path}` does not declare authentication requirements "
                                f"in the OpenAPI spec and returned HTTP 200 when probed unauthenticated at `{probe_target}`."
                            ),
                            impact="Unauthorized callers can inspect or trigger sensitive application logic without credentials.",
                            recommendation="Enforce authentication and authorization checks (e.g. Bearer token, API Key, OAuth2).",
                            url=probe_target,
                            location=ep.path,
                            owasp="A01:2021-Broken Access Control",
                            cwe="CWE-306",
                            evidence=[
                                Evidence(
                                    tool="run_openapi_scan",
                                    url=probe_target,
                                    location=ep.path,
                                    observed=f"{probe_method} returned HTTP {exchange.status_code}",
                                    expected="Expected HTTP 401 Unauthorized or 403 Forbidden",
                                    raw={"method": ep.method, "path": ep.path, "status": exchange.status_code},
                                )
                            ],
                            source_tools=["run_openapi_scan"],
                            tags=["openapi", "auth", "api", "sensitive"],
                        )
                    )
            except EgressDenied:
                ep.in_scope = False
            except Exception as exc:  # noqa: BLE001
                notes.append(f"Probe {ep.method} {clean_path} failed: {type(exc).__name__}")

    # Summary finding for general missing authentication across API
    unauth_total = sum(1 for ep in discovered_endpoints if not ep.requires_auth)
    if unauth_total > 0 and not findings:
        findings.append(
            make_finding(
                title=f"{unauth_total} API endpoint(s) declare no authentication in OpenAPI specification",
                category=FindingCategory.AUTHENTICATION,
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                description=(
                    f"Out of {len(discovered_endpoints)} endpoints discovered in {spec_url}, "
                    f"{unauth_total} endpoints have no security requirements declared."
                ),
                impact="If the server does not enforce auth at the gateway/handler, endpoints may be publicly accessible.",
                recommendation="Audit API endpoints and configure appropriate securitySchemes in the OpenAPI definition.",
                url=spec_url,
                owasp="A01:2021-Broken Access Control",
                cwe="CWE-306",
                source_tools=["run_openapi_scan"],
                tags=["openapi", "api", "auth"],
            )
        )

    summary_text = (
        f"OpenAPI scan discovered {len(discovered_endpoints)} endpoints from {spec_url or decision.url}. "
        f"Tested {probed_count} endpoints. {unauth_total} endpoints declare no authentication "
        f"({unauth_sensitive_count} sensitive). Produced {len(findings)} finding(s)."
    )

    data = RunOpenApiScanData(
        url=decision.url,
        spec_url=spec_url,
        title=title,
        openapi_version=openapi_version,
        total_endpoints_discovered=len(discovered_endpoints),
        endpoints_tested=probed_count,
        unauthenticated_endpoints_count=unauth_total,
        sensitive_endpoints_count=unauth_sensitive_count,
        endpoints=discovered_endpoints[:50],  # Bounded to avoid blowing payload
        findings_count=len(findings),
        requests_used=probed_count + (1 if spec_url else len(WELL_KNOWN_SPEC_PATHS)),
        notes=notes,
    )

    return ok(summary_text, data, findings=findings, notes=notes)


def _fetch_url(ctx, url: str, notes: list[str]) -> HttpExchange | None:
    try:
        return ctx.http.request(url, method="GET", follow_redirects=False, read_body=True)
    except EgressDenied as exc:
        notes.append(f"Scope refusal for {url}: {exc.reason}")
        return None
    except Exception as exc:  # noqa: BLE001
        notes.append(f"Request to {url} failed: {type(exc).__name__}")
        return None


def _parse_json(content: str) -> dict[str, Any] | None:
    content = (content or "").strip()
    if not content:
        return None
    try:
        data = json.loads(content)
        return data if isinstance(data, dict) else None
    except Exception:
        return None
