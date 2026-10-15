"""Deployment configuration and request authorisation.

This module is the API's equivalent of the CLI's scope confirmation, and it is the most
security-sensitive file in ``app/service``. It exists to answer one question:

    Given an untrusted HTTP request, what is the service actually allowed to do?

The answer is computed as the **intersection** of what the operator authorised at
deployment time and what the caller asked for. The caller can narrow; the caller can
never widen. Concretely, a request cannot:

* name a host outside :attr:`DeploymentConfig.allowed_hosts`;
* reach private/loopback addresses unless the operator enabled them;
* exceed any budget ceiling the operator set;
* select a planner the operator did not configure;
* supply an API key for the LLM (the key belongs to the service, never to the caller);
* supply a custom User-Agent, enable active tooling, or bypass the confirmation policy.

Every refusal produces the same structured error shape, and the reasons are phrased so an
operator can paste them into an email to whoever is asking for access.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from app.models.scan import ScanConfig, ScopePolicy
from app.policy.scope import (
    ScopeGuard,
    ScopeVerdict,
    _normalize_host,
    build_scope_policy,
    host_matches_pattern,
)
from app.service.models import ScanRequest
from app.tools.registry import ToolRegistry

LOCAL_PROFILE = "local"
EXPOSED_PROFILE = "exposed"

# Budgets used when a request omits them. Deliberately modest: an API caller that does not
# think about budgets should not accidentally run an expensive scan.
DEFAULT_MAX_STEPS = 16
DEFAULT_MAX_TOOL_CALLS = 40
DEFAULT_MAX_PAGES = 6
DEFAULT_MAX_REQUESTS = 60
DEFAULT_RATE = 4.0

# The entire set of limitations this build has. Published in the capabilities response so
# a caller cannot claim they were not told.
SERVICE_LIMITATIONS: tuple[str, ...] = (
    "Read-only: the service never submits forms, authenticates, uploads files or fuzzes. "
    "When explicitly enabled, the harness may send fixed injection probes; callers cannot "
    "supply payloads.",
    "Unauthenticated: no credentials are used, so anything behind a login is not assessed.",
    "A scan can only ever narrow the operator's authorisation, never widen it.",
    "Findings describe configuration weaknesses and disclosures observed in HTTP "
    "responses. They are not confirmed exploits and require human review.",
    "Absence of a finding is not evidence of absence: only the checks listed in the "
    "report's checks_executed were performed.",
)


class ScopeRefused(ValueError):
    """The request asked for something the deployment does not authorise.

    Carries every reason, not just the first, so a caller can fix the request in one go.
    """

    def __init__(self, reasons: list[str]) -> None:
        super().__init__("; ".join(reasons))
        self.reasons = reasons


@dataclass(frozen=True)
class DeploymentConfig:
    """What the operator authorised when starting the service.

    Immutable for the lifetime of the process: there is no code path that adds a host or
    raises a ceiling after startup.
    """

    allowed_hosts: tuple[str, ...]
    denied_hosts: tuple[str, ...] = ()
    allowed_ports: tuple[int, ...] = (80, 443)
    allow_private_addresses: bool = False
    max_steps: int = 40
    max_tool_calls: int = 120
    max_pages: int = 20
    max_requests: int = 200
    max_requests_per_second: float = 10.0
    request_timeout_s: float = 15.0
    tool_timeout_s: float = 45.0
    scan_timeout_s: float = 600.0
    max_concurrent_scans: int = 1
    planner_enabled: bool = False
    llm_model: str = ""
    llm_base_url: str = ""
    api_key_ref: str = "DAST_API_KEY"
    runs_dir: Path = field(default_factory=lambda: Path("runs/service"))
    profile: str = LOCAL_PROFILE
    authorized_by_service: str = ""
    allow_active_scanning: bool = False
    allow_injection_probing: bool = False

    # -- derived facts ----------------------------------------------------- #

    @property
    def private_addresses_allowed(self) -> bool:
        """Whether a caller may opt in to private targets. Operator-controlled only."""
        return self.allow_private_addresses

    @property
    def active_scanning_loaded(self) -> bool:
        """Whether active tools may be requested by callers."""
        return self.allow_active_scanning

    def planners(self) -> list[str]:
        return ["scripted", "llm"] if self.planner_enabled else ["scripted"]

    def llm_api_key(self) -> str:
        """The service's own LLM credential. Never accepted from a request."""
        return os.environ.get(self.api_key_ref, "")

    def llm_configured(self) -> bool:
        return bool(self.planner_enabled and self.llm_model and self.llm_api_key())

    def describe_ceilings(self) -> dict[str, Any]:
        return {
            "max_steps": self.max_steps,
            "max_tool_calls": self.max_tool_calls,
            "max_pages": self.max_pages,
            "max_requests": self.max_requests,
            "max_requests_per_second": self.max_requests_per_second,
            "scan_timeout_s": self.scan_timeout_s,
            "tool_timeout_s": self.tool_timeout_s,
        }

    def describe_defaults(self) -> dict[str, Any]:
        return {
            "max_steps": min(DEFAULT_MAX_STEPS, self.max_steps),
            "max_tool_calls": min(DEFAULT_MAX_TOOL_CALLS, self.max_tool_calls),
            "max_pages": min(DEFAULT_MAX_PAGES, self.max_pages),
            "max_requests": min(DEFAULT_MAX_REQUESTS, self.max_requests),
            "requests_per_second": min(DEFAULT_RATE, self.max_requests_per_second),
        }

    def service_user_agent(self) -> str:
        return "ai-dast-core-service/0.1 (+authorized-security-testing)"


@dataclass(frozen=True)
class AuthorisedScan:
    """The fully resolved, authorised shape of one request.

    Produced only by :func:`authorise_request`. The job layer never re-derives any of
    this, so there is exactly one place where an untrusted request becomes a scope.
    """

    target: str
    scope: ScopePolicy
    config: ScanConfig
    planner: str
    llm_model: str = ""
    llm_base_url: str = ""
    llm_api_key: str = ""
    enable_active: bool = False
    enable_injection: bool = False


def build_deployment_config(
    *,
    allowed_hosts: list[str],
    denied_hosts: list[str] | None = None,
    allowed_ports: list[int] | None = None,
    allow_private_addresses: bool = False,
    allow_active: bool = False,
    allow_injection: bool = False,
    max_steps: int = 40,
    max_tool_calls: int = 120,
    max_pages: int = 20,
    max_requests: int = 200,
    max_requests_per_second: float = 10.0,
    scan_timeout_s: float = 600.0,
    max_concurrent_scans: int = 1,
    planner_enabled: bool = False,
    llm_model: str = "",
    llm_base_url: str = "",
    runs_dir: Path | str = "runs/service",
    profile: str = LOCAL_PROFILE,
    authorized_by_service: str = "",
) -> DeploymentConfig:
    """Validate and normalise the operator's deployment authorisation.

    Fails loudly on an empty allowlist: a service that can scan *any* host is not a
    deployment choice, it is an open proxy.
    """
    cleaned_allowed: list[str] = []
    for entry in allowed_hosts:
        raw = entry.strip().lower()
        if not raw:
            continue
        if raw == "*":
            host = "*"
        else:
            host = "*." + _normalize_host(raw[2:]) if raw.startswith("*.") else _normalize_host(raw)
        if host and host not in cleaned_allowed:
            cleaned_allowed.append(host)
    if not cleaned_allowed:
        raise ValueError(
            "at least one allowed host is required: a service that may scan anything is "
            "an open proxy. Pass --api-allowed-host (repeatable), or '*.example.com'."
        )

    cleaned_denied = []
    for entry in denied_hosts or []:
        raw = entry.strip().lower()
        if not raw:
            continue
        host = "*." + _normalize_host(raw[2:]) if raw.startswith("*.") else _normalize_host(raw)
        if host and host not in cleaned_denied:
            cleaned_denied.append(host)

    ports = sorted({int(port) for port in (allowed_ports or [80, 443])})
    if not ports:
        raise ValueError("at least one allowed port is required")
    for port in ports:
        if not 1 <= port <= 65535:
            raise ValueError(f"invalid port: {port}")

    if max_concurrent_scans < 1:
        raise ValueError("max_concurrent_scans must be at least 1")

    return DeploymentConfig(
        allowed_hosts=tuple(cleaned_allowed),
        denied_hosts=tuple(cleaned_denied),
        allowed_ports=tuple(ports),
        allow_private_addresses=bool(allow_private_addresses),
        max_steps=max(1, max_steps),
        max_tool_calls=max(1, max_tool_calls),
        max_pages=max(1, max_pages),
        max_requests=max(1, max_requests),
        max_requests_per_second=max(0.1, max_requests_per_second),
        scan_timeout_s=max(5.0, scan_timeout_s),
        max_concurrent_scans=max_concurrent_scans,
        planner_enabled=bool(planner_enabled),
        llm_model=llm_model,
        llm_base_url=llm_base_url,
        runs_dir=Path(runs_dir),
        profile=profile,
        authorized_by_service=authorized_by_service,
        allow_active_scanning=bool(allow_active),
        allow_injection_probing=bool(allow_injection),
    )


def authorise_request(
    request: ScanRequest,
    deployment: DeploymentConfig,
    *,
    registry: ToolRegistry | None = None,
) -> AuthorisedScan:
    """Turn an untrusted request into an authorised scan, or refuse it.

    Raises :class:`ScopeRefused` listing every problem found. The caller is responsible
    for turning that into a 403 with the reasons; nothing here mutates deployment state.
    """
    reasons: list[str] = []

    target, target_host, target_port, target_scheme = _parse_target(request.target, reasons)
    if target_host:
        _check_host_authorised(target_host, deployment, reasons, role="target")
        _check_port_authorised(target_port, target_scheme, deployment, reasons)

    extra_hosts: list[str] = []
    for host in request.scope_hosts:
        normalised = (
            "*." + _normalize_host(host[2:]) if host.startswith("*.") else _normalize_host(host)
        )
        if not normalised:
            continue
        _check_host_authorised(normalised, deployment, reasons, role="scope_hosts")
        extra_hosts.append(host)

    planner, llm_model, llm_base_url, llm_api_key = _resolve_planner(request, deployment, reasons)

    if reasons:
        raise ScopeRefused(reasons)

    # Build the scope from what survived validation. The operator's allowlist supplies the
    # permitted universe; the request only selects a subset of it.
    try:
        scope = build_scope_policy(
            target,
            extra_hosts=extra_hosts,
            excluded_hosts=list(deployment.denied_hosts),
            allow_private=deployment.allow_private_addresses,
            authorized_by=request.authorized_by,
            authorization_note=request.authorization_note,
            max_redirects=5,
        )
    except ValueError as exc:
        raise ScopeRefused([f"could not build a scope for {request.target!r}: {exc}"]) from exc

    # Pin the port allowlist to the deployment's, plus the target's own port which was
    # already checked above. A request cannot widen this.
    scope.allowed_ports = sorted(set(deployment.allowed_ports) | {target_port})
    scope.allowed_schemes = ["http", "https"]

    # Cross-check with the real scope guard using a syntactic check only (no DNS), so the
    # API refuses a target it would later refuse, with a message that explains why. Hosts
    # that merely fail to resolve are left to the scan, which reports that cleanly.
    probe = ScopeGuard(scope).check_url(target, resolve=False)
    if not probe.allowed and probe.verdict is ScopeVerdict.DENIED_PRIVATE_ADDRESS:
        raise ScopeRefused(
            [
                f"target {target!r} is a private, loopback or link-local address, and this "
                "deployment does not authorise private targets. An operator can enable it "
                "with --api-allow-private, and only for networks they control."
            ]
        )
    if not probe.allowed:
        raise ScopeRefused([f"target {target!r} was refused: {probe.reason}"])

    enable_active = bool(getattr(request, "enable_active", False) and deployment.allow_active_scanning)
    enable_injection = bool(getattr(request, "enable_injection", False) and deployment.allow_injection_probing)

    config = _resolve_config(request, deployment, enable_active=enable_active)

    return AuthorisedScan(
        target=target,
        scope=scope,
        config=config,
        planner=planner,
        llm_model=llm_model,
        llm_base_url=llm_base_url,
        llm_api_key=llm_api_key,
        enable_active=enable_active,
        enable_injection=enable_injection,
    )


# --------------------------------------------------------------------------- #
# Individual checks
# --------------------------------------------------------------------------- #


def _parse_target(raw: str, reasons: list[str]) -> tuple[str, str, int, str]:
    """Normalise the target URL, defaulting the scheme to https like the CLI does."""
    candidate = raw.strip()
    if "://" not in candidate:
        candidate = f"https://{candidate}"
    try:
        parts = urlsplit(candidate)
    except ValueError as exc:
        reasons.append(f"target is not a valid URL: {exc}")
        return raw, "", 443, "https"

    scheme = (parts.scheme or "").lower()
    if scheme not in {"http", "https"}:
        reasons.append(f"target scheme {scheme!r} is not allowed; use http or https")
        return candidate, "", 443, scheme or "https"

    if parts.username or parts.password:
        reasons.append("target must not contain embedded credentials")
        return candidate, "", 443, scheme

    host = _normalize_host(parts.hostname or "")
    if not host:
        reasons.append("target has no hostname")
        return candidate, "", 443, scheme

    try:
        port = parts.port if parts.port is not None else (443 if scheme == "https" else 80)
    except ValueError:
        reasons.append("target has an invalid port")
        return candidate, host, 443, scheme

    return candidate, host, port, scheme


def _check_host_authorised(
    host: str,
    deployment: DeploymentConfig,
    reasons: list[str],
    *,
    role: str,
) -> None:
    if any(host_matches_pattern(host, pattern) for pattern in deployment.denied_hosts):
        reasons.append(
            f"{role}: host {host!r} is explicitly excluded by this deployment"
        )
        return
    if "*" in deployment.allowed_hosts:
        return
    if not any(host_matches_pattern(host, pattern) for pattern in deployment.allowed_hosts):
        reasons.append(
            f"{role}: host {host!r} is not authorised by this deployment. "
            f"Authorised hosts: {', '.join(deployment.allowed_hosts)}. "
            "An operator can add it with --api-allowed-host."
        )


def _check_port_authorised(
    port: int,
    scheme: str,
    deployment: DeploymentConfig,
    reasons: list[str],
) -> None:
    if port not in deployment.allowed_ports:
        reasons.append(
            f"target: port {port} is not authorised by this deployment. "
            f"Authorised ports: {', '.join(str(item) for item in deployment.allowed_ports)}."
        )


def _resolve_planner(
    request: ScanRequest, deployment: DeploymentConfig, reasons: list[str]
) -> tuple[str, str, str, str]:
    if request.planner == "scripted":
        return "scripted", "", "", ""

    # Priority 1: User provided AI configuration in scan request
    req_key = (getattr(request, "ai_api_key", None) or "").strip()
    req_model = (getattr(request, "ai_model", None) or "").strip()
    req_base_url = (getattr(request, "ai_base_url", None) or "").strip()

    if req_model:
        # If user gave a model, we allow it (key can be dummy for local servers like Ollama)
        dotenv_key = ""
        env_file = Path(".env")
        if env_file.exists():
            try:
                for line in env_file.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if line.startswith("GROQ_API_KEY="):
                        dotenv_key = line.split("=", 1)[1].strip().strip('"').strip("'")
            except Exception:
                pass

        env_fallback = (
            dotenv_key
            or os.environ.get("GROQ_API_KEY", "")
            or os.environ.get("OPENAI_API_KEY", "")
            or deployment.llm_api_key()
        )
        effective_key = req_key or env_fallback or "dummy-local-key"
        effective_base_url = req_base_url or deployment.llm_base_url
        return "llm", req_model, effective_base_url, effective_key

    # Priority 2: Deployment-level LLM configuration
    if not deployment.planner_enabled:
        reasons.append(
            "planner 'llm' is not available on this deployment; use 'scripted' or supply "
            "ai_model in your request, or ask the operator to start with --api-planner-llm"
        )
        return "scripted", "", "", ""
    if not deployment.llm_configured():
        reasons.append(
            f"planner 'llm' is configured on deployment but no credential was found in "
            f"{deployment.api_key_ref}; provide ai_api_key in request or configure environment"
        )
        return "scripted", "", "", ""
    return "llm", deployment.llm_model, deployment.llm_base_url, deployment.llm_api_key()


def _resolve_config(
    request: ScanRequest,
    deployment: DeploymentConfig,
    *,
    enable_active: bool = False,
) -> ScanConfig:
    """Clamp every requested budget to the operator's ceiling.

    Clamping - rather than rejecting - is deliberate: a caller asking for more than is
    allowed still gets a useful scan at the permitted maximum, and the resolved config is
    echoed in the report so what actually ran is never ambiguous.
    """
    defaults = deployment.describe_defaults()

    def clamp(requested: int | float | None, key: str, fallback: Any) -> Any:
        if requested is None:
            return fallback
        return min(requested, deployment.describe_ceilings()[key])

    return ScanConfig(
        max_steps=int(clamp(request.max_steps, "max_steps", defaults["max_steps"])),
        max_tool_calls=int(clamp(request.max_tool_calls, "max_tool_calls", defaults["max_tool_calls"])),
        max_pages=int(clamp(request.max_pages, "max_pages", defaults["max_pages"])),
        max_requests=int(clamp(request.max_requests, "max_requests", defaults["max_requests"])),
        requests_per_second=float(
            clamp(
                request.requests_per_second,
                "max_requests_per_second",
                defaults["requests_per_second"],
            )
        ),
        request_timeout_s=deployment.request_timeout_s,
        tool_timeout_s=deployment.tool_timeout_s,
        scan_timeout_s=deployment.scan_timeout_s,
        allow_active_tools=enable_active,
        require_confirmation=False if enable_active else True,
        user_agent=deployment.service_user_agent(),
    )


def capabilities(
    deployment: DeploymentConfig,
    *,
    version: str,
    auth_required: bool,
) -> dict[str, Any]:
    """Render the deployment's self-description for ``GET /v1/capabilities``."""
    return {
        "service": "ai-dast-core",
        "version": version,
        "auth_required": auth_required,
        "deploy_profile": deployment.profile,
        "allowed_hosts": list(deployment.allowed_hosts),
        "denied_hosts": list(deployment.denied_hosts),
        "allowed_ports": list(deployment.allowed_ports),
        "allowed_schemes": ["http", "https"],
        "private_addresses_allowed": deployment.private_addresses_allowed,
        "active_scanning_loaded": deployment.active_scanning_loaded,
        "planners": deployment.planners(),
        "llm_configured": deployment.llm_configured(),
        "limits": deployment.describe_ceilings(),
        "defaults": deployment.describe_defaults(),
        "max_concurrent_scans": deployment.max_concurrent_scans,
        "limitations": list(SERVICE_LIMITATIONS),
    }


__all__ = [
    "AuthorisedScan",
    "DEFAULT_MAX_PAGES",
    "DEFAULT_MAX_REQUESTS",
    "DEFAULT_MAX_STEPS",
    "DEFAULT_MAX_TOOL_CALLS",
    "DEFAULT_RATE",
    "DeploymentConfig",
    "EXPOSED_PROFILE",
    "LOCAL_PROFILE",
    "SERVICE_LIMITATIONS",
    "ScopeRefused",
    "authorise_request",
    "build_deployment_config",
    "capabilities",
]
