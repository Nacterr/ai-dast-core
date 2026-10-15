"""FastAPI application exposing the scanner as callable scan jobs.

Endpoint summary::

    GET    /                          self-contained web UI
    GET    /v1/health                 liveness, no auth
    GET    /v1/capabilities           what this deployment will and will not do
    GET    /v1/tools                  the tool catalogue and JSON Schemas
    POST   /v1/scans                  submit a scan, returns 202 with a job id
    GET    /v1/scans                  job history
    GET    /v1/scans/{id}             job status and progress
    GET    /v1/scans/{id}/report      JSON report (409 while still running)
    GET    /v1/scans/{id}/events      live log tail
    POST   /v1/scans/{id}/cancel      request cancellation
    GET    /v1/scans/{id}/report.md   Markdown report

Security posture:

* **Authentication is required for exposed deployments.** ``create_app`` refuses a
  non-loopback bind without an API key, so a powerful scanner cannot be published by
  accident. The comparison is constant-time.
* **The API cannot drive individual tools.** There is no endpoint that runs one tool with
  caller-supplied arguments. A caller submits a scan, and the service's own policy and
  planner decide what happens next.
* **Authorisation happens once, up front.** :func:`authorise_request` resolves the request
  into an immutable scope, or refuses it with reasons. Nothing downstream re-derives it.
"""

from __future__ import annotations

import contextlib
import hmac
import ipaddress
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from app import __version__
from app.service.config import (
    EXPOSED_PROFILE,
    LOCAL_PROFILE,
    DeploymentConfig,
    ScopeRefused,
    authorise_request,
    capabilities,
)
from app.service.jobs import JobStore
from app.service.models import (
    ErrorResponse,
    JobAccepted,
    JobList,
    JobState,
    JobStatus,
    ReportEnvelope,
    ScanRequest,
    ServerCapabilities,
    ToolListing,
)
from app.tools.catalog import build_default_registry
from app.reports.json_report import tool_categories

STATIC_DIR = Path(__file__).parent / "static"
_DEMO_SERVER: tuple[Any, str] | None = None

# --------------------------------------------------------------------------- #
# Application state
# --------------------------------------------------------------------------- #


class ServiceState:
    """Everything the app needs, assembled once at startup."""

    def __init__(
        self,
        deployment: DeploymentConfig,
        *,
        api_key: str = "",
        auth_required: bool = False,
    ) -> None:
        self.deployment = deployment
        self.api_key = api_key
        self.auth_required = auth_required
        self.registry = build_default_registry()
        self.store = JobStore(deployment, registry=self.registry)


def _loopback_only(host: str) -> bool:
    """Whether a bind address is reachable only from this machine."""
    candidate = host.strip().strip("[]").lower()
    if candidate in {"localhost", ""}:
        return True
    try:
        return ipaddress.ip_address(candidate).is_loopback
    except ValueError:
        # A hostname we cannot classify is treated as exposed.
        return False


def create_app(
    deployment: DeploymentConfig,
    *,
    api_key: str = "",
    bind_host: str = "127.0.0.1",
    auth_required: bool | None = None,
    start_workers: bool = True,
) -> FastAPI:
    """Build the FastAPI application.

    ``auth_required`` defaults to True for any non-loopback bind. An exposed deployment
    without a key raises immediately rather than serving unprotected.
    """
    exposed = not _loopback_only(bind_host)
    if auth_required is None:
        auth_required = exposed or bool(api_key)

    if exposed and not api_key:
        raise ValueError(
            f"refusing to bind to {bind_host!r} without an API key. An unauthenticated "
            "scanner on a network interface is an open relay for attacks. Pass --api-key, "
            "or bind to 127.0.0.1 for local use."
        )

    deployment_for_profile = deployment
    if deployment.profile != (EXPOSED_PROFILE if exposed else LOCAL_PROFILE):
        deployment_for_profile = _with_profile(
            deployment, EXPOSED_PROFILE if exposed else LOCAL_PROFILE
        )

    state = ServiceState(deployment_for_profile, api_key=api_key, auth_required=auth_required)

    @contextlib.asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        """Start the scan workers with the app and drain them on shutdown."""
        if start_workers:
            state.store.start()
        try:
            yield
        finally:
            # Cancels in-flight scans and joins the workers, so a browser process is never
            # left behind after the service stops.
            state.store.stop()

    app = FastAPI(
        title="ai-dast-core service",
        version=__version__,
        description=(
            "Scope-restricted web DAST scanner. Submit a scan, poll it, read the report. "
            "The authorisation of what may be scanned belongs to the deployment, not to "
            "the request."
        ),
        docs_url="/docs",
        redoc_url=None,
        lifespan=lifespan,
    )
    app.state.service = state

    # -- authentication ---------------------------------------------------- #

    async def require_auth(authorization: str | None = Header(default=None)) -> None:
        """Dependency enforcing the API key on every non-public endpoint."""
        if not state.auth_required:
            return
        presented = ""
        if authorization and authorization.lower().startswith("bearer "):
            presented = authorization[7:].strip()
        if not presented:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="missing bearer token; send 'Authorization: Bearer <api key>'",
                headers={"WWW-Authenticate": "Bearer"},
            )
        # Constant-time comparison so a wrong key cannot be discovered byte by byte.
        if not hmac.compare_digest(presented, state.api_key):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid API key",
                headers={"WWW-Authenticate": "Bearer"},
            )

    # -- error handling ---------------------------------------------------- #

    @app.exception_handler(ScopeRefused)
    async def scope_refused_handler(request: Request, exc: ScopeRefused) -> JSONResponse:
        """A refusal is a first-class response, not a 500."""
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content=ErrorResponse(
                error="the requested target is outside this deployment's authorisation",
                detail=" ".join(exc.reasons),
                category="forbidden_scope",
            ).model_dump(mode="json"),
        )

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
        """Normalise every HTTP error into the documented :class:`ErrorResponse` shape.

        FastAPI's default is ``{"detail": ...}``, which would make the documented schema a
        lie for 4xx responses. Clients should never have to handle two error shapes.
        """
        category = _category_for_status(exc.status_code)
        detail = exc.detail if isinstance(exc.detail, str) else str(exc.detail)
        return JSONResponse(
            status_code=exc.status_code,
            content=ErrorResponse(
                error=detail,
                detail="",
                category=category,
            ).model_dump(mode="json"),
            headers=getattr(exc, "headers", None),
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        """Return schema violations as a readable list rather than a nested dump."""
        problems: list[str] = []
        for error in exc.errors()[:10]:
            location = ".".join(str(part) for part in error.get("loc", ())) or "(body)"
            problems.append(f"{location}: {error.get('msg', 'invalid')}")
        return JSONResponse(
            # Starlette renamed this status constant; keep the fallback for older
            # supported versions without touching the deprecated attribute.
            status_code=getattr(status, "HTTP_422_UNPROCESSABLE_CONTENT", 422),
            content=ErrorResponse(
                error="the request body did not satisfy the API schema",
                detail="; ".join(problems),
                category="invalid_request",
            ).model_dump(mode="json"),
        )

    # -- public endpoints -------------------------------------------------- #

    @app.get("/v1/health", tags=["meta"], summary="Liveness probe")
    async def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "service": "ai-dast-core",
            "version": __version__,
            "deploy_profile": state.deployment.profile,
        }

    @app.get(
        "/v1/capabilities",
        response_model=ServerCapabilities,
        tags=["meta"],
        summary="What this deployment will and will not do",
    )
    async def get_capabilities() -> ServerCapabilities:
        return ServerCapabilities.model_validate(
            capabilities(
                state.deployment,
                version=__version__,
                auth_required=state.auth_required,
            )
        )

    @app.get(
        "/v1/tools",
        response_model=ToolListing,
        tags=["meta"],
        summary="The tool catalogue",
        dependencies=[Depends(require_auth)],
    )
    async def list_tools(
        include_schema: bool = Query(default=False, description="Include each tool's JSON Schema.")
    ) -> ToolListing:
        listing: list[dict[str, Any]] = []
        for tool in state.registry:
            entry = tool.to_dict()
            if include_schema:
                entry["schema"] = tool.json_schema()
            listing.append(entry)
        return ToolListing(
            tools=listing,
            by_category=tool_categories(state.registry),
        )

    @app.post(
        "/v1/demo/start",
        tags=["meta"],
        summary="Start local demo target server for 1-click testing",
        dependencies=[Depends(require_auth)],
    )
    async def start_demo_server() -> dict[str, Any]:
        """Launch the bundled vulnerable demo server on loopback for instant 1-click scanning."""
        if not state.deployment.allow_private_addresses:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Demo target requires private/loopback addresses to be permitted (--api-allow-private).",
            )
        import threading
        from tools.demo_target import make_server

        global _DEMO_SERVER
        if _DEMO_SERVER is None:
            try:
                server = make_server("127.0.0.1", 8099)
            except OSError:
                server = make_server("127.0.0.1", 0)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            _DEMO_SERVER = (server, f"http://127.0.0.1:{server.server_address[1]}")

        return {
            "status": "ready",
            "target": _DEMO_SERVER[1],
            "message": "Demo target is running and ready to be scanned.",
        }

    # -- scan lifecycle ---------------------------------------------------- #

    @app.post(
        "/v1/scans",
        response_model=JobAccepted,
        status_code=status.HTTP_202_ACCEPTED,
        tags=["scans"],
        summary="Submit a scan",
        responses={
            403: {"model": ErrorResponse, "description": "Target outside authorisation"},
            503: {"model": ErrorResponse, "description": "Service not accepting scans"},
        },
        dependencies=[Depends(require_auth)],
    )
    async def submit_scan(request: ScanRequest) -> JobAccepted:
        """Authorise the request, then queue it.

        The authorisation step is the only place an untrusted request becomes a scope. If
        it raises, nothing is queued and no traffic is sent.
        """
        authorised = authorise_request(request, state.deployment, registry=state.registry)

        try:
            job = state.store.submit(authorised, authorization_note=request.authorization_note)
        except RuntimeError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=str(exc),
            ) from exc

        return JobAccepted(
            job_id=job.job_id,
            state=job.state,
            target=job.authorised.target,
            queue_position=state.store.queue_position(job.job_id),
            status_url=f"/v1/scans/{job.job_id}",
            report_url=f"/v1/scans/{job.job_id}/report",
        )

    @app.get(
        "/v1/scans",
        response_model=JobList,
        tags=["scans"],
        summary="Job history",
        dependencies=[Depends(require_auth)],
    )
    async def list_scans(
        limit: int = Query(default=50, ge=1, le=500),
    ) -> JobList:
        jobs = state.store.list_jobs(limit=limit)
        queued, running = state.store.counts()
        return JobList(
            jobs=[job.summary() for job in jobs],
            total=len(jobs),
            queued=queued,
            running=running,
        )

    @app.get(
        "/v1/scans/{job_id}",
        response_model=JobStatus,
        tags=["scans"],
        summary="Job status and progress",
        responses={404: {"model": ErrorResponse}},
        dependencies=[Depends(require_auth)],
    )
    async def get_scan(job_id: str) -> JobStatus:
        job = state.store.get(job_id)
        if job is None:
            raise _not_found(job_id)
        return job.status()

    @app.get(
        "/v1/scans/{job_id}/report",
        response_model=ReportEnvelope,
        tags=["scans"],
        summary="The JSON report",
        responses={
            404: {"model": ErrorResponse},
            409: {"model": ErrorResponse, "description": "Scan still running"},
        },
        dependencies=[Depends(require_auth)],
    )
    async def get_report(job_id: str) -> ReportEnvelope:
        job = state.store.get(job_id)
        if job is None:
            raise _not_found(job_id)
        if job.report is None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"scan is {job.state.value}; the report is available once it reaches a "
                    "terminal state"
                ),
            )
        return ReportEnvelope(job_id=job.job_id, state=job.state, report=job.report)

    @app.get(
        "/v1/scans/{job_id}/report.md",
        response_class=PlainTextResponse,
        tags=["scans"],
        summary="The Markdown report",
        dependencies=[Depends(require_auth)],
    )
    async def get_report_markdown(job_id: str) -> PlainTextResponse:
        job = state.store.get(job_id)
        if job is None:
            raise _not_found(job_id)
        path = state.deployment.runs_dir / job_id / "report.md"
        if not path.exists():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"scan is {job.state.value}; no Markdown report yet",
            )
        return PlainTextResponse(path.read_text(encoding="utf-8"), media_type="text/markdown")

    @app.get(
        "/v1/scans/{job_id}/events",
        tags=["scans"],
        summary="Live log tail",
        dependencies=[Depends(require_auth)],
    )
    async def get_events(
        job_id: str,
        tail: int = Query(default=200, ge=1, le=2000),
    ) -> dict[str, Any]:
        job = state.store.get(job_id)
        if job is None:
            raise _not_found(job_id)
        return {
            "job_id": job.job_id,
            "state": job.state.value,
            "lines": state.store.read_log(job, tail=tail),
        }

    @app.post(
        "/v1/scans/{job_id}/cancel",
        tags=["scans"],
        summary="Request cancellation",
        dependencies=[Depends(require_auth)],
    )
    async def cancel_scan(job_id: str) -> dict[str, Any]:
        job = state.store.get(job_id)
        if job is None:
            raise _not_found(job_id)
        if job.terminal:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"scan is already {job.state.value}",
            )
        accepted = state.store.cancel(job_id, reason="cancelled over the API")
        return {
            "job_id": job.job_id,
            "cancellation_requested": accepted,
            "state": state.store.get(job_id).state.value if state.store.get(job_id) else job.state.value,
            "note": "cancellation is observed at the next step boundary, not instantly",
        }

    def _not_found(job_id: str) -> HTTPException:
        return HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"no scan with id {job_id!r}",
        )

    # -- web UI ------------------------------------------------------------ #

    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    async def index() -> HTMLResponse:
        """Serve the self-contained web UI.

        The page holds no secrets: it asks the operator for the API key and keeps it in
        memory for the session only.
        """
        page = STATIC_DIR / "index.html"
        if not page.exists():
            return HTMLResponse(
                "<h1>ai-dast-core service</h1>"
                "<p>The web UI is not installed. Use the API directly; see "
                "<a href='/docs'>/docs</a>.</p>",
                status_code=200,
            )
        return HTMLResponse(page.read_text(encoding="utf-8"))

    return app


def _category_for_status(status_code: int) -> str:
    """Map an HTTP status onto the documented error category."""
    mapping = {
        400: "invalid_request",
        401: "unauthorized",
        403: "forbidden_scope",
        404: "not_found",
        409: "conflict",
        422: "invalid_request",
        503: "service_unavailable",
    }
    if status_code in mapping:
        return mapping[status_code]
    return "internal" if status_code >= 500 else "invalid_request"


def _with_profile(deployment: DeploymentConfig, profile: str) -> DeploymentConfig:
    """Return a copy of the deployment config with the profile field set."""
    from dataclasses import replace

    return replace(deployment, profile=profile)


def build_app_from_args(
    *,
    allowed_hosts: list[str],
    denied_hosts: list[str] | None = None,
    allowed_ports: list[int] | None = None,
    allow_private: bool = False,
    allow_active: bool = False,
    allow_injection: bool = False,
    api_key: str = "",
    bind_host: str = "127.0.0.1",
    runs_dir: str | Path = "runs/service",
    max_concurrent_scans: int = 1,
    max_steps: int = 40,
    max_tool_calls: int = 120,
    max_pages: int = 20,
    max_requests: int = 200,
    max_rate: float = 10.0,
    scan_timeout_s: float = 600.0,
    planner_enabled: bool = False,
    llm_model: str = "",
    llm_base_url: str = "",
    authorized_by_service: str = "",
    start_workers: bool = True,
) -> FastAPI:
    """Convenience constructor used by the CLI ``serve`` subcommand."""
    from app.service.config import build_deployment_config

    deployment = build_deployment_config(
        allowed_hosts=allowed_hosts,
        denied_hosts=denied_hosts,
        allowed_ports=allowed_ports,
        allow_private_addresses=allow_private,
        allow_active=allow_active,
        allow_injection=allow_injection,
        max_steps=max_steps,
        max_tool_calls=max_tool_calls,
        max_pages=max_pages,
        max_requests=max_requests,
        max_requests_per_second=max_rate,
        scan_timeout_s=scan_timeout_s,
        max_concurrent_scans=max_concurrent_scans,
        planner_enabled=planner_enabled,
        llm_model=llm_model,
        llm_base_url=llm_base_url,
        runs_dir=Path(runs_dir),
        authorized_by_service=authorized_by_service,
    )
    return create_app(
        deployment,
        api_key=api_key,
        bind_host=bind_host,
        start_workers=start_workers,
    )


__all__ = ["ServiceState", "build_app_from_args", "create_app"]
