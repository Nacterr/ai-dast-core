"""HTTP service tests.

Two groups:

* **Authorisation** (no browser, no network) — the rules that decide what an untrusted
  request is allowed to touch. This is the security-critical half and runs fast.
* **API behaviour** (``integration``) — the endpoints driven through a real in-process
  ASGI client, including one full scan against the local demo target.

The theme throughout: the API caller is untrusted, and the deployment config is the only
source of authority.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.service.api import build_app_from_args, create_app
from app.service.config import (
    EXPOSED_PROFILE,
    LOCAL_PROFILE,
    ScopeRefused,
    authorise_request,
    build_deployment_config,
    capabilities,
)
from app.service.jobs import JobStore
from app.service.models import JobState, ScanRequest

API_KEY = "test-key-0123456789"


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


@pytest.fixture()
def deployment():
    return build_deployment_config(
        allowed_hosts=["example.com", "*.example.com"],
        allowed_ports=[80, 443],
        allow_private_addresses=False,
        max_steps=10,
        max_tool_calls=20,
        max_pages=4,
        max_requests=30,
        max_requests_per_second=5.0,
    )


@pytest.fixture()
def client(tmp_path: Path):
    app = build_app_from_args(
        allowed_hosts=["127.0.0.1"],
        allowed_ports=[80],
        allow_private=True,
        api_key=API_KEY,
        bind_host="127.0.0.1",
        runs_dir=tmp_path / "service",
        max_steps=10,
        max_pages=2,
        max_requests=20,
    )
    with TestClient(app) as test_client:
        yield test_client


def auth() -> dict[str, str]:
    return {"Authorization": f"Bearer {API_KEY}"}


def request_for(target: str, **overrides) -> ScanRequest:
    payload = {"target": target, "authorized_by": "tester@example.com"}
    payload.update(overrides)
    return ScanRequest(**payload)


# --------------------------------------------------------------------------- #
# Deployment configuration
# --------------------------------------------------------------------------- #


def test_empty_allowlist_is_refused() -> None:
    """A service that may scan anything is an open proxy, not a deployment."""
    with pytest.raises(ValueError, match="allowed host"):
        build_deployment_config(allowed_hosts=[])


def test_allowlist_is_normalised() -> None:
    deployment = build_deployment_config(allowed_hosts=["Example.COM.", "  *.Example.COM "])
    assert "example.com" in deployment.allowed_hosts
    assert "*.example.com" in deployment.allowed_hosts


def test_invalid_port_is_refused() -> None:
    with pytest.raises(ValueError, match="invalid port"):
        build_deployment_config(allowed_hosts=["example.com"], allowed_ports=[99999])


def test_active_scanning_is_never_loaded() -> None:
    deployment = build_deployment_config(allowed_hosts=["example.com"])
    assert deployment.active_scanning_loaded is False


def test_capabilities_discloses_the_limits(deployment) -> None:
    described = capabilities(deployment, version="0.1.0", auth_required=True)
    assert described["allowed_hosts"] == ["example.com", "*.example.com"]
    assert described["active_scanning_loaded"] is False
    assert described["private_addresses_allowed"] is False
    assert described["planners"] == ["scripted"]
    assert described["limits"]["max_steps"] == 10
    assert len(described["limitations"]) >= 5


# --------------------------------------------------------------------------- #
# Authorisation: the request may only narrow
# --------------------------------------------------------------------------- #


def test_target_inside_the_allowlist_is_authorised(deployment) -> None:
    authorised = authorise_request(request_for("https://example.com/app"), deployment)
    assert authorised.target == "https://example.com/app"
    assert "example.com" in authorised.scope.allowed_hosts
    assert authorised.planner == "scripted"


def test_target_outside_the_allowlist_is_refused(deployment) -> None:
    with pytest.raises(ScopeRefused) as excinfo:
        authorise_request(request_for("https://evil.test/"), deployment)
    assert "not authorised" in str(excinfo.value)


def test_wildcard_allowlist_matches_subdomains_but_not_the_apex() -> None:
    deployment = build_deployment_config(allowed_hosts=["*.example.com"])
    with pytest.raises(ScopeRefused):
        authorise_request(request_for("https://example.com/"), deployment)
    authorised = authorise_request(request_for("https://app.example.com/"), deployment)
    assert authorised.scope.allowed_hosts == ["app.example.com"]


def test_request_cannot_add_a_host_the_operator_never_authorised(deployment) -> None:
    """``scope_hosts`` narrows within the allowlist; it does not extend it."""
    with pytest.raises(ScopeRefused, match="scope_hosts"):
        authorise_request(
            request_for("https://example.com/", scope_hosts=["internal.corp"]), deployment
        )


def test_request_can_narrow_to_a_permitted_host() -> None:
    deployment = build_deployment_config(allowed_hosts=["*.example.com"])
    authorised = authorise_request(
        request_for("https://app.example.com/", scope_hosts=["api.example.com"]), deployment
    )
    assert "api.example.com" in authorised.scope.allowed_hosts


def test_private_targets_are_refused_without_the_operator_opt_in() -> None:
    deployment = build_deployment_config(
        allowed_hosts=["127.0.0.1"], allowed_ports=[8000], allow_private_addresses=False
    )
    with pytest.raises(ScopeRefused) as excinfo:
        authorise_request(request_for("http://127.0.0.1:8000/"), deployment)
    assert "private" in str(excinfo.value).lower()


def test_private_targets_are_allowed_with_the_opt_in() -> None:
    deployment = build_deployment_config(
        allowed_hosts=["127.0.0.1"], allowed_ports=[8000], allow_private_addresses=True
    )
    authorised = authorise_request(request_for("http://127.0.0.1:8000/"), deployment)
    assert authorised.scope.allow_private_addresses is True


@pytest.mark.parametrize(
    "target",
    [
        "file:///etc/passwd",
        "gopher://example.com/",
        "ftp://example.com/",
    ],
)
def test_non_http_schemes_are_refused(deployment, target: str) -> None:
    with pytest.raises(ScopeRefused):
        authorise_request(request_for(target), deployment)


def test_unlisted_port_is_refused(deployment) -> None:
    with pytest.raises(ScopeRefused) as excinfo:
        authorise_request(request_for("https://example.com:8443/"), deployment)
    assert "port" in str(excinfo.value)


def test_embedded_credentials_in_target_are_refused(deployment) -> None:
    with pytest.raises(ScopeRefused):
        authorise_request(request_for("https://user:pass@example.com/"), deployment)


def test_scheme_defaults_to_https(deployment) -> None:
    authorised = authorise_request(request_for("example.com"), deployment)
    assert authorised.target == "https://example.com"


def test_llm_planner_is_refused_when_not_configured(deployment) -> None:
    with pytest.raises(ScopeRefused, match="planner 'llm' is not available"):
        authorise_request(request_for("https://example.com/", planner="llm"), deployment)


def test_llm_planner_is_refused_when_configured_but_uncredentialed(monkeypatch) -> None:
    monkeypatch.delenv("DAST_API_KEY", raising=False)
    deployment = build_deployment_config(
        allowed_hosts=["example.com"], planner_enabled=True, llm_model="gpt-4o-mini"
    )
    with pytest.raises(ScopeRefused, match="credential"):
        authorise_request(request_for("https://example.com/", planner="llm"), deployment)


def test_llm_planner_works_when_fully_configured(monkeypatch) -> None:
    monkeypatch.setenv("DAST_API_KEY", "sk-test")
    deployment = build_deployment_config(
        allowed_hosts=["example.com"], planner_enabled=True, llm_model="gpt-4o-mini"
    )
    authorised = authorise_request(request_for("https://example.com/", planner="llm"), deployment)
    assert authorised.planner == "llm"
    assert authorised.llm_model == "gpt-4o-mini"


def test_budgets_are_clamped_to_the_ceiling(deployment) -> None:
    authorised = authorise_request(
        request_for("https://example.com/", max_steps=400, max_requests=3000), deployment
    )
    assert authorised.config.max_steps == 10
    assert authorised.config.max_requests == 30
    assert authorised.config.max_pages == 4


def test_budgets_below_the_ceiling_are_honoured(deployment) -> None:
    authorised = authorise_request(
        request_for("https://example.com/", max_steps=3, max_pages=1), deployment
    )
    assert authorised.config.max_steps == 3
    assert authorised.config.max_pages == 1


def test_omitted_budgets_use_the_modest_defaults() -> None:
    deployment = build_deployment_config(allowed_hosts=["example.com"], max_steps=99, max_pages=99)
    authorised = authorise_request(request_for("https://example.com/"), deployment)
    assert authorised.config.max_steps < 99
    assert authorised.config.max_pages < 99


def test_request_cannot_enable_active_tools_or_disable_confirmation(deployment) -> None:
    """These are not request fields at all; the resolved config proves it."""
    authorised = authorise_request(
        request_for("https://example.com/", max_steps=5), deployment
    )
    assert authorised.config.allow_active_tools is False
    assert authorised.config.require_confirmation is True


def test_request_cannot_override_the_user_agent(deployment) -> None:
    authorised = authorise_request(request_for("https://example.com/"), deployment)
    assert "ai-dast-core-service" in authorised.config.user_agent


def test_scope_exclusions_from_the_deployment_are_preserved() -> None:
    deployment = build_deployment_config(
        allowed_hosts=["*.example.com"], denied_hosts=["legacy.example.com"], allow_private_addresses=True
    )
    authorised = authorise_request(request_for("https://app.example.com/"), deployment)
    assert "legacy.example.com" in authorised.scope.excluded_hosts


def test_target_with_a_control_character_is_rejected_at_validation() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        ScanRequest(target="https://example.com/\nHost: evil.test", authorized_by="x")


def test_scope_hosts_with_a_slash_are_rejected() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        ScanRequest(target="https://example.com/", authorized_by="x", scope_hosts=["a/b"])


# --------------------------------------------------------------------------- #
# App construction guardrails
# --------------------------------------------------------------------------- #


def test_exposed_bind_without_a_key_is_refused(deployment) -> None:
    with pytest.raises(ValueError, match="without an API key"):
        create_app(deployment, api_key="", bind_host="0.0.0.0")


def test_exposed_bind_with_a_key_sets_the_exposed_profile(deployment) -> None:
    app = create_app(deployment, api_key=API_KEY, bind_host="0.0.0.0", start_workers=False)
    assert app.state.service.auth_required is True
    assert app.state.service.deployment.profile == EXPOSED_PROFILE


def test_loopback_bind_defaults_to_local_profile(deployment) -> None:
    app = create_app(deployment, api_key="", bind_host="127.0.0.1", start_workers=False)
    assert app.state.service.auth_required is False
    assert app.state.service.deployment.profile == LOCAL_PROFILE


def test_loopback_bind_with_a_key_requires_it(deployment) -> None:
    app = create_app(deployment, api_key=API_KEY, bind_host="127.0.0.1", start_workers=False)
    assert app.state.service.auth_required is True


# --------------------------------------------------------------------------- #
# Job store
# --------------------------------------------------------------------------- #


def test_queue_position_is_available_before_the_worker_starts(deployment, tmp_path: Path) -> None:
    store = JobStore(deployment, registry=None)
    store._accepting = True  # noqa: SLF001
    authorised = authorise_request(request_for("https://example.com/"), deployment)
    first = store.submit(authorised)
    second = store.submit(authorised)
    # No workers started, so both sit in the queue.
    assert store.get(first.job_id) is not None
    assert store.get(second.job_id) is not None
    assert store.queue_position(first.job_id) >= 0


def test_unknown_job_is_none(deployment) -> None:
    store = JobStore(deployment)
    assert store.get("job-does-not-exist") is None


def test_cancel_on_unknown_job_returns_false(deployment) -> None:
    store = JobStore(deployment)
    assert store.cancel("job-does-not-exist") is False


def test_cancelling_a_finished_job_returns_false(deployment) -> None:
    store = JobStore(deployment)
    authorised = authorise_request(request_for("https://example.com/"), deployment)
    job = store.submit(authorised)
    job.state = JobState.COMPLETED
    assert store.cancel(job.job_id) is False


def test_cancelling_a_queued_job_marks_it_cancelled(deployment) -> None:
    store = JobStore(deployment)
    authorised = authorise_request(request_for("https://example.com/"), deployment)
    job = store.submit(authorised)
    assert store.cancel(job.job_id, reason="test") is True
    assert store.get(job.job_id).state is JobState.CANCELLED


# --------------------------------------------------------------------------- #
# API surface
# --------------------------------------------------------------------------- #


def test_health_is_public(client: TestClient) -> None:
    response = client.get("/v1/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_capabilities_is_public(client: TestClient) -> None:
    response = client.get("/v1/capabilities")
    assert response.status_code == 200
    body = response.json()
    assert body["allowed_hosts"] == ["127.0.0.1"]
    assert body["active_scanning_loaded"] is False


def test_tools_requires_authentication(client: TestClient) -> None:
    assert client.get("/v1/tools").status_code == 401
    assert client.get("/v1/tools", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.get("/v1/tools", headers=auth()).status_code == 200


def test_tools_lists_every_registered_tool(client: TestClient) -> None:
    body = client.get("/v1/tools", headers=auth()).json()
    names = {tool["name"] for tool in body["tools"]}
    assert {"browser_open", "extract_links", "check_headers", "check_cookies"} <= names
    assert {"run_zap_baseline", "run_openapi_scan"} <= names
    # The roadmap tools are declared but not callable.
    roadmap = {
        tool["name"]: tool for tool in body["tools"] if tool["name"] in {"run_zap_baseline", "run_authenticated_crawl"}
    }
    assert all(not tool["implemented"] for tool in roadmap.values())
    openapi = next(tool for tool in body["tools"] if tool["name"] == "run_openapi_scan")
    assert openapi["implemented"] is True


def test_the_service_never_grants_active_scanning(client: TestClient) -> None:
    """A remote caller must not be able to reach the active-check tool.

    ``run_selected_active_check`` is implemented, but the service grants no ``active_scan``
    capability and there is no request field that could ask for one. A caller cannot turn a
    scan service into an active prober; only an operator running the CLI with ``--active``
    can, and only against a target they named.
    """
    from app.policy.permissions import Capability, PermissionSet

    state = client.app.state.service
    assert state.deployment.active_scanning_loaded is False

    # The capability the active tool requires is not in the default set the service uses.
    permissions = PermissionSet()
    assert permissions.allows(Capability.ACTIVE_SCAN) is False
    assert permissions.check(["http_egress", "active_scan"]) is not None


def test_the_service_builds_a_read_only_scan_config(client: TestClient) -> None:
    """Even a caller who knows about the active tool cannot switch it on."""
    from app.service.config import authorise_request
    from app.service.models import ScanRequest

    state = client.app.state.service
    # The client fixture authorises 127.0.0.1 on port 80 with private addresses enabled, so
    # a loopback target is what this deployment will accept.
    authorised = authorise_request(
        ScanRequest(target="http://127.0.0.1/", authorized_by="tester"),
        state.deployment,
    )
    assert authorised.config.allow_active_tools is False
    assert authorised.config.require_confirmation is True


def test_tools_can_include_schemas(client: TestClient) -> None:
    body = client.get("/v1/tools?include_schema=true", headers=auth()).json()
    entry = next(tool for tool in body["tools"] if tool["name"] == "browser_open")
    assert entry["schema"]["additionalProperties"] is False


def test_no_endpoint_runs_a_single_tool(client: TestClient) -> None:
    """The API must not expose a way to invoke one tool with caller-supplied arguments."""
    paths = {route.path for route in client.app.routes if hasattr(route, "path")}
    assert not any("tool" in path and "{" in path for path in paths)
    assert "/v1/tools" in paths  # listing is fine; invocation is not
    for method in ("post", "put", "patch"):
        response = getattr(client, method)("/v1/tools", headers=auth(), json={"args": {}})
        assert response.status_code in {404, 405}


def test_scan_submission_refuses_an_unauthorised_target(client: TestClient) -> None:
    response = client.post(
        "/v1/scans",
        headers=auth(),
        json={"target": "https://evil.test/", "authorized_by": "x"},
    )
    assert response.status_code == 403
    body = response.json()
    assert body["category"] == "forbidden_scope"
    assert "not authorised" in body["detail"]


def test_scan_submission_requires_an_authorizer(client: TestClient) -> None:
    response = client.post("/v1/scans", headers=auth(), json={"target": "http://127.0.0.1:80/"})
    assert response.status_code == 422


def test_scan_submission_requires_authentication(client: TestClient) -> None:
    response = client.post(
        "/v1/scans", json={"target": "http://127.0.0.1/", "authorized_by": "x"}
    )
    assert response.status_code == 401


def test_unknown_job_returns_404(client: TestClient) -> None:
    assert client.get("/v1/scans/job-nope", headers=auth()).status_code == 404
    assert client.get("/v1/scans/job-nope/report", headers=auth()).status_code == 404
    assert client.post("/v1/scans/job-nope/cancel", headers=auth()).status_code == 404


def test_web_ui_is_served(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert "ai-dast-core" in response.text
    assert "<!doctype html>" in response.text.lower()


def test_cli_serve_starts_scan_workers(tmp_path: Path) -> None:
    """Regression: ``serve`` must not disable the workers that process jobs.

    An earlier version passed ``start_workers=False`` to the app factory, which left every
    submitted job queued forever. This asserts the app the CLI builds does start them when
    its lifespan runs.
    """
    from app.main import build_parser, _build_config  # noqa: F401 - parser import is the point
    from app.service.api import build_app_from_args

    app = build_app_from_args(
        allowed_hosts=["127.0.0.1"],
        allowed_ports=[80],
        allow_private=True,
        api_key=API_KEY,
        bind_host="127.0.0.1",
        runs_dir=tmp_path / "service",
        start_workers=True,
    )
    with TestClient(app):
        # Entering the TestClient context runs the lifespan, which starts the workers.
        assert app.state.service.store._workers, "no scan workers were started"  # noqa: SLF001


def test_serve_defaults_to_starting_workers() -> None:
    """The factory default must be to start workers, so a caller cannot forget."""
    import inspect

    from app.service.api import build_app_from_args

    signature = inspect.signature(build_app_from_args)
    assert signature.parameters["start_workers"].default is True


# --------------------------------------------------------------------------- #
# Full scan over the API
# --------------------------------------------------------------------------- #


@pytest.mark.integration
def test_full_scan_over_the_api(tmp_path: Path, demo_server: str) -> None:
    """Submit, poll, and read a report - exactly what a remote client does."""
    from app.policy.scope import ScopeGuard

    port = int(demo_server.rsplit(":", 1)[1])
    app = build_app_from_args(
        allowed_hosts=["127.0.0.1"],
        allowed_ports=[port],
        allow_private=True,
        api_key=API_KEY,
        bind_host="127.0.0.1",
        runs_dir=tmp_path / "service",
        max_steps=20,
        max_pages=2,
        max_requests=30,
        max_rate=20.0,
    )

    with TestClient(app) as client:
        accepted = client.post(
            "/v1/scans",
            headers=auth(),
            json={
                "target": demo_server,
                "authorized_by": "api-tester@example.com",
                "authorization_note": "local demo target",
                "max_pages": 2,
            },
        )
        assert accepted.status_code == 202, accepted.text
        job_id = accepted.json()["job_id"]

        deadline = time.time() + 180
        job = None
        while time.time() < deadline:
            job = client.get(f"/v1/scans/{job_id}", headers=auth()).json()
            if job["state"] in {"completed", "failed", "cancelled"}:
                break
            time.sleep(0.5)

        assert job is not None
        assert job["state"] == "completed", job.get("error") or job["stop_reason"]
        assert job["progress"]["tool_calls_used"] > 0

        report_response = client.get(f"/v1/scans/{job_id}/report", headers=auth())
        assert report_response.status_code == 200
        report = report_response.json()["report"]

        assert len(report["findings"]) >= 8
        assert report["authorization"]["authorized_by"] == "api-tester@example.com"
        assert report["scope"]["allowed_hosts"] == ["127.0.0.1"]
        # Budgets were clamped by the deployment, and the report proves what ran.
        assert report["config"]["max_pages"] == 2
        assert report["config"]["allow_active_tools"] is False
        assert report["config"]["require_confirmation"] is True
        assert report["attack_surface"]["forms_total"] >= 3
        assert all(finding["evidence"] for finding in report["findings"])

        # The Markdown report and the event log are both retrievable.
        assert client.get(f"/v1/scans/{job_id}/report.md", headers=auth()).status_code == 200
        events = client.get(f"/v1/scans/{job_id}/events", headers=auth()).json()
        assert events["lines"]

        # And the job is in history.
        listing = client.get("/v1/scans", headers=auth()).json()
        assert any(entry["job_id"] == job_id for entry in listing["jobs"])


@pytest.mark.integration
def test_report_is_conflict_while_running(tmp_path: Path, demo_server: str) -> None:
    """Polling for a report too early must be a clean 409, not a 500."""
    port = int(demo_server.rsplit(":", 1)[1])
    app = build_app_from_args(
        allowed_hosts=["127.0.0.1"],
        allowed_ports=[port],
        allow_private=True,
        api_key=API_KEY,
        bind_host="127.0.0.1",
        runs_dir=tmp_path / "service",
        max_steps=20,
        max_pages=2,
        max_rate=20.0,
    )
    with TestClient(app) as client:
        accepted = client.post(
            "/v1/scans",
            headers=auth(),
            json={"target": demo_server, "authorized_by": "x", "max_pages": 2},
        )
        job_id = accepted.json()["job_id"]

        # Immediately after submission the report cannot exist yet.
        response = client.get(f"/v1/scans/{job_id}/report", headers=auth())
        assert response.status_code == 409
        assert response.json()["category"] == "conflict"


@pytest.mark.integration
def test_cancellation_stops_a_scan(tmp_path: Path, demo_server: str) -> None:
    port = int(demo_server.rsplit(":", 1)[1])
    app = build_app_from_args(
        allowed_hosts=["127.0.0.1"],
        allowed_ports=[port],
        allow_private=True,
        api_key=API_KEY,
        bind_host="127.0.0.1",
        runs_dir=tmp_path / "service",
        max_steps=40,
        max_pages=6,
        max_requests=60,
        max_rate=20.0,
    )
    with TestClient(app) as client:
        accepted = client.post(
            "/v1/scans",
            headers=auth(),
            json={"target": demo_server, "authorized_by": "x", "max_pages": 6},
        )
        job_id = accepted.json()["job_id"]

        cancel = client.post(f"/v1/scans/{job_id}/cancel", headers=auth())
        assert cancel.status_code == 200

        deadline = time.time() + 120
        job = None
        while time.time() < deadline:
            job = client.get(f"/v1/scans/{job_id}", headers=auth()).json()
            if job["state"] in {"completed", "failed", "cancelled"}:
                break
            time.sleep(0.5)

        assert job is not None
        assert job["state"] in {"cancelled", "completed"}
        if job["state"] == "cancelled":
            assert "cancel" in job["stop_reason"].lower()
