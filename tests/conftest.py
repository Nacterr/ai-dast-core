"""Test fixtures: a live local demo target and a fully wired scan context.

The fixtures bind to 127.0.0.1 on an ephemeral port, so the suite never touches an
external system. The scan context is built with ``allow_private_addresses=True`` because
the target *is* a loopback address - the same opt-in the CLI exposes as ``--allow-private``.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

from app.models.scan import AttackSurface, ScanConfig, ScanSession, ScanStatus, ScopePolicy
from app.policy.limits import LimitTracker
from app.policy.permissions import ConfirmationGate, PermissionSet
from app.policy.scope import ScopeGuard, build_scope_policy
from app.tools.catalog import build_default_registry
from app.tools.context import ToolContext
from app.tools.registry import ToolRegistry
from tools.demo_target import make_server
from tools.safe_target import make_server as make_safe_server


@pytest.fixture(scope="session")
def demo_server() -> Iterator[str]:
    """A live local HTTP target, yielded as its base URL."""
    server = make_server("127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[0], server.server_address[1]
    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.fixture(scope="session")
def demo_safe_server() -> Iterator[str]:
    """A live local hardened comparison target, also bound to loopback."""
    server = make_safe_server("127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[0], server.server_address[1]
    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.fixture()
def registry() -> ToolRegistry:
    return build_default_registry()


@pytest.fixture()
def callable_registry() -> ToolRegistry:
    return build_default_registry(include_roadmap=False)


def make_scope(target: str, **overrides) -> ScopePolicy:
    """Scope that permits the loopback demo target."""
    params = {
        "allow_private": True,
        "authorized_by": "test-suite",
        "authorization_note": "local demo target owned by the test suite",
    }
    params.update(overrides)
    return build_scope_policy(target, **params)


def make_session(target: str, config: ScanConfig | None = None, **scope_overrides) -> ScanSession:
    return ScanSession(
        scan_id="scan-test-0001",
        scope=make_scope(target, **scope_overrides),
        config=config or ScanConfig(max_pages=4, max_requests=60, requests_per_second=50.0),
        status=ScanStatus.RUNNING,
        surface=AttackSurface(target=target),
    )


@pytest.fixture()
def ctx_factory(tmp_path: Path):
    """Build a ToolContext for a target, with cleanup handled at teardown."""
    created: list[ToolContext] = []

    def factory(
        target: str,
        *,
        config: ScanConfig | None = None,
        permissions: PermissionSet | None = None,
        scope_overrides: dict | None = None,
    ) -> ToolContext:
        session = make_session(target, config, **(scope_overrides or {}))
        context = ToolContext(
            session=session,
            scope=ScopeGuard(session.scope),
            limits=LimitTracker(session.config),
            artifact_dir=tmp_path / "artifacts",
            permissions=permissions or PermissionSet(),
            confirmation=ConfirmationGate(interactive=False, auto_approve=True),
            quiet=True,
            # Mirror what ScanRunner wires up, so the result tools see a realistic
            # transaction log when a test drives the registry directly.
            exchange_sink=lambda exchange: _record_exchange(session, exchange),
        )
        created.append(context)
        return context

    yield factory

    for context in created:
        context.close()


def _record_exchange(session: ScanSession, exchange) -> None:
    """Replica of the loop's exchange recorder, for tests that bypass the orchestrator."""
    from app.models.scan import HttpExchangeRecord

    headers = exchange.headers or {}
    session.surface.record_exchange(
        HttpExchangeRecord(
            requested_url=exchange.requested_url,
            final_url=exchange.final_url,
            method=exchange.hops[0].method if exchange.hops else "GET",
            status_code=exchange.status_code,
            redirect_chain=[hop.url for hop in exchange.hops],
            content_type=str(headers.get("content-type", ""))[:200],
            body_bytes=exchange.body_bytes,
            total_ms=sum(hop.elapsed_ms for hop in exchange.hops),
            error=exchange.error or "",
        )
    )
