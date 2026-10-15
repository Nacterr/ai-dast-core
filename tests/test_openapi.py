"""Tests for run_openapi_scan tool."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from app.models.finding import FindingCategory, Severity
from app.models.scan import ScanConfig, ScanSession, ScanStatus, ScopePolicy
from app.models.tools import RunOpenApiScanRequest, ToolCall, ToolStatus
from app.policy.limits import LimitTracker
from app.policy.permissions import Capability, ConfirmationGate, PermissionSet
from app.policy.scope import ScopeGuard, build_scope_policy
from app.tools.catalog import build_default_registry
from app.tools.context import ToolContext
from app.tools.http_client import HttpExchange, SafeHttpClient
from app.tools.openapi import run_openapi_scan


def _make_context(target: str, permissions: PermissionSet | None = None) -> ToolContext:
    scope = build_scope_policy(target, allow_private=True, authorized_by="tester")
    session = ScanSession(
        scan_id="test-scan",
        scope=scope,
        config=ScanConfig(allow_active_tools=True, require_confirmation=False),
        status=ScanStatus.RUNNING,
        counters={},
    )
    perms = permissions or PermissionSet(
        granted={Capability.HTTP_EGRESS, Capability.ACTIVE_SCAN, Capability.BROWSER, Capability.DNS_LOOKUP, Capability.WRITE_ARTIFACT}
    )
    return ToolContext(
        session=session,
        scope=ScopeGuard(scope),
        limits=LimitTracker(session.config),
        artifact_dir=MagicMock(),
        permissions=perms,
        confirmation=ConfirmationGate(auto_approve=True),
    )


SAMPLE_OPENAPI_SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "Test Banking API", "version": "1.0.0"},
    "security": [{"bearerAuth": []}],
    "paths": {
        "/api/v1/public/ping": {
            "get": {
                "summary": "Health check",
                "security": [],  # Overrides global auth to no auth
                "responses": {"200": {"description": "OK"}},
            }
        },
        "/api/v1/admin/users": {
            "get": {
                "summary": "List all users",
                "security": [],  # SENSITIVE + NO AUTH!
                "responses": {"200": {"description": "OK"}},
            },
            "delete": {
                "summary": "Delete user",
                "security": [],
                "responses": {"200": {"description": "OK"}},
            },
        },
        "/api/v1/account": {
            "get": {
                "summary": "Account details",
                # Inherits bearerAuth
                "responses": {"200": {"description": "OK"}},
            }
        },
    },
}


def test_openapi_tool_is_registered_and_callable() -> None:
    registry = build_default_registry()
    assert "run_openapi_scan" in registry.names
    tool = registry.get("run_openapi_scan")
    assert tool.meta.implemented is True
    assert "active_scan" in tool.meta.capabilities
    assert tool.meta.requires_confirmation is True


def test_openapi_scan_requires_active_scan_capability() -> None:
    ctx = _make_context(
        "http://127.0.0.1:8000",
        permissions=PermissionSet(granted={Capability.HTTP_EGRESS}),  # No ACTIVE_SCAN
    )
    registry = build_default_registry()
    res = registry.dispatch(
        ToolCall(tool="run_openapi_scan", args={"url": "http://127.0.0.1:8000"}),
        ctx,
    )
    assert res.status == ToolStatus.DENIED
    assert "capability not granted: active_scan" in (res.denial_reason or "")


def test_openapi_scan_parses_spec_and_flags_unauth_sensitive() -> None:
    ctx = _make_context("http://127.0.0.1:8000")

    spec_str = json.dumps(SAMPLE_OPENAPI_SPEC)

    def mock_request(url: str, **kwargs):
        if url.endswith("/openapi.json"):
            return HttpExchange(
                requested_url=url,
                final_url=url,
                status_code=200,
                headers={"content-type": "application/json"},
                body_prefix=spec_str,
            )
        if "/admin/users" in url:
            return HttpExchange(
                requested_url=url,
                final_url=url,
                status_code=200,
                headers={"content-type": "application/json"},
                body_prefix='[{"id": 1, "username": "admin"}]',
            )
        return HttpExchange(
            requested_url=url,
            final_url=url,
            status_code=200,
            headers={"content-type": "application/json"},
            body_prefix="{}",
        )

    ctx.http.request = MagicMock(side_effect=mock_request)

    registry = build_default_registry()
    res = registry.dispatch(
        ToolCall(
            tool="run_openapi_scan",
            args={
                "url": "http://127.0.0.1:8000",
                "spec_url": "http://127.0.0.1:8000/openapi.json",
                "probe_endpoints": True,
            },
        ),
        ctx,
    )

    assert res.status == ToolStatus.OK
    assert "OpenAPI scan discovered 4 endpoints" in res.summary
    assert res.data["title"] == "Test Banking API"
    assert res.data["unauthenticated_endpoints_count"] >= 2
    assert res.data["sensitive_endpoints_count"] >= 1

    # Check findings (stored as dicts in ToolResult)
    findings = res.findings
    assert len(findings) >= 2

    # Finding 1: Spec is publicly accessible
    spec_finding = next((f for f in findings if "OpenAPI / Swagger specification is publicly accessible" in f["title"]), None)
    assert spec_finding is not None
    assert spec_finding["category"] == FindingCategory.INFORMATION_DISCLOSURE.value

    # Finding 2: Sensitive endpoint accessible unauthenticated
    admin_finding = next((f for f in findings if "Sensitive API endpoint accessible without authentication" in f["title"]), None)
    assert admin_finding is not None
    assert admin_finding["severity"] == Severity.HIGH.value
    assert admin_finding["category"] == FindingCategory.AUTHENTICATION.value
