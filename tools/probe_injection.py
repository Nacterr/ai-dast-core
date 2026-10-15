"""Probe the injection check against the demo target."""

from __future__ import annotations

import pathlib
import sys
import threading

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import tests.conftest as cf  # noqa: E402
from app.models.scan import ScanConfig  # noqa: E402
from app.models.tools import ToolCall  # noqa: E402
from app.policy.limits import LimitTracker  # noqa: E402
from app.policy.permissions import Capability, ConfirmationGate, PermissionSet  # noqa: E402
from app.policy.scope import ScopeGuard  # noqa: E402
from app.tools.catalog import build_default_registry  # noqa: E402
from app.tools.context import ToolContext  # noqa: E402
from app.tools.injection import PAYLOADS_BY_TECHNIQUE  # noqa: E402
from tools.demo_target import make_server  # noqa: E402


def main() -> int:
    server = make_server("127.0.0.1", 0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    target = f"http://127.0.0.1:{server.server_address[1]}"
    print(f"demo target: {target}")
    for technique, payloads in PAYLOADS_BY_TECHNIQUE.items():
        print(f"  {technique}: {[p.label for p in payloads]}")

    cfg = ScanConfig(max_requests=200, requests_per_second=50.0, allow_active_tools=True)
    session = cf.make_session(target, cfg)
    permissions = PermissionSet()
    permissions.grant(Capability.ACTIVE_SCAN)
    permissions.grant(Capability.INJECTION_PROBE)

    ctx = ToolContext(
        session=session,
        scope=ScopeGuard(session.scope),
        limits=LimitTracker(cfg),
        artifact_dir=pathlib.Path("runs/_probe"),
        permissions=permissions,
        confirmation=ConfirmationGate(auto_approve=True),
        quiet=True,
    )
    registry = build_default_registry()

    cases = (
        ("/products?q=shoe", "vulnerable endpoint"),
        ("/search?q=shoe&page=1", "safe endpoint"),
        ("/products", "no query at all"),
    )
    for suffix, label in cases:
        result = registry.dispatch(
            ToolCall(tool="run_injection_check", args={"url": target + suffix}),
            ctx,
        )
        print(f"\n=== {label}: {suffix} -> {result.status.value} ===")
        print(" ", result.summary[:200])
        if result.denial_reason:
            print("   denied:", result.denial_reason)
            continue
        for finding_result in result.data.get("results", []):
            print(
                f"    {finding_result['parameter']:8s} vulnerable={finding_result['vulnerable']!s:5s} "
                f"{finding_result['verdict']:32s} {finding_result['error_signature'][:60]}"
            )
        for finding in result.findings:
            print(f"  FINDING [{finding['severity']}] {finding['title']}")
            print(f"    {finding['evidence'][0]['observed'][:120]}")

    print("\n=== budget ===")
    print(" ", ctx.limits.snapshot())
    ctx.close()
    server.shutdown()
    server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
