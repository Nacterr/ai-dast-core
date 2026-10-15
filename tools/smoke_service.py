"""End-to-end smoke test of the HTTP service.

Starts the demo target and the service in-process, then drives the real API with
``urllib`` from a background thread so the assertions are honest about what a remote
client would see.

Run with::

    python -m tools.smoke_service
"""

from __future__ import annotations

import json
import pathlib
import sys
import threading
import time
import urllib.error
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import uvicorn  # noqa: E402

from app.service.api import build_app_from_args  # noqa: E402
from tools.demo_target import make_server  # noqa: E402

SERVICE_PORT = 8091
API_KEY = "smoke-test-key"


def call(method: str, path: str, body: dict | None = None, *, key: str | None = API_KEY):
    """Perform one HTTP call against the service and return (status, parsed body)."""
    url = f"http://127.0.0.1:{SERVICE_PORT}{path}"
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Content-Type", "application/json")
    if key:
        request.add_header("Authorization", f"Bearer {key}")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = response.read().decode()
            return response.status, _maybe_json(payload)
    except urllib.error.HTTPError as error:
        payload = error.read().decode()
        return error.code, _maybe_json(payload)


def _maybe_json(payload: str):
    """Parse JSON when the body is JSON; otherwise return the raw text.

    The Markdown report endpoint returns ``text/markdown``, so a strict JSON parse would
    fail a perfectly good response.
    """
    if not payload:
        return None
    try:
        return json.loads(payload)
    except json.JSONDecodeError:
        return payload


def main() -> int:
    demo = make_server("127.0.0.1", 0)
    demo_port = demo.server_address[1]
    demo_url = f"http://127.0.0.1:{demo_port}"
    threading.Thread(target=demo.serve_forever, daemon=True).start()

    app = build_app_from_args(
        allowed_hosts=["127.0.0.1"],
        allowed_ports=[demo_port],
        allow_private=True,
        api_key=API_KEY,
        bind_host="127.0.0.1",
        runs_dir=pathlib.Path("runs/_smoke"),
        max_steps=20,
        max_pages=3,
        max_requests=40,
        max_rate=20.0,
    )
    config = uvicorn.Config(app, host="127.0.0.1", port=SERVICE_PORT, log_level="warning")
    server = uvicorn.Server(config)
    threading.Thread(target=server.run, daemon=True).start()

    # Wait for the service to accept connections.
    for _ in range(80):
        try:
            status, _body = call("GET", "/v1/health", key=None)
            if status == 200:
                break
        except Exception:  # noqa: BLE001
            pass
        time.sleep(0.25)
    else:
        print("FAIL: service never became ready")
        return 1

    failures: list[str] = []

    def check(label: str, condition: bool, detail: str = "") -> None:
        mark = "ok  " if condition else "FAIL"
        print(f"  [{mark}] {label}" + (f" — {detail}" if detail and not condition else ""))
        if not condition:
            failures.append(label)

    print("\n=== meta endpoints ===")
    status, health = call("GET", "/v1/health", key=None)
    check("health is public", status == 200, str(health))
    status, _ = call("GET", "/v1/capabilities", key=None)
    check("capabilities is public", status == 200)

    status, _ = call("GET", "/v1/tools", key=None)
    check("tools requires auth", status == 401)
    status, _ = call("GET", "/v1/tools", key="wrong-key")
    check("wrong key is rejected", status == 401)
    status, tools = call("GET", "/v1/tools")
    names = {tool["name"] for tool in tools["tools"]} if isinstance(tools, dict) else set()
    check("tools works with the key", status == 200 and bool(names), str(tools)[:120])
    check(
        "the core tool surface is present",
        {
            "browser_open",
            "extract_links",
            "extract_forms",
            "extract_scripts",
            "read_robots",
            "check_headers",
            "check_cookies",
            "get_scan_status",
            "get_alerts",
            "get_http_history",
        }
        <= names,
        f"missing: {sorted(names)[:5]}",
    )
    check(
        "the roadmap tools are declared but not callable",
        all(
            not tool["implemented"]
            for tool in tools["tools"]
            if tool["name"] in {"run_zap_baseline", "run_openapi_scan", "run_authenticated_crawl"}
        ),
    )

    # The active-check tool IS implemented, but the service must never be able to reach it:
    # it grants no active_scan capability and allow_active_tools is not a request field.
    status, capabilities = call("GET", "/v1/capabilities", key=None)
    check(
        "the service reports that active scanning is not loaded",
        isinstance(capabilities, dict) and capabilities.get("active_scanning_loaded") is False,
        str(capabilities)[:160] if isinstance(capabilities, dict) else "",
    )

    status, accepted = call(
        "POST",
        "/v1/scans",
        {
            "target": demo_url + "/",
            "authorized_by": "smoke-test",
            "checks": ["cors_preflight"],
        },
    )
    check(
        "an active-check field is not part of the scan request",
        status in {403, 422},
        f"scan accepted an unknown field: HTTP {status}",
    )

    print("\n=== authorisation refusals ===")
    status, body = call("POST", "/v1/scans", {"target": "https://not-allowed.test/", "authorized_by": "x"})
    check("out-of-scope host is 403", status == 403, str(body))
    status, _ = call("POST", "/v1/scans", {"target": "https://127.0.0.1/", "authorized_by": ""})
    check("missing authorizer is 422", status == 422)
    status, _ = call("POST", "/v1/scans", {"target": "file:///etc/passwd", "authorized_by": "x"})
    check("file scheme is refused", status == 403)

    print("\n=== full scan ===")
    status, accepted = call(
        "POST",
        "/v1/scans",
        {
            "target": demo_url,
            "authorized_by": "smoke-test",
            "authorization_note": "local demo target",
            "max_pages": 3,
        },
    )
    check("scan accepted with 202", status == 202, str(accepted))
    if status != 202:
        return 1
    job_id = accepted["job_id"]
    print(f"       job: {job_id}")

    deadline = time.time() + 180
    final = None
    while time.time() < deadline:
        status, job = call("GET", f"/v1/scans/{job_id}")
        if status != 200:
            check("status endpoint", False, str(job))
            break
        if job["state"] in {"completed", "failed", "cancelled"}:
            final = job
            break
        time.sleep(1.0)

    check("scan reached a terminal state", final is not None)
    if final is None:
        return 1
    check("scan completed", final["state"] == "completed", final.get("error") or final["stop_reason"])
    check("progress was reported", bool(final["progress"]))

    status, envelope = call("GET", f"/v1/scans/{job_id}/report")
    check("report available", status == 200, str(envelope)[:200])
    if status != 200:
        return 1

    report = envelope["report"]
    findings = report["findings"]
    check("findings were produced", len(findings) >= 10, f"got {len(findings)}")
    check(
        "every finding has evidence",
        all(f["evidence"] for f in findings),
    )
    check(
        "every finding has a host",
        all(f["host"] for f in findings),
    )
    check(
        "evidence points at real trace entries",
        all(
            0 <= e["tool_call_index"] < len(report["tool_trace"])
            for f in findings
            for e in f["evidence"]
        ),
    )
    check("scope is embedded", report["scope"]["allowed_hosts"] == ["127.0.0.1"])
    check("authorisation is recorded", report["authorization"]["authorized_by"] == "smoke-test")
    check("limitations are stated", len(report["limitations"]) >= 5)
    check("attack surface was mapped", report["attack_surface"]["forms_total"] >= 3)

    severities = report["severity_counts"]
    print(
        f"       findings: {len(findings)} "
        f"({severities['critical']}C {severities['high']}H {severities['medium']}M "
        f"{severities['low']}L {severities['info']}I), "
        f"{len(report['tool_trace'])} tool calls"
    )

    print("\n=== report downloads and log ===")
    status, _ = call("GET", f"/v1/scans/{job_id}/events")
    check("events endpoint works", status == 200)
    status, markdown = call("GET", f"/v1/scans/{job_id}/report.md")
    check("markdown report is served", status == 200)

    print("\n=== re-read from disk ===")
    status, _ = call("GET", f"/v1/scans/{job_id}")
    check("job still resolvable", status == 200)
    status, listing = call("GET", "/v1/scans")
    check("job appears in history", status == 200 and any(j["job_id"] == job_id for j in listing["jobs"]))

    server.should_exit = True
    time.sleep(1.0)
    demo.shutdown()
    demo.server_close()

    print()
    if failures:
        print(f"SMOKE TEST FAILED: {len(failures)} check(s): {', '.join(failures)}")
        return 1
    print("SMOKE TEST PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
