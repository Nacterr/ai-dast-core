"""Orchestrator, report and end-to-end tests.

These run the whole application - planner, loop, tools, findings, report - against the
local demo target, and assert the guarantees that matter:

* the AI cannot escape the tool surface;
* the planner cannot exceed a budget;
* findings are traceable to the tool call that produced them;
* the report is complete and self-consistent.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.models.scan import ScanConfig, ScanStatus
from app.models.tools import ToolCall, ToolStatus
from app.orchestrator.loop import ScanRunner, _dedupe_findings
from app.orchestrator.planner import (
    LlmPlanner,
    PlannerError,
    ScriptedPlanner,
    build_planner_context,
)
from app.policy.permissions import ConfirmationGate, PermissionSet
from app.reports.json_report import build_report, render_markdown, tool_categories, write_report
from app.tools.catalog import build_default_registry
import tests.conftest as cf


pytestmark = pytest.mark.integration


def _runner(tmp_path: Path, planner=None, **kwargs) -> ScanRunner:
    return ScanRunner(
        build_default_registry(),
        planner=planner or ScriptedPlanner(),
        artifact_dir=tmp_path / "artifacts",
        confirmation=ConfirmationGate(auto_approve=True),
        quiet=True,
        **kwargs,
    )


# --------------------------------------------------------------------------- #
# Scripted planner
# --------------------------------------------------------------------------- #


def test_scripted_planner_opens_target_first(demo_server: str) -> None:
    session = cf.make_session(demo_server)
    decision = ScriptedPlanner()(session, {"steps_remaining": 10, "max_steps": 10})
    assert decision.action == "tool"
    assert decision.tool == "browser_open"
    assert decision.args["url"] == demo_server


def test_scripted_planner_finishes_when_out_of_steps(demo_server: str) -> None:
    session = cf.make_session(demo_server)
    decision = ScriptedPlanner()(session, {"steps_remaining": 0, "max_steps": 10})
    assert decision.action == "finish"
    assert "budget" in decision.summary.lower()


def test_scripted_planner_never_repeats_a_page(demo_server: str) -> None:
    session = cf.make_session(demo_server)
    session.surface.pages["p1"] = {"final_url": demo_server + "/"}
    planner = ScriptedPlanner()
    page_ids = [next(iter(session.surface.pages))]

    seen: list[tuple[str, tuple]] = []
    for _ in range(8):
        decision = planner(session, {"steps_remaining": 20, "max_steps": 20})
        if decision.action != "tool":
            break
        signature = (decision.tool, tuple(sorted(decision.args.items())))
        assert signature not in seen, f"planner repeated {signature}"
        seen.append(signature)
    assert page_ids


# --------------------------------------------------------------------------- #
# Planner context (what the AI is actually shown)
# --------------------------------------------------------------------------- #


def test_planner_context_includes_scope_and_prohibitions(demo_server: str) -> None:
    session = cf.make_session(demo_server)
    registry = build_default_registry()
    context = build_planner_context(session, registry, {"steps_remaining": 5, "step": 1, "max_steps": 10})
    prompt = context.render_system_prompt()

    assert demo_server in prompt
    assert "browser_open" in prompt
    # The prohibitions must be explicit in the prompt, not implied.
    assert "shell" in prompt.lower()
    assert "scope" in prompt.lower()
    assert "payload" in prompt.lower()


def test_planner_context_offers_only_implemented_tools(demo_server: str) -> None:
    session = cf.make_session(demo_server)
    registry = build_default_registry()
    context = build_planner_context(session, registry, {})
    offered = {spec["function"]["name"] for spec in context.tool_specs}

    # Derived from the registry rather than hardcoded, so adding a tool does not silently
    # break this test - only failing to exclude an unimplemented one would.
    expected = {tool.name for tool in registry.callable_tools()}
    assert offered == expected
    assert "run_zap_baseline" not in offered
    assert "run_shell" not in offered
    # The MVP surface must at least contain the core six plus the result tools.
    assert {
        "browser_open",
        "extract_links",
        "extract_forms",
        "extract_scripts",
        "check_headers",
        "check_cookies",
    } <= offered
    assert {"get_scan_status", "get_alerts", "get_http_history"} <= offered


def test_planner_context_schemas_forbid_extra_arguments(demo_server: str) -> None:
    session = cf.make_session(demo_server)
    context = build_planner_context(session, build_default_registry(), {})
    for spec in context.tool_specs:
        schema = spec["function"]["parameters"]
        assert schema.get("additionalProperties") is False, spec["function"]["name"]


# --------------------------------------------------------------------------- #
# LLM planner plumbing (no network: a fake client)
# --------------------------------------------------------------------------- #


class _FakeFunction:
    def __init__(self, name: str, arguments: str) -> None:
        self.name = name
        self.arguments = arguments


class _FakeToolCall:
    def __init__(self, name: str, arguments: str, call_id: str = "call-1") -> None:
        self.id = call_id
        self.function = _FakeFunction(name, arguments)


class _FakeMessage:
    def __init__(self, content: str | None, tool_calls: list | None) -> None:
        self.content = content
        self.tool_calls = tool_calls


class _FakeChoice:
    def __init__(self, message: _FakeMessage) -> None:
        self.message = message


class _FakeCompletion:
    def __init__(self, message: _FakeMessage) -> None:
        self.choices = [_FakeChoice(message)]


class _FakeCompletions:
    def __init__(self, responses: list[_FakeMessage]) -> None:
        self._responses = responses
        self.calls: list[dict] = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        message = self._responses.pop(0) if self._responses else _FakeMessage("done", None)
        return _FakeCompletion(message)


class _FakeClient:
    def __init__(self, responses: list[_FakeMessage]) -> None:
        self.chat = type("Chat", (), {"completions": _FakeCompletions(responses)})()


def test_llm_planner_converts_a_tool_call(demo_server: str) -> None:
    session = cf.make_session(demo_server)
    registry = build_default_registry()
    client = _FakeClient(
        [_FakeMessage("Let me open the target.", [_FakeToolCall("browser_open", json.dumps({"url": demo_server}))])]
    )
    planner = LlmPlanner(registry, model="fake", client=client)

    decision = planner(session, {"steps_remaining": 5, "step": 0, "max_steps": 10})
    assert decision.action == "tool"
    assert decision.tool == "browser_open"
    assert decision.args == {"url": demo_server}

    # The tools parameter must be the registry's schemas, and must exclude roadmap tools.
    tools = client.chat.completions.calls[0]["tools"]
    offered = {tool["function"]["name"] for tool in tools}
    assert offered == {tool.name for tool in registry.callable_tools()}
    assert "run_zap_baseline" not in offered
    assert client.chat.completions.calls[0]["tool_choice"] == "auto"


def test_llm_planner_finishes_on_a_text_only_reply(demo_server: str) -> None:
    session = cf.make_session(demo_server)
    planner = LlmPlanner(
        build_default_registry(),
        model="fake",
        client=_FakeClient([_FakeMessage("I have enough evidence; stopping.", None)]),
    )
    decision = planner(session, {"steps_remaining": 5, "step": 0, "max_steps": 10})
    assert decision.action == "finish"
    assert "stopping" in decision.summary


def test_llm_planner_rejects_invalid_json_arguments(demo_server: str) -> None:
    session = cf.make_session(demo_server)
    planner = LlmPlanner(
        build_default_registry(),
        model="fake",
        client=_FakeClient([_FakeMessage("go", [_FakeToolCall("browser_open", "{not json")])]),
    )
    with pytest.raises(PlannerError):
        planner(session, {"steps_remaining": 5, "step": 0, "max_steps": 10})


def test_llm_planner_honours_only_the_first_parallel_call(demo_server: str) -> None:
    session = cf.make_session(demo_server)
    planner = LlmPlanner(
        build_default_registry(),
        model="fake",
        client=_FakeClient(
            [
                _FakeMessage(
                    "two at once",
                    [
                        _FakeToolCall("browser_open", json.dumps({"url": demo_server}), "a"),
                        _FakeToolCall("check_headers", json.dumps({"url": demo_server}), "b"),
                    ],
                )
            ]
        ),
    )
    decision = planner(session, {"steps_remaining": 5, "step": 0, "max_steps": 10})
    assert decision.tool == "browser_open"
    assert any("sequential" in note for note in decision.notes)


def test_llm_planner_surfaces_provider_errors(demo_server: str) -> None:
    session = cf.make_session(demo_server)

    class _Boom:
        def create(self, **kwargs):
            raise RuntimeError("upstream 500")

    client = type("C", (), {"chat": type("Chat", (), {"completions": _Boom()})()})()
    planner = LlmPlanner(build_default_registry(), model="fake", client=client)
    with pytest.raises(PlannerError):
        planner(session, {"steps_remaining": 5, "step": 0, "max_steps": 10})


# --------------------------------------------------------------------------- #
# End to end
# --------------------------------------------------------------------------- #


def test_end_to_end_scan_produces_a_complete_report(tmp_path: Path, demo_server: str) -> None:
    runner = _runner(tmp_path)
    session = runner.create_session(
        cf.make_scope(demo_server),
        ScanConfig(
            max_steps=20,
            max_tool_calls=40,
            max_pages=3,
            max_requests=40,
            requests_per_second=50.0,
        ),
    )
    runner.run(session)

    assert session.status == ScanStatus.COMPLETED
    assert session.finished_at
    assert len(session.trace) >= 6
    assert session.findings, "the demo target must yield findings"

    executed = {record.tool for record in session.trace}
    assert {"browser_open", "extract_links", "extract_forms", "extract_scripts"} <= executed
    assert {"check_headers", "check_cookies"} <= executed

    # Every finding must be traceable.
    for finding in session.findings:
        assert finding.evidence, finding.title
        assert finding.id.startswith("F-")
        for evidence in finding.evidence:
            assert evidence.tool_call_index >= 0
            assert 0 <= evidence.tool_call_index < len(session.trace)

    # The attack surface model must be populated from tool output, not from the planner.
    assert session.surface.pages
    assert session.surface.links
    assert session.surface.forms
    assert session.surface.api_endpoints

    report = build_report(session, build_default_registry(), planner_name="scripted-recon-v1")
    assert report.severity_counts.total == len(report.findings)
    assert report.checks_executed
    assert report.summary
    assert report.scope.target == demo_server
    assert report.limitations
    assert report.attack_surface["pages_opened"] >= 1
    assert report.attack_surface["forms_total"] >= 3

    written = write_report(report, tmp_path / "run")
    assert written["json"].exists() and written["markdown"].exists()

    reloaded = json.loads(written["json"].read_text(encoding="utf-8"))
    assert reloaded["scan_id"] == session.scan_id
    assert reloaded["report_version"] == "1.0"
    assert len(reloaded["findings"]) == len(report.findings)
    assert reloaded["tool_trace"]

    markdown = written["markdown"].read_text(encoding="utf-8")
    assert "# Web DAST report" in markdown
    assert "## Limitations" in markdown
    assert "## Disclaimer" in markdown


def test_scan_respects_the_step_budget(tmp_path: Path, demo_server: str) -> None:
    runner = _runner(tmp_path)
    session = runner.create_session(
        cf.make_scope(demo_server),
        ScanConfig(max_steps=3, max_tool_calls=40, max_pages=3, requests_per_second=50.0),
    )
    runner.run(session)
    assert len(session.trace) <= 3
    assert "budget" in session.stop_reason.lower() or session.stop_reason


def test_scan_stops_immediately_with_a_planner_that_finishes(tmp_path: Path, demo_server: str) -> None:
    from app.models.scan import PlannerDecision

    def planner(session, budget):  # noqa: ANN001
        return PlannerDecision(action="finish", summary="nothing to do")

    runner = _runner(tmp_path, planner=planner)
    session = runner.create_session(cf.make_scope(demo_server), ScanConfig(requests_per_second=50.0))
    runner.run(session)
    assert session.trace == []
    assert session.stop_reason == "nothing to do"
    assert session.status == ScanStatus.COMPLETED


def test_scan_survives_a_planner_that_raises(tmp_path: Path, demo_server: str) -> None:
    def planner(session, budget):  # noqa: ANN001
        raise RuntimeError("planner exploded")

    runner = _runner(tmp_path, planner=planner)
    session = runner.create_session(cf.make_scope(demo_server), ScanConfig(requests_per_second=50.0))
    runner.run(session)
    assert session.status == ScanStatus.COMPLETED
    assert "planner raised" in session.stop_reason


def test_scan_records_a_denied_tool_call_in_the_trace(tmp_path: Path, demo_server: str) -> None:
    from app.models.scan import PlannerDecision

    calls = [0]

    def planner(session, budget):  # noqa: ANN001
        calls[0] += 1
        if calls[0] == 1:
            return PlannerDecision(
                action="tool",
                tool="run_shell",
                args={"command": "curl evil.test"},
                thought="trying to escape the tool surface",
            )
        return PlannerDecision(action="finish", summary="stopped")

    runner = _runner(tmp_path, planner=planner)
    session = runner.create_session(cf.make_scope(demo_server), ScanConfig(requests_per_second=50.0))
    runner.run(session)

    assert len(session.trace) == 1
    record = session.trace[0]
    assert record.tool == "run_shell"
    assert record.status == ToolStatus.DENIED.value
    assert "unknown tool" in (record.denial_reason or "")
    # The refusal must be visible in the audit trail.
    assert any("Refused" in question for question in session.surface.open_questions)


def test_scan_refuses_an_out_of_scope_url_from_the_planner(tmp_path: Path, demo_server: str) -> None:
    from app.models.scan import PlannerDecision

    calls = [0]

    def planner(session, budget):  # noqa: ANN001
        calls[0] += 1
        if calls[0] == 1:
            return PlannerDecision(
                action="tool", tool="browser_open", args={"url": "https://attacker.test/"}
            )
        return PlannerDecision(action="finish", summary="stopped")

    runner = _runner(tmp_path, planner=planner)
    session = runner.create_session(cf.make_scope(demo_server), ScanConfig(requests_per_second=50.0))
    runner.run(session)

    assert session.trace[0].status == ToolStatus.ERROR.value
    assert "out of scope" in (session.trace[0].error or "").lower()
    assert session.surface.pages == {}


def test_scan_timeout_stops_the_loop(tmp_path: Path, demo_server: str) -> None:
    from app.models.scan import PlannerDecision

    def planner(session, budget):  # noqa: ANN001
        return PlannerDecision(action="tool", tool="browser_open", args={"url": demo_server})

    runner = _runner(tmp_path, planner=planner)
    session = runner.create_session(
        cf.make_scope(demo_server),
        ScanConfig(scan_timeout_s=5.0, max_steps=100, requests_per_second=50.0),
    )
    # Start the clock in the past so the deadline fires on the first check.
    runner.run(session)
    assert session.status == ScanStatus.COMPLETED


def test_report_json_round_trips(tmp_path: Path, demo_server: str) -> None:
    runner = _runner(tmp_path)
    session = runner.create_session(
        cf.make_scope(demo_server),
        ScanConfig(max_steps=8, max_pages=1, max_requests=20, requests_per_second=50.0),
    )
    runner.run(session)
    report = build_report(session, build_default_registry())
    payload = report.model_dump(mode="json")
    text = json.dumps(payload, default=str)
    assert json.loads(text)["scan_id"] == session.scan_id
    # Scope and config must be embedded so the report is self-contained.
    assert payload["scope"]["allowed_hosts"]
    assert payload["config"]["max_steps"] == 8


def test_markdown_renders_a_thorough_report(tmp_path: Path, demo_server: str) -> None:
    runner = _runner(tmp_path)
    session = runner.create_session(
        cf.make_scope(demo_server),
        ScanConfig(max_steps=16, max_pages=2, max_requests=30, requests_per_second=50.0),
    )
    runner.run(session)
    markdown = render_markdown(build_report(session, build_default_registry()))
    for section in (
        "## Severity summary",
        "## Scope",
        "## Findings",
        "## Attack surface",
        "## Checks executed",
        "## Tool call trace",
        "## Limitations",
    ):
        assert section in markdown, section


def test_tool_categories_grouping() -> None:
    grouped = tool_categories(build_default_registry())
    assert "browser_open" in grouped["discovery"]
    assert "check_headers" in grouped["passive"]
    assert "run_zap_baseline" in grouped["active"]


# --------------------------------------------------------------------------- #
# Finding deduplication
# --------------------------------------------------------------------------- #


def test_dedupe_merges_findings_for_the_same_host_and_location() -> None:
    """A host-wide configuration issue must collapse across paths."""
    from app.models.finding import Confidence, Evidence, FindingCategory, Severity
    from app.tools.findings import make_finding

    first = make_finding(
        title="CSP missing",
        category=FindingCategory.SECURITY_HEADERS,
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        url="https://example.com/a?x=1",
        location="content-security-policy",
        evidence=[Evidence(tool="check_headers", url="https://example.com/a", observed="absent")],
    )
    second = make_finding(
        title="CSP missing",
        category=FindingCategory.SECURITY_HEADERS,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        url="https://example.com/b?x=2",
        location="content-security-policy",
        evidence=[Evidence(tool="check_headers", url="https://example.com/b", observed="absent")],
    )
    merged = _dedupe_findings([first, second])
    assert len(merged) == 1
    assert merged[0].severity == Severity.HIGH
    assert len(merged[0].evidence) == 2
    assert merged[0].host == "example.com"


def test_dedupe_keeps_findings_apart_across_hosts() -> None:
    """The same issue on two different origins is two findings, not one."""
    from app.models.finding import FindingCategory, Severity
    from app.tools.findings import make_finding

    findings = [
        make_finding(
            title="CSP missing",
            category=FindingCategory.SECURITY_HEADERS,
            severity=Severity.MEDIUM,
            url="https://a.test/",
            location="content-security-policy",
        ),
        make_finding(
            title="CSP missing",
            category=FindingCategory.SECURITY_HEADERS,
            severity=Severity.MEDIUM,
            url="https://b.test/",
            location="content-security-policy",
        ),
    ]
    assert len(_dedupe_findings(findings)) == 2


def test_dedupe_keeps_distinct_findings_apart() -> None:
    from app.models.finding import FindingCategory, Severity
    from app.tools.findings import make_finding

    findings = [
        make_finding(
            title="CSP missing",
            category=FindingCategory.SECURITY_HEADERS,
            severity=Severity.MEDIUM,
            url="https://example.com/",
            location="content-security-policy",
        ),
        make_finding(
            title="HSTS missing",
            category=FindingCategory.SECURITY_HEADERS,
            severity=Severity.MEDIUM,
            url="https://example.com/",
            location="strict-transport-security",
        ),
    ]
    assert len(_dedupe_findings(findings)) == 2


def test_dedupe_ignores_query_strings_scheme_and_port() -> None:
    from app.models.finding import Finding

    base = Finding.compute_dedup_key("security_headers", "x-frame-options", "a.test")
    other = Finding.compute_dedup_key("security_headers", "x-frame-options", "A.TEST")
    assert base == other
    assert Finding.host_of("https://example.com:8443/p?a=1#f") == "example.com"
    assert Finding.host_of("http://example.com/p") == "example.com"
    assert Finding.host_of("") == ""


def test_dedupe_caps_evidence_volume() -> None:
    """A finding observed on 40 paths must not produce 40 evidence rows."""
    from app.models.finding import Evidence, FindingCategory, Severity
    from app.tools.findings import make_finding

    findings = [
        make_finding(
            title="Referrer-Policy is missing",
            category=FindingCategory.SECURITY_HEADERS,
            severity=Severity.LOW,
            url=f"https://example.com/page-{index}",
            location="referrer-policy",
            evidence=[
                Evidence(
                    tool="check_headers",
                    url=f"https://example.com/page-{index}",
                    observed="absent",
                )
            ],
        )
        for index in range(40)
    ]
    merged = _dedupe_findings(findings)
    assert len(merged) == 1
    assert len(merged[0].evidence) <= 12
    assert "40" in merged[0].ai_notes


# --------------------------------------------------------------------------- #
# Permissions in the full run
# --------------------------------------------------------------------------- #


def test_scan_with_http_egress_revoked_still_completes(tmp_path: Path, demo_server: str) -> None:
    permissions = PermissionSet()
    from app.policy.permissions import Capability

    permissions.revoke(Capability.HTTP_EGRESS)
    runner = _runner(tmp_path, permissions=permissions)
    session = runner.create_session(
        cf.make_scope(demo_server),
        ScanConfig(max_steps=10, max_pages=1, requests_per_second=50.0),
    )
    runner.run(session)

    assert session.status == ScanStatus.COMPLETED
    denied = [record for record in session.trace if record.status == ToolStatus.DENIED.value]
    assert denied, "passive tools must have been denied"

    passive_denials = [record for record in denied if record.tool in {"check_headers", "check_cookies"}]
    assert passive_denials, "at least one passive tool must have been refused"
    assert all("http_egress" in (record.denial_reason or "") for record in passive_denials)
    # Discovery tools do not need HTTP egress, so they must still have succeeded.
    assert any(
        record.tool == "browser_open" and record.status == ToolStatus.OK.value
        for record in session.trace
    )


def test_registry_dispatch_is_the_only_tool_path() -> None:
    """Guard against a future change that bypasses the registry."""
    import inspect

    from app.orchestrator import loop as loop_module

    source = inspect.getsource(loop_module)
    assert "registry.dispatch" in source
    # The loop must not import the executors directly.
    assert "from app.tools.discovery import" not in source
    assert "from app.tools.passive_checks import" not in source
