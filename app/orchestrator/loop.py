"""The agent loop.

One iteration is: ask the planner for a decision, run the decision through the tool
dispatcher, fold the result into the harness's own state, and repeat until the planner
finishes, a budget runs out, or the harness stops it.

Three properties matter more than anything else here:

1. **The AI cannot exceed a budget.** Steps, tool calls, pages and requests are all
   reserved *before* the work happens.
2. **The AI cannot act without a tool.** A decision is either "call this registered
   tool with these schema-valid arguments" or "stop". There is no third option.
3. **The harness owns the truth.** Findings, the attack surface, counters and the
   report are built from tool results - never from the planner's prose. The planner's
   text is recorded as commentary and nothing else.
"""

from __future__ import annotations

import datetime as _dt
import threading
import time
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

from app.models.finding import CONFIDENCE_ORDER, SEVERITY_ORDER, Finding, sort_findings
from app.models.scan import (
    ScanConfig,
    ScanSession,
    ScanStatus,
    ScopePolicy,
    SeverityCounts,
    ToolCallRecord,
)
from app.models.tools import ToolCall, ToolStatus
from app.policy.limits import LimitExceeded, LimitTracker
from app.policy.permissions import ConfirmationGate, PermissionSet
from app.policy.scope import ScopeGuard
from app.orchestrator.planner import LlmPlanner, PlannerError, PlannerFn, ScriptedPlanner
from app.tools.context import ToolContext
from app.tools.registry import ToolRegistry

EventSink = Callable[[str], None]

# A configuration finding observed on dozens of paths is still one finding; this caps
# how many individual observations are listed in the report.
_MAX_EVIDENCE_PER_FINDING = 12


class ScanRunner:
    """Executes one scan session end to end."""

    def __init__(
        self,
        registry: ToolRegistry,
        *,
        planner: PlannerFn | None = None,
        artifact_dir: Path,
        permissions: PermissionSet | None = None,
        confirmation: ConfirmationGate | None = None,
        event_sink: EventSink | None = None,
        quiet: bool = False,
        cancel_event: threading.Event | None = None,
    ) -> None:
        self.registry = registry
        self.planner = planner or ScriptedPlanner()
        self.artifact_dir = Path(artifact_dir)
        self.permissions = permissions or PermissionSet()
        self.confirmation = confirmation or ConfirmationGate()
        self._event_sink = event_sink
        self.quiet = quiet
        # A caller-supplied event lets an embedding service stop a scan mid-flight
        # without touching the loop's internals. Checked between steps and passed to the
        # planner, so a long LLM call is the only thing that cannot be interrupted.
        self.cancel_event = cancel_event or threading.Event()
        self.session: ScanSession | None = None
        self._context: ToolContext | None = None
        # The tool call currently executing, so the exchange sink can attribute each HTTP
        # exchange to the trace entry that caused it.
        self._active_call: tuple[int, str] = (-1, "")

    @property
    def cancelled(self) -> bool:
        """Whether a stop has been requested for this scan."""
        return self.cancel_event.is_set()

    def cancel(self, reason: str = "cancelled by the caller") -> None:
        """Ask the running scan to stop at the next safe point."""
        self.cancel_event.set()
        if self.session is not None and not self.session.stop_reason:
            self.session.stop_reason = reason

    # -- logging ----------------------------------------------------------- #

    def _emit(self, message: str) -> None:
        if self._event_sink is not None:
            self._event_sink(message)
        elif not self.quiet:
            print(message, flush=True)

    # -- session construction ---------------------------------------------- #

    def create_session(self, scope: ScopePolicy, config: ScanConfig) -> ScanSession:
        return ScanSession(
            scan_id=f"scan-{_dt.datetime.now(_dt.UTC).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}",
            scope=scope,
            config=config,
            status=ScanStatus.PENDING,
            counters={},
        )

    # -- main entry point -------------------------------------------------- #

    def run(self, session: ScanSession) -> ScanSession:
        """Run the loop to completion and return the final session state."""
        self.session = session
        limits = LimitTracker(session.config)
        guard = ScopeGuard(session.scope)

        context = ToolContext(
            session=session,
            scope=guard,
            limits=limits,
            artifact_dir=self.artifact_dir,
            permissions=self.permissions,
            confirmation=self.confirmation,
            quiet=self.quiet,
            event_sink=self._event_sink,
            exchange_sink=lambda exchange: _record_exchange(session, exchange, self._active_call),
        )
        self._context = context

        session.status = ScanStatus.RUNNING
        session.counters = limits.snapshot()
        self._emit(
            f"scan {session.scan_id} starting against {session.scope.target} "
            f"(planner={getattr(self.planner, 'name', type(self.planner).__name__)})"
        )

        try:
            self._loop(session, context, limits)
        except KeyboardInterrupt:
            session.status = ScanStatus.ABORTED
            session.stop_reason = "interrupted by the operator"
            self._emit("scan interrupted by the operator")
        except Exception as exc:  # noqa: BLE001 - never lose a partial result
            session.status = ScanStatus.FAILED
            session.stop_reason = f"harness error: {type(exc).__name__}: {exc}"
            self._emit(f"scan failed: {type(exc).__name__}: {exc}")
        finally:
            session.findings = _dedupe_findings(session.findings)
            session.counters = limits.snapshot()
            session.finished_at = _now()
            if session.status == ScanStatus.RUNNING:
                session.status = ScanStatus.COMPLETED
            self._emit(
                f"scan {session.scan_id} finished: {len(session.findings)} finding(s), "
                f"{len(session.trace)} tool call(s)"
            )
            context.close()
            self._context = None

        return session

    # -- loop -------------------------------------------------------------- #

    def _loop(self, session: ScanSession, context: ToolContext, limits: LimitTracker) -> None:
        while True:
            # Harness-side stop conditions, checked before asking the planner at all.
            if self.cancel_event.is_set():
                session.stop_reason = session.stop_reason or "cancelled"
                return

            try:
                limits.check_scan_deadline()
            except LimitExceeded as exc:
                session.stop_reason = exc.message
                return

            if limits.budgets["steps"].exhausted:
                session.stop_reason = "planning step budget exhausted"
                return
            if limits.budgets["tool_calls"].exhausted:
                session.stop_reason = "tool call budget exhausted"
                return

            budget = self._planner_budget(limits, session)
            try:
                decision = self.planner(session, budget)
            except PlannerError as exc:
                session.stop_reason = f"planner error: {exc}"
                self._emit(f"planner error, stopping: {exc}")
                return
            except Exception as exc:  # noqa: BLE001 - a planner bug must not lose the scan
                session.stop_reason = f"planner raised {type(exc).__name__}: {exc}"
                self._emit(f"planner raised {type(exc).__name__}, stopping: {exc}")
                return

            if decision.thought:
                self._emit(f"  planner: {_one_line(decision.thought)}")
            for note in decision.notes:
                if note and note not in session.planner_notes:
                    session.planner_notes.append(note)

            if decision.action == "finish":
                session.stop_reason = decision.summary or (
                    decision.thought[:300] or "planner finished"
                )
                if decision.summary:
                    session.planner_notes.append(decision.summary)
                return

            # A tool action must carry a tool name.
            if not decision.tool:
                session.stop_reason = "planner requested a tool action without naming a tool"
                self._emit("planner produced a tool action with no tool name; stopping")
                return

            try:
                limits.reserve("steps")
            except LimitExceeded as exc:
                session.stop_reason = exc.message
                return

            self._execute_decision(session, context, limits, decision)

    def _execute_decision(
        self,
        session: ScanSession,
        context: ToolContext,
        limits: LimitTracker,
        decision: Any,
    ) -> None:
        index = session.next_tool_index()
        call = ToolCall(tool=decision.tool, args=dict(decision.args or {}), reason=decision.thought[:500])

        self._emit(f"  step {index}: {call.tool}({_render_args(call.args)})")
        self._active_call = (index, call.tool)
        try:
            result = self.registry.dispatch(call, context, step=index)
        finally:
            self._active_call = (-1, "")

        # Fold findings into the session, re-stamping evidence with the trace index so
        # every finding can be traced back to the exact call that produced it. Tool
        # results carry findings as plain dicts (they cross the JSON boundary to the
        # planner), so they are re-hydrated into models here.
        for payload in result.findings:
            finding = Finding.model_validate(payload)
            session.findings.append(_stamp_evidence(finding, index, call.tool))

        record = ToolCallRecord(
            index=index,
            step=index,
            tool=call.tool,
            args=call.args,
            reason=call.reason,
            status=result.status.value,
            summary=_one_line(result.summary, 500),
            error=result.error,
            denial_reason=result.denial_reason,
            duration_ms=result.duration_ms,
            findings_count=len(result.findings),
            artifacts=list(result.artifacts),
        )
        session.add_trace(record)
        session.counters = limits.snapshot()

        status_marker = {
            ToolStatus.OK: "ok",
            ToolStatus.DENIED: "denied",
            ToolStatus.ERROR: "error",
            ToolStatus.TIMEOUT: "timeout",
            ToolStatus.NOT_IMPLEMENTED: "not implemented",
            ToolStatus.SKIPPED: "skipped",
        }.get(result.status, result.status.value)
        detail = result.denial_reason or result.error or ""
        self._emit(
            f"    -> {status_marker} ({result.duration_ms} ms)"
            + (f": {_one_line(detail, 160)}" if detail else "")
            + (f" [{len(result.findings)} finding(s)]" if result.findings else "")
        )

        # Update Asset Graph state: mark endpoint tested and distill facts & hints
        page_id_arg = str(call.args.get("page_id") or "")
        page_resolved_url = ""
        if page_id_arg and page_id_arg in session.surface.pages:
            page_resolved_url = str(
                session.surface.pages[page_id_arg].get("final_url")
                or session.surface.pages[page_id_arg].get("url")
                or ""
            )
        target_url = str(call.args.get("url") or page_resolved_url or session.scope.target)
        session.surface.mark_tested(target_url, call.tool)

        if result.findings:
            for f in result.findings:
                if isinstance(f, dict):
                    sev = f.get("severity", "medium")
                    sev_str = sev.value if hasattr(sev, "value") else str(sev)
                    title = str(f.get("title", "Vulnerability"))
                    loc = str(f.get("location") or f.get("url") or target_url)
                    cid = str(f.get("cwe") or f.get("category") or f.get("check_id") or "security")
                else:
                    sev = getattr(f, "severity", None)
                    sev_str = sev.value if hasattr(sev, "value") else str(sev or "medium")
                    title = str(getattr(f, "title", "Vulnerability"))
                    loc = str(getattr(f, "location", None) or getattr(f, "url", None) or target_url)
                    cat = getattr(f, "category", None)
                    cat_str = cat.value if hasattr(cat, "value") else str(cat or "")
                    cid = str(getattr(f, "cwe", None) or cat_str or "security")
                session.surface.add_fact(f"[{sev_str.upper()}] {title} on {loc}")
                session.surface.add_hint(f"Prioritize verification for {title} ({cid})")
        elif result.status == ToolStatus.OK and result.summary:
            if call.tool in ("detect_technologies", "check_headers", "analyze_cors", "analyze_exposed_files"):
                session.surface.add_fact(f"{call.tool}: {_one_line(result.summary, 120)}")

        # Hand the result back to the planner's conversation, if it keeps one.
        result_text = result.to_planner_message(session.config.max_payload_chars)
        session.planner_notes.append(f"{call.tool} -> {result.status.value}: {_one_line(result.summary, 400)}")
        if isinstance(self.planner, LlmPlanner):
            self.planner.record_result("", call.tool, result_text)

        # A denied call is a signal about the planner, not about the target: record it
        # so the report can show exactly what the AI tried and was not allowed to do.
        if result.status == ToolStatus.DENIED:
            session.surface.open_questions.append(
                f"Refused: {call.tool} was denied ({result.denial_reason or 'no reason given'})"
            )

    # -- helpers ----------------------------------------------------------- #

    @staticmethod
    def _budget_snapshot(limits: LimitTracker, session: ScanSession) -> dict[str, Any]:
        budgets = limits.budgets
        return {
            "step": budgets["steps"].used,
            "max_steps": budgets["steps"].limit,
            "steps_remaining": budgets["steps"].remaining,
            "tool_calls_remaining": budgets["tool_calls"].remaining,
            "pages_remaining": budgets["pages"].remaining,
            "requests_remaining": budgets["requests"].remaining,
            "scan_seconds_remaining": max(0, int(session.config.scan_timeout_s - limits.elapsed_s)),
            "findings": len(session.findings),
        }

    def _planner_budget(self, limits: LimitTracker, session: ScanSession) -> dict[str, Any]:
        """What the planner is told about its own situation.

        Includes the granted capabilities, so a playbook planner does not propose a tool the
        dispatcher will immediately refuse. The capability check is still the authority; this
        only stops the trace from filling with predictable refusals.
        """
        snapshot = self._budget_snapshot(limits, session)
        snapshot["capabilities"] = sorted(capability.value for capability in self.permissions.granted)
        return snapshot


# --------------------------------------------------------------------------- #
# HTTP transaction log
# --------------------------------------------------------------------------- #


def _record_exchange(
    session: ScanSession, exchange: Any, active_call: tuple[int, str]
) -> None:
    """Append one HTTP exchange to the session's transaction log.

    Called by the HTTP client after every request, including refused ones. This is what
    makes ``get_http_history`` answerable without sending new traffic, and what lets the
    report show the redirect chains that were actually followed.
    """
    from app.models.scan import HttpExchangeRecord

    final_headers = exchange.headers or {}
    content_type = str(final_headers.get("content-type", ""))[:200]
    total_ms = sum(hop.elapsed_ms for hop in exchange.hops)
    index, tool = active_call

    session.surface.record_exchange(
        HttpExchangeRecord(
            requested_url=exchange.requested_url,
            final_url=exchange.final_url,
            method=exchange.hops[0].method if exchange.hops else "GET",
            status_code=exchange.status_code,
            redirect_chain=[hop.url for hop in exchange.hops],
            content_type=content_type,
            body_bytes=exchange.body_bytes,
            total_ms=total_ms,
            error=exchange.error or "",
            tool=tool,
            tool_call_index=index,
        )
    )


# --------------------------------------------------------------------------- #
# Finding bookkeeping
# --------------------------------------------------------------------------- #


def _stamp_evidence(finding: Finding, trace_index: int, tool: str) -> Finding:
    """Point a finding's evidence at the trace entry that produced it."""
    finding.refresh_host()
    for evidence in finding.evidence:
        evidence.tool_call_index = trace_index
        if not evidence.tool:
            evidence.tool = tool
    if tool not in finding.source_tools:
        finding.source_tools.append(tool)
    return finding


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    """Collapse findings with the same identity, merging their evidence.

    Identity is ``category + host + location``, so a missing header seen on five pages
    of one origin becomes one finding with five evidence rows rather than five findings.
    That is the difference between a report a human can act on and a wall of repetition.
    Merging keeps the highest severity and confidence observed, because the most serious
    observation is the true one.

    Evidence is capped per finding and the full list is summarised in ``ai_notes``, so a
    pathological target cannot inflate the report without bound.
    """
    groups: dict[str, list[Finding]] = {}
    for finding in findings:
        finding.refresh_host()
        groups.setdefault(finding.dedup_key(), []).append(finding)

    merged: list[Finding] = []
    for key, group in groups.items():
        canonical = group[0]
        canonical.id = Finding.compute_id(key)
        canonical.merged_from = len(group)

        for other in group[1:]:
            if SEVERITY_ORDER.get(other.severity, 0) > SEVERITY_ORDER.get(canonical.severity, 0):
                canonical.severity = other.severity
                canonical.impact = other.impact or canonical.impact
            if CONFIDENCE_ORDER.get(other.confidence, 0) > CONFIDENCE_ORDER.get(
                canonical.confidence, 0
            ):
                canonical.confidence = other.confidence
            for tool_name in other.source_tools:
                if tool_name not in canonical.source_tools:
                    canonical.source_tools.append(tool_name)
            for tag in other.tags:
                if tag not in canonical.tags:
                    canonical.tags.append(tag)
            canonical.evidence.extend(other.evidence)

        # Normalise and de-duplicate evidence, then order it deterministically.
        seen: set[tuple[str, str, str, str]] = set()
        unique_evidence = []
        for evidence in canonical.evidence:
            # Query strings are not part of a configuration finding's identity, so they
            # are stripped from the reported location to keep the list readable.
            evidence.url = evidence.url.split("#", 1)[0].split("?", 1)[0]
            signature = (evidence.tool, evidence.url, evidence.location, evidence.observed)
            if signature in seen:
                continue
            seen.add(signature)
            unique_evidence.append(evidence)

        unique_evidence.sort(key=lambda item: (item.url, item.location, item.observed))
        total_observations = len(unique_evidence)
        if total_observations > _MAX_EVIDENCE_PER_FINDING:
            unique_evidence = unique_evidence[:_MAX_EVIDENCE_PER_FINDING]
            canonical.ai_notes = (
                f"Observed {total_observations} times; the first "
                f"{_MAX_EVIDENCE_PER_FINDING} are listed."
            )
        canonical.evidence = unique_evidence

        # Point the finding at the lexicographically first affected URL so the report is
        # reproducible rather than dependent on discovery order.
        urls = sorted({evidence.url for evidence in unique_evidence if evidence.url})
        if urls:
            canonical.url = urls[0]

        merged.append(canonical)

    return sort_findings(merged)


def severity_counts(findings: list[Finding]) -> SeverityCounts:
    return SeverityCounts.from_findings(findings)


# --------------------------------------------------------------------------- #
# Small formatting helpers
# --------------------------------------------------------------------------- #


def _one_line(text: str, limit: int = 220) -> str:
    collapsed = " ".join(str(text).split())
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[: limit - 1] + "\u2026"


def _render_args(args: dict[str, Any]) -> str:
    if not args:
        return ""
    rendered = ", ".join(f"{key}={value!r}" for key, value in list(args.items())[:6])
    return rendered[:200]


def _now() -> str:
    return _dt.datetime.now(_dt.UTC).isoformat(timespec="seconds")


__all__ = [
    "EventSink",
    "ScanRunner",
    "severity_counts",
]
