"""Result tools: read-only views over what the scan already knows.

These three tools answer the questions a planner actually asks in the middle of a scan:

* *Where am I?* — :func:`get_scan_status`
* *What have I found so far?* — :func:`get_alerts`
* *What did we actually request, and what came back?* — :func:`get_http_history`

All three are free: they read harness state, send no traffic, and consume no request
budget. That matters for prompt design — the planner can check its own progress as often
as it likes without spending the budget it is trying to conserve.

They are also the difference between an AI planner that sees only the last tool result and
one that can reason over the whole engagement.
"""

from __future__ import annotations

from app.models.finding import SEVERITY_ORDER, Severity, sort_findings
from app.models.tools import (
    AlertSummary,
    GetAlertsData,
    GetAlertsRequest,
    GetHttpHistoryData,
    GetHttpHistoryRequest,
    GetScanStatusRequest,
    HttpHistoryEntry,
    ScanStatusData,
)
from app.tools.base import ToolOutcome, ok

_SEVERITY_LEVELS: tuple[Severity, ...] = (
    Severity.INFO,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
)


# --------------------------------------------------------------------------- #
# get_scan_status
# --------------------------------------------------------------------------- #


def get_scan_status(ctx, request: GetScanStatusRequest) -> ToolOutcome:
    """Report progress, remaining budget and concrete next steps."""
    session = ctx.session
    surface = session.surface

    counts: dict[str, int] = {level.value: 0 for level in _SEVERITY_LEVELS}
    for finding in session.findings:
        counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1

    # Prefer the orchestrator's trace when it exists; fall back to the context's own
    # observation log so the tool is accurate when driven directly (tests, embedding).
    tools_used = sorted(
        {record.tool for record in session.trace if record.status == "ok"}
    )
    if not tools_used:
        tools_used = ctx.tools_run()

    limits = ctx.limits
    remaining = {
        name: budget.remaining for name, budget in limits.budgets.items()
    }
    remaining["scan_seconds"] = max(
        0, int(session.config.scan_timeout_s - limits.elapsed_s)
    )

    data = ScanStatusData(
        scan_id=session.scan_id,
        target=session.scope.target,
        status=session.status.value,
        elapsed_s=round(limits.elapsed_s, 1),
        pages_opened=len(surface.pages),
        urls_known=len(surface.links),
        urls_in_scope=sum(1 for link in surface.links.values() if link.in_scope),
        forms_found=len(surface.forms),
        scripts_found=len(surface.scripts),
        api_endpoints_found=len(surface.api_endpoints),
        http_exchanges=len(surface.http_history),
        findings_total=len(session.findings),
        findings_by_severity=counts,
        tools_used=tools_used,
        remaining=remaining,
        suggestions=_suggest_next_steps(ctx, tools_used),
    )

    summary = (
        f"Scan {session.scan_id} is {session.status.value} after "
        f"{len(session.trace)} tool call(s) in {limits.elapsed_s:.0f}s. "
        f"Opened {len(surface.pages)} page(s), know {len(surface.links)} URL(s), "
        f"{len(surface.forms)} form(s), {len(surface.api_endpoints)} API endpoint(s); "
        f"recorded {len(surface.http_history)} HTTP exchange(s). "
        f"{len(session.findings)} finding(s): {counts['critical']} critical, "
        f"{counts['high']} high, {counts['medium']} medium, {counts['low']} low, "
        f"{counts['info']} info. Budget left - {_render_remaining(remaining)}."
    )
    return ok(summary, data)


def _render_remaining(remaining: dict[str, int]) -> str:
    parts = [
        f"{name}: {value}"
        for name, value in remaining.items()
        if name in {"steps", "tool_calls", "pages", "requests"}
    ]
    return ", ".join(parts) or "n/a"


def _suggest_next_steps(ctx, tools_used: list[str]) -> list[str]:
    """Derive next-step hints from harness state, not from the model's imagination.

    These are *observations about what has not been covered yet*, phrased as options. The
    planner is free to ignore them; they exist so it does not have to rediscover the gap.
    """
    session = ctx.session
    surface = session.surface
    suggestions: list[str] = []

    unchecked = [
        link.url
        for link in surface.links.values()
        if link.in_scope and link.url not in _checked_urls(surface)
    ]
    if "check_headers" not in tools_used:
        suggestions.append(
            "check_headers has not run: response security headers are unassessed."
        )
    if "check_cookies" not in tools_used:
        suggestions.append(
            "check_cookies has not run: cookie attribute posture is unassessed."
        )
    if "read_robots" not in tools_used:
        suggestions.append(
            "read_robots has not run: robots.txt and sitemap may disclose unlinked paths."
        )
    if unchecked:
        suggestions.append(
            f"{len(unchecked)} in-scope URL(s) have not had their headers checked, "
            f"starting with {unchecked[0]}"
        )
    if surface.forms:
        without_token = [
            form
            for form in surface.forms
            if form.method != "get" and not form.has_csrf_token
        ]
        if without_token:
            suggestions.append(
                f"{len(without_token)} state-changing form(s) showed no CSRF token "
                f"(e.g. {without_token[0].action}); this harness cannot test them further."
            )
    if surface.api_endpoints:
        untested = [
            url for url in surface.api_endpoints if url not in _checked_urls(surface)
        ]
        if untested:
            suggestions.append(
                f"{len(untested)} API endpoint(s) discovered but not checked, "
                f"starting with {untested[0]}"
            )
    if not suggestions:
        suggestions.append(
            "Coverage looks complete for the tools this harness offers. Consider finishing."
        )
    return suggestions[:6]


def _checked_urls(surface) -> set[str]:
    """URLs the harness has already issued a request against."""
    return {entry.final_url or entry.requested_url for entry in surface.http_history}


# --------------------------------------------------------------------------- #
# get_alerts
# --------------------------------------------------------------------------- #


def get_alerts(ctx, request: GetAlertsRequest) -> ToolOutcome:
    """Return the findings produced so far, filtered and compacted."""
    all_findings = sort_findings(list(ctx.session.findings))

    minimum: Severity | None = None
    if request.severity:
        minimum = Severity(request.severity)
    threshold = SEVERITY_ORDER[minimum] if minimum else -1

    selected = []
    for finding in all_findings:
        if threshold >= 0 and SEVERITY_ORDER.get(finding.severity, 0) < threshold:
            continue
        if request.category and finding.category.value != request.category:
            continue
        if request.host and request.host.lower() not in (finding.host or "").lower():
            continue
        selected.append(finding)

    counts: dict[str, int] = {level.value: 0 for level in _SEVERITY_LEVELS}
    for finding in all_findings:
        counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1

    alerts = [
        AlertSummary(
            id=finding.id,
            title=finding.title,
            severity=finding.severity.value,
            confidence=finding.confidence.value,
            category=finding.category.value,
            host=finding.host,
            location=finding.location,
            url=finding.url,
            recommendation=finding.recommendation[:400],
            evidence_count=len(finding.evidence),
        )
        for finding in selected[: request.limit]
    ]

    data = GetAlertsData(
        total_findings=len(all_findings),
        matched=len(selected),
        returned=len(alerts),
        counts_by_severity=counts,
        alerts=alerts,
    )

    if not all_findings:
        summary = (
            "No findings have been produced yet. That means the checks run so far have not "
            "flagged anything, not that the target is clean."
        )
    else:
        filters = []
        if request.severity:
            filters.append(f"severity >= {request.severity}")
        if request.category:
            filters.append(f"category = {request.category}")
        if request.host:
            filters.append(f"host contains {request.host}")
        filter_text = f" (filtered by {', '.join(filters)})" if filters else ""
        summary = (
            f"{len(all_findings)} finding(s) so far{filter_text}; returning "
            f"{len(alerts)} of {len(selected)} matching. Breakdown: "
            f"{counts['critical']} critical, {counts['high']} high, {counts['medium']} medium, "
            f"{counts['low']} low, {counts['info']} info."
        )
    return ok(summary, data)


# --------------------------------------------------------------------------- #
# get_http_history
# --------------------------------------------------------------------------- #


def get_http_history(ctx, request: GetHttpHistoryRequest) -> ToolOutcome:
    """Return the recorded HTTP transaction log. Never re-requests anything."""
    surface = ctx.session.surface
    history = list(surface.http_history)

    entries = []
    for record in history:
        if request.redirects_only and len(record.redirect_chain) < 2:
            continue
        if request.host and request.host.lower() not in record.requested_url.lower():
            continue
        entries.append(record)

    total_redirects = sum(1 for record in history if len(record.redirect_chain) >= 2)
    blocked = sum(
        1
        for record in history
        if "refused" in record.error.lower() or "blocked" in record.error.lower()
    )

    selected = entries[-request.limit :]
    data = GetHttpHistoryData(
        total_exchanges=len(history),
        returned=len(selected),
        redirects_followed=total_redirects,
        blocked_redirects=blocked,
        entries=[
            HttpHistoryEntry(
                requested_url=record.requested_url,
                final_url=record.final_url,
                method=record.method,
                status_code=record.status_code,
                redirect_count=max(0, len(record.redirect_chain) - 1),
                redirect_chain=record.redirect_chain,
                content_type=record.content_type,
                body_bytes=record.body_bytes,
                total_ms=record.total_ms,
                error=record.error,
                tool=record.tool,
                tool_call_index=record.tool_call_index,
            )
            for record in selected
        ],
    )

    if not history:
        summary = (
            "No HTTP exchanges have been recorded yet. Use check_headers, check_cookies or "
            "read_robots to generate traffic, or browser_open to open a page."
        )
    else:
        statuses: dict[str, int] = {}
        for record in history:
            key = str(record.status_code) if record.status_code is not None else "no-response"
            statuses[key] = statuses.get(key, 0) + 1
        rendered = ", ".join(
            f"{code}×{count}" for code, count in sorted(statuses.items(), key=lambda item: -item[1])
        )
        summary = (
            f"{len(history)} HTTP exchange(s) recorded: {rendered}. "
            f"{total_redirects} followed a redirect and {blocked} had a redirect refused by "
            f"the scope guard. Returning {len(selected)}."
        )
    return ok(summary, data)
