"""JSON and Markdown report generation.

The report is assembled entirely from harness state - the session, its trace and its
findings - so it is reproducible from the recorded run. The planner contributes only
its executive summary text, which is labelled as commentary.

Two artefacts are produced for every run:

* ``report.json`` - the machine-readable deliverable, versioned and self-contained.
* ``report.md`` - the same content rendered for a human reader.
"""

from __future__ import annotations

import datetime as _dt
import json
from pathlib import Path
from typing import Any

from app.models.finding import Finding, Severity, sort_findings
from app.models.scan import (
    ScanReport,
    ScanSession,
    ScanStatus,
    SeverityCounts,
    ToolCallRecord,
)
from app.models.tools import ToolCategory, ToolStatus
from app.tools.registry import ToolRegistry

REPORT_VERSION = "1.0"

_LIMITATIONS: tuple[str, ...] = (
    "Read-only only: this run did not fuzz parameters, submit forms, authenticate, or upload "
    "files. If enabled, the harness may send fixed injection probes; callers cannot supply "
    "those payloads.",
    "Unauthenticated: no credentials were used, so anything behind a login was not "
    "assessed. Findings inside the authenticated area may exist and are not reported.",
    "Single-origin depth: link discovery is bounded by the page and depth budgets, so "
    "the inventory is a sample of the target's surface, not an exhaustive map.",
    "Header and cookie checks describe what the server returned to this client at this "
    "moment. Behaviour can differ by route, by device, by geography and over time.",
    "Absence of a finding is not evidence of absence. A clean report means the checks in "
    "``checks_executed`` passed, nothing more.",
    "Automated output requires human review before it is treated as a confirmed "
    "vulnerability or used for compliance reporting.",
)

_METHODOLOGY = (
    "The scanner is a scope-restricted agent. An AI planner chooses the next tool to "
    "run; the harness validates the choice against a fixed tool catalogue, a resolved "
    "scope allowlist, capability permissions, per-scan budgets and a confirmation gate, "
    "and only then performs the work. Findings are derived from observed tool output, "
    "not from the planner's text, and every finding carries the tool call index that "
    "produced its evidence."
)


def build_report(
    session: ScanSession,
    registry: ToolRegistry | None = None,
    *,
    planner_name: str = "",
    planner_meta: dict[str, Any] | None = None,
    duration_s: float | None = None,
) -> ScanReport:
    """Assemble the final report from a finished (or partial) session."""
    findings = sort_findings(list(session.findings))
    counts = SeverityCounts.from_findings(findings)

    executed = sorted({record.tool for record in session.trace if record.status == ToolStatus.OK.value})
    skipped = [
        {
            "tool": record.tool,
            "status": record.status,
            "reason": record.denial_reason or record.error or "not specified",
        }
        for record in session.trace
        if record.status in {ToolStatus.DENIED.value, ToolStatus.ERROR.value, ToolStatus.TIMEOUT.value, ToolStatus.NOT_IMPLEMENTED.value}
    ]

    merged_observations = _merged_observation_index(findings)

    return ScanReport(
        report_version=REPORT_VERSION,
        scan_id=session.scan_id,
        target=session.scope.target,
        status=session.status,
        started_at=session.started_at,
        finished_at=session.finished_at,
        duration_s=round(duration_s if duration_s is not None else _duration(session), 2),
        authorization={
            "authorized_by": session.scope.authorized_by,
            "note": session.scope.authorization_note,
            "scope_confirmed_at": session.scope.created_at,
            "methodology": _METHODOLOGY,
        },
        scope=session.scope,
        config=session.config,
        planner={
            "name": planner_name or "unknown",
            "stop_reason": session.stop_reason,
            "notes": list(session.planner_notes[-20:]),
            **(planner_meta or {}),
        },
        summary=_executive_summary(session, counts, executed),
        severity_counts=counts,
        findings=findings,
        merged_observations=merged_observations,
        attack_surface=_attack_surface(session),
        checks_executed=executed,
        checks_skipped=skipped,
        tool_trace=[_trace_entry(record) for record in session.trace],
        counters=dict(session.counters),
        stop_reason=session.stop_reason,
        limitations=list(_LIMITATIONS),
    )


def write_report(
    report: ScanReport,
    run_dir: Path,
    *,
    include_markdown: bool = True,
) -> dict[str, Path]:
    """Write ``report.json`` (and optionally ``report.md``) into ``run_dir``."""
    run_dir = Path(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    written: dict[str, Path] = {}

    json_path = run_dir / "report.json"
    json_path.write_text(
        json.dumps(report.model_dump(mode="json"), indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )
    written["json"] = json_path

    if include_markdown:
        markdown_path = run_dir / "report.md"
        markdown_path.write_text(render_markdown(report), encoding="utf-8")
        written["markdown"] = markdown_path

    return written


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #

_SEVERITY_BADGE = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MEDIUM",
    Severity.LOW: "LOW",
    Severity.INFO: "INFO",
}


def render_markdown(report: ScanReport) -> str:
    """Render the report for a human reader."""
    lines: list[str] = []
    counts = report.severity_counts

    lines.append(f"# Web DAST report: {report.target}")
    lines.append("")
    lines.append(f"- Scan id: `{report.scan_id}`")
    lines.append(f"- Status: **{report.status.value}**")
    lines.append(f"- Started: {report.started_at}")
    lines.append(f"- Finished: {report.finished_at or '(not finished)'}")
    lines.append(f"- Duration: {report.duration_s:.1f}s")
    lines.append(f"- Planner: `{report.planner.get('name', 'unknown')}`")
    lines.append(f"- Tool calls: {len(report.tool_trace)}")
    lines.append("")

    lines.append("## Severity summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("| --- | --- |")
    for label, value in (
        ("Critical", counts.critical),
        ("High", counts.high),
        ("Medium", counts.medium),
        ("Low", counts.low),
        ("Info", counts.info),
    ):
        lines.append(f"| {label} | {value} |")
    lines.append(f"| **Total** | **{counts.total}** |")
    lines.append("")

    lines.append("## Executive summary")
    lines.append("")
    lines.append(report.summary or "(no summary produced)")
    lines.append("")

    if report.authorization.get("authorized_by") or report.authorization.get("note"):
        lines.append("## Authorisation")
        lines.append("")
        lines.append(f"- Authorised by: {report.authorization.get('authorized_by') or '(not recorded)'}")
        if report.authorization.get("note"):
            lines.append(f"- Note: {report.authorization['note']}")
        lines.append("")

    lines.append("## Scope")
    lines.append("")
    lines.append("```")
    lines.append(report.scope.as_prompt_block())
    lines.append("```")
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    if not report.findings:
        lines.append(
            "No findings were produced by the checks that ran. See "
            "'Checks executed' below and the limitations section: this is not a clean bill "
            "of health."
        )
        lines.append("")
    for finding in report.findings:
        badge = _SEVERITY_BADGE.get(finding.severity, finding.severity.value.upper())
        lines.append(f"### [{badge}] {finding.title}")
        lines.append("")
        lines.append(f"- Id: `{finding.id}`")
        lines.append(f"- Category: `{finding.category.value}`")
        lines.append(f"- Confidence: `{finding.confidence.value}`")
        if finding.url:
            lines.append(f"- URL: `{finding.url}`")
        if finding.location:
            lines.append(f"- Location: `{finding.location}`")
        if finding.owasp:
            lines.append(f"- OWASP: {finding.owasp}")
        if finding.cwe:
            lines.append(f"- CWE: {finding.cwe}")
        lines.append("")
        if finding.description:
            lines.append(finding.description)
            lines.append("")
        if finding.impact:
            lines.append(f"**Impact.** {finding.impact}")
            lines.append("")
        if finding.recommendation:
            lines.append(f"**Recommendation.** {finding.recommendation}")
            lines.append("")
        if finding.evidence:
            lines.append("**Evidence**")
            lines.append("")
            lines.append("| Tool | Call | Location | Observed | Expected |")
            lines.append("| --- | --- | --- | --- | --- |")
            for evidence in finding.evidence:
                lines.append(
                    "| {tool} | #{index} | {location} | {observed} | {expected} |".format(
                        tool=_md_cell(evidence.tool),
                        index=evidence.tool_call_index,
                        location=_md_cell(evidence.location) or "-",
                        observed=_md_cell(evidence.observed) or "-",
                        expected=_md_cell(evidence.expected) or "-",
                    )
                )
            lines.append("")
        if finding.references:
            lines.append("References: " + ", ".join(finding.references))
            lines.append("")

    if report.merged_observations:
        lines.append("## Observations merged during deduplication")
        lines.append("")
        lines.append(
            "A configuration issue is identified by category, host and location - not by "
            "URL - so an issue seen on several paths is reported once, with each "
            "observation kept as evidence. These findings represent more than one "
            "observation:"
        )
        lines.append("")
        lines.append("| Finding id | Location | Observations | Tool calls |")
        lines.append("| --- | --- | --- | --- |")
        for entry in report.merged_observations:
            calls = ", ".join(f"#{index}" for index in entry["tool_calls"]) or "-"
            lines.append(
                f"| `{entry['id']}` | {_md_cell(entry['location'])} | "
                f"{entry['observations']} | {calls} |"
            )
        lines.append("")

    lines.append("## Attack surface")
    lines.append("")
    surface = report.attack_surface
    lines.append(f"- Pages opened: {surface.get('pages_opened', 0)}")
    lines.append(f"- Unique URLs collected: {surface.get('links_total', 0)} "
                 f"({surface.get('links_in_scope', 0)} in scope)")
    lines.append(f"- URLs with query parameters: {surface.get('links_with_query', 0)}")
    lines.append(f"- Forms discovered: {surface.get('forms_total', 0)}")
    lines.append(f"- Scripts discovered: {surface.get('scripts_total', 0)}")
    lines.append(f"- API endpoint candidates: {surface.get('api_endpoints_total', 0)}")
    lines.append(f"- HTTP exchanges recorded: {surface.get('http_history_total', 0)}")
    lines.append("")

    robots = surface.get("robots") or {}
    if robots:
        lines.append("### Well-known files")
        lines.append("")
        lines.append(
            "- robots.txt: " + ("present" if robots.get("has_robots") else "not served")
        )
        lines.append(
            "- security.txt: " + ("present" if robots.get("has_security_txt") else "not served")
        )
        if robots.get("crawl_delay_s") is not None:
            lines.append(f"- crawl-delay requested: {robots['crawl_delay_s']}s")
        if not robots.get("has_robots"):
            lines.append("")
            lines.append(
                "A missing robots.txt is not a finding. It is recorded because its absence "
                "changes what the crawler could have discovered."
            )
        paths = robots.get("discovered_paths") or []
        if paths:
            lines.append("")
            lines.append(
                f"Paths derived from robots rules and the sitemap ({len(paths)}), now in the "
                "known-URL list:"
            )
            lines.append("")
            for path in paths[:40]:
                lines.append(f"- `{path}`")
            lines.append("")
            lines.append(
                "A `Disallow` entry is a disclosure hint, not a vulnerability: the operator "
                "chose to list the path publicly."
            )
        lines.append("")

    redirects = surface.get("redirect_chains") or []
    if redirects:
        lines.append("### Redirect chains followed")
        lines.append("")
        lines.append("| Requested | Final | Hops | Blocked |")
        lines.append("| --- | --- | --- | --- |")
        for entry in redirects[:30]:
            lines.append(
                "| {requested} | {final} | {hops} | {blocked} |".format(
                    requested=_md_cell(entry["requested_url"], 60),
                    final=_md_cell(entry["final_url"], 60),
                    hops=len(entry["chain"]),
                    blocked="yes" if entry["blocked"] else "no",
                )
            )
        lines.append("")

    endpoints = surface.get("api_endpoints") or []
    if endpoints:
        lines.append("API endpoint candidates:")
        lines.append("")
        for endpoint in endpoints[:40]:
            lines.append(f"- `{endpoint}`")
        lines.append("")

    lines.append("## Checks executed")
    lines.append("")
    if report.checks_executed:
        for tool in report.checks_executed:
            lines.append(f"- `{tool}`")
    else:
        lines.append("- (none)")
    lines.append("")
    if report.checks_skipped:
        lines.append("Checks that did not complete:")
        lines.append("")
        for skipped in report.checks_skipped:
            lines.append(f"- `{skipped['tool']}` ({skipped['status']}): {skipped['reason']}")
        lines.append("")

    lines.append("## Tool call trace")
    lines.append("")
    lines.append("| # | Tool | Status | ms | Findings | Reason |")
    lines.append("| --- | --- | --- | --- | --- | --- |")
    for record in report.tool_trace:
        lines.append(
            "| {index} | `{tool}` | {status} | {ms} | {findings} | {reason} |".format(
                index=record.index,
                tool=_md_cell(record.tool),
                status=record.status,
                ms=record.duration_ms,
                findings=record.findings_count,
                reason=_md_cell(record.reason) or "-",
            )
        )
    lines.append("")

    lines.append("## Limitations")
    lines.append("")
    for limitation in report.limitations:
        lines.append(f"- {limitation}")
    lines.append("")

    lines.append("## Disclaimer")
    lines.append("")
    lines.append(report.disclaimer)
    lines.append("")
    return "\n".join(lines)


def _md_cell(value: str, limit: int = 140) -> str:
    text = " ".join(str(value or "").split()).replace("|", "\\|")
    if len(text) > limit:
        text = text[: limit - 1] + "\u2026"
    return text


# --------------------------------------------------------------------------- #
# Assembly helpers
# --------------------------------------------------------------------------- #


def _duration(session: ScanSession) -> float:
    """Wall-clock duration, preferring the recorded timestamps."""
    if session.finished_at and session.started_at:
        try:
            started = _dt.datetime.fromisoformat(session.started_at)
            finished = _dt.datetime.fromisoformat(session.finished_at)
            return max(0.0, (finished - started).total_seconds())
        except ValueError:
            return 0.0
    return 0.0


def _executive_summary(
    session: ScanSession, counts: SeverityCounts, executed: list[str]
) -> str:
    """Deterministic summary. The planner's own text is kept separately as commentary."""
    surface = session.surface
    parts: list[str] = []
    parts.append(
        f"Passive, unauthenticated assessment of {session.scope.target}. "
        f"{len(session.trace)} tool call(s) ran, covering {', '.join(executed) or 'no tools'}, "
        f"and produced {counts.total} finding(s): {counts.critical} critical, "
        f"{counts.high} high, {counts.medium} medium, {counts.low} low and {counts.info} "
        "informational."
    )
    parts.append(
        f"The harness opened {len(surface.pages)} page(s) and inventoried "
        f"{len(surface.links)} URL(s), {len(surface.forms)} form(s), "
        f"{len(surface.scripts)} script(s) and {len(surface.api_endpoints)} API endpoint "
        "candidate(s)."
    )
    if counts.critical or counts.high:
        parts.append(
            "At least one high-severity configuration gap was identified; review those "
            "findings first. They are configuration weaknesses, not confirmed exploits."
        )
    else:
        parts.append(
            "No high-severity configuration gaps were identified by the checks that ran. "
            "This does not mean the application is free of vulnerabilities - see the "
            "limitations."
        )
    if session.status != ScanStatus.COMPLETED:
        parts.append(
            f"The scan ended with status '{session.status.value}': {session.stop_reason}"
        )
    return " ".join(parts)


def _attack_surface(session: ScanSession) -> dict[str, Any]:
    surface = session.surface
    links = list(surface.links.values())
    return {
        "pages_opened": len(surface.pages),
        "pages": [
            {
                "page_id": page_id,
                "url": str(facts.get("final_url") or facts.get("url") or ""),
                "status_code": facts.get("status_code"),
                "title": facts.get("title"),
                "html_bytes": facts.get("html_bytes"),
                "blocked_request_count": facts.get("blocked_request_count", 0),
            }
            for page_id, facts in surface.pages.items()
        ],
        "links_total": len(links),
        "links_in_scope": sum(1 for link in links if link.in_scope),
        "links_with_query": sum(1 for link in links if link.has_query),
        "sample_links": [
            {"url": link.url, "in_scope": link.in_scope, "query_keys": link.query_keys}
            for link in sorted(links, key=lambda item: (not item.in_scope, item.url))[:60]
        ],
        "forms_total": len(surface.forms),
        "forms": [form.model_dump(mode="json") for form in surface.forms[:40]],
        "scripts_total": len(surface.scripts),
        "scripts": [
            script.model_dump(mode="json") for script in list(surface.scripts.values())[:60]
        ],
        "api_endpoints_total": len(surface.api_endpoints),
        "api_endpoints": list(surface.api_endpoints[:80]),
        "technologies": list(surface.technologies),
        "open_questions": list(surface.open_questions[:40]),
        # Well-known file findings, so the report shows what robots.txt and the sitemap
        # disclosed rather than only the paths they produced.
        "robots": dict(surface.robots),
        # The transaction log, which is what makes a finding's provenance checkable.
        "http_history_total": len(surface.http_history),
        "http_history": [
            {
                "requested_url": entry.requested_url,
                "final_url": entry.final_url,
                "method": entry.method,
                "status_code": entry.status_code,
                "redirect_chain": entry.redirect_chain,
                "content_type": entry.content_type,
                "body_bytes": entry.body_bytes,
                "total_ms": entry.total_ms,
                "error": entry.error,
                "tool": entry.tool,
                "tool_call_index": entry.tool_call_index,
            }
            for entry in surface.http_history[:200]
        ],
        "redirect_chains": [
            {
                "requested_url": entry.requested_url,
                "final_url": entry.final_url,
                "chain": entry.redirect_chain,
                "blocked": entry.crossed_scope_boundary,
            }
            for entry in surface.redirect_chains()
        ],
        "tested_endpoints": dict(surface.tested_endpoints),
        "facts": list(surface.facts),
        "hints": list(surface.hints),
        "asset_tree": surface.to_asset_tree(session.findings),
    }


def _merged_observation_index(findings: list[Finding]) -> list[dict[str, Any]]:
    """Findings that collapsed several observations into one, as a transparency list.

    Deduplication happens before the report is built, so this is not a list of
    leftovers: it records which findings were seen on more than one path or by more
    than one tool, and how many raw observations each represents. That is what lets a
    reader tell "this header is missing" apart from "this header is missing on every
    page we looked at".
    """
    merged: list[dict[str, Any]] = []
    for finding in findings:
        if finding.merged_from <= 1 and len(finding.evidence) <= 1:
            continue
        merged.append(
            {
                "id": finding.id,
                "title": finding.title,
                "host": finding.host,
                "location": finding.location,
                "observations": max(finding.merged_from, len(finding.evidence)),
                "evidence_count": len(finding.evidence),
                "tool_calls": sorted(
                    {evidence.tool_call_index for evidence in finding.evidence}
                ),
            }
        )
    merged.sort(key=lambda entry: (-entry["observations"], entry["title"]))
    return merged


def _trace_entry(record: ToolCallRecord) -> ToolCallRecord:
    """Copy a trace entry into the report so later mutation cannot alter history."""
    return record.model_copy(deep=True)


def tool_categories(registry: ToolRegistry) -> dict[str, list[str]]:
    """Group registered tool names by category, for docs and the CLI."""
    grouped: dict[str, list[str]] = {category.value: [] for category in ToolCategory}
    for tool in registry:
        grouped[tool.category].append(tool.name)
    return {key: sorted(value) for key, value in grouped.items()}


__all__ = [
    "REPORT_VERSION",
    "build_report",
    "render_markdown",
    "tool_categories",
    "write_report",
]
