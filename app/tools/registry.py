"""Tool registry and dispatcher.

The registry is the *allowlist*. If a name is not in it, the AI cannot call it -
there is no fallback path, no dynamic import, no ``eval``.

The dispatcher is the *choke point*. Every AI-requested action flows through
:meth:`ToolRegistry.dispatch`, which runs the same ordered pipeline regardless of
which tool was asked for:

1. **lookup** - is this a registered tool name?
2. **availability** - is it implemented in this build?
3. **permissions** - does the process hold the capabilities it needs, and do the
   arguments look like an escape attempt?
4. **confirmation** - has a human approved it, when required?
5. **validation** - do the arguments satisfy the declared request model?
6. **budget** - is there tool-call budget left for this scan?
7. **execution** - run the tool body with a timeout.
8. **truncation** - trim the payload to the AI's token budget.

Steps 1-6 are pure policy and never touch the network, which is what makes the
guarantees testable without a live target.
"""

from __future__ import annotations

import concurrent.futures
import time
from collections.abc import Iterator
from typing import Any

from pydantic import ValidationError

from app.models.finding import Finding
from app.models.tools import ToolCall, ToolMeta, ToolResult, ToolStatus
from app.policy.limits import LimitExceeded
from app.policy.permissions import ConfirmationRequest
from app.tools.base import Tool, ToolExecutionError, ToolOutcome, ToolUnavailableError, build_result
from app.tools.context import ToolContext

# A tool body that blocks longer than this is treated as a harness bug, not an
# AI problem: the AI-facing limits are enforced separately by LimitTracker.
_EXECUTION_GRACE_S = 5.0


class ToolNotFoundError(KeyError):
    """Raised when a tool name is not registered."""


class ToolRegistry:
    """Ordered collection of :class:`Tool` definitions."""

    def __init__(self, tools: list[Tool] | None = None) -> None:
        self._tools: dict[str, Tool] = {}
        for tool in tools or []:
            self.register(tool)

    # -- construction ------------------------------------------------------ #

    def register(self, tool: Tool) -> Tool:
        name = tool.meta.name
        if name in self._tools:
            raise ValueError(f"tool {name!r} is already registered")
        self._tools[name] = tool
        return tool

    def extend(self, tools: list[Tool]) -> ToolRegistry:
        for tool in tools:
            self.register(tool)
        return self

    # -- lookup ------------------------------------------------------------ #

    def __contains__(self, name: object) -> bool:
        return name in self._tools

    def __len__(self) -> int:
        return len(self._tools)

    def __iter__(self) -> Iterator[Tool]:
        return iter(self._tools.values())

    def get(self, name: str) -> Tool:
        try:
            return self._tools[name]
        except KeyError:
            raise ToolNotFoundError(
                f"unknown tool {name!r}; available: {', '.join(sorted(self._tools))}"
            ) from None

    @property
    def names(self) -> list[str]:
        return list(self._tools)

    def metas(self) -> list[ToolMeta]:
        return [tool.meta for tool in self._tools.values()]

    def by_category(self, category: str) -> list[Tool]:
        return [tool for tool in self._tools.values() if tool.category == category]

    def implemented(self) -> list[Tool]:
        return [tool for tool in self._tools.values() if tool.meta.implemented]

    def callable_tools(self) -> list[Tool]:
        """Tools the AI is actually offered: registered and implemented."""
        return self.implemented()

    # -- AI-facing surface ------------------------------------------------- #

    def to_llm_specs(
        self,
        *,
        compact: bool = False,
        names: Sequence[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Tool specs for an LLM tool-calling API (only implemented tools)."""
        tools = self.callable_tools()
        if names is not None:
            name_set = set(names)
            tools = [t for t in tools if t.name in name_set]
        return [tool.to_llm_spec(compact=compact) for tool in tools]

    def describe(self) -> list[dict[str, Any]]:
        """Full listing, including roadmap tools, for docs and the CLI."""
        return [tool.to_dict() for tool in self._tools.values()]

    def render_for_prompt(self) -> str:
        """Compact catalogue injected into the planner's system prompt."""
        lines: list[str] = []
        for tool in self.callable_tools():
            tags = f" (tags: {', '.join(tool.meta.tags)})" if tool.meta.tags else ""
            lines.append(f"- {tool.name} [{tool.category}]: {tool.meta.summary}{tags}")
        unavailable = [tool for tool in self._tools.values() if not tool.meta.implemented]
        if unavailable:
            lines.append("")
            lines.append("Declared but NOT available in this build:")
            for tool in unavailable:
                lines.append(f"- {tool.name}: {tool.meta.summary} (not implemented)")
        return "\n".join(lines)

    # -- dispatch ---------------------------------------------------------- #

    def dispatch(self, call: ToolCall, ctx: ToolContext, *, step: int = 0) -> ToolResult:
        """Validate, authorise, execute and normalise one tool call."""
        started = time.monotonic()

        # 1. lookup
        try:
            tool = self.get(call.tool)
        except ToolNotFoundError as exc:
            return build_result(
                call.tool,
                status=ToolStatus.DENIED,
                summary="Tool is not available.",
                denial_reason=str(exc),
                duration_ms=_elapsed_ms(started),
            )

        # 2. availability
        if not tool.meta.implemented:
            return build_result(
                call.tool,
                status=ToolStatus.NOT_IMPLEMENTED,
                summary=f"{call.tool} is declared but not implemented in this build.",
                denial_reason="tool not implemented",
                duration_ms=_elapsed_ms(started),
            )

        # 3. permissions + argument screening
        assert ctx.policy is not None
        preflight = ctx.policy.preflight(tool.meta, call.args)
        if not preflight.allowed:
            return build_result(
                call.tool,
                status=ToolStatus.DENIED,
                summary="The harness refused this call before execution.",
                denial_reason=f"[{preflight.stage}] {preflight.reason}",
                duration_ms=_elapsed_ms(started),
            )

        # 4. confirmation
        if tool.meta.requires_confirmation and ctx.config.require_confirmation:
            approved, reason = ctx.confirmation.request(
                ConfirmationRequest(tool=tool.meta, args=call.args, reason=call.reason)
            )
            if not approved:
                return build_result(
                    call.tool,
                    status=ToolStatus.DENIED,
                    summary="A human declined this action.",
                    denial_reason=reason,
                    duration_ms=_elapsed_ms(started),
                )

        # 5. argument validation against the declared contract
        try:
            request = tool.parse_args(call.args)
        except ValidationError as exc:
            return build_result(
                call.tool,
                status=ToolStatus.DENIED,
                summary=(
                    "Arguments did not satisfy the tool's schema. "
                    "Re-read the tool description and retry with valid parameters."
                ),
                denial_reason=_format_validation_error(exc),
                duration_ms=_elapsed_ms(started),
            )

        # 6. budget
        try:
            ctx.limits.reserve("tool_calls")
        except LimitExceeded as exc:
            return build_result(
                call.tool,
                status=ToolStatus.DENIED,
                summary="Scan budget exhausted.",
                denial_reason=exc.message,
                duration_ms=_elapsed_ms(started),
            )

        # 7. execution
        result = self._execute(tool, request, ctx, started)
        # Record the run on the context so a progress tool can report it even when this
        # registry was invoked directly rather than through the orchestrator.
        ctx.record_tool_run(tool.name, result.status.value)
        return result

    def _execute(
        self,
        tool: Tool,
        request: Any,
        ctx: ToolContext,
        started: float,
    ) -> ToolResult:
        timeout_s = ctx.config.tool_timeout_s + _EXECUTION_GRACE_S

        # A tool that only reads already-captured page state does not need a thread,
        # but using one uniformly keeps timeouts honest and the loop responsive.
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=1, thread_name_prefix=f"tool-{tool.name}"
        ) as pool:
            future = pool.submit(tool.executor, ctx, request)
            try:
                outcome: ToolOutcome = future.result(timeout=timeout_s)
            except concurrent.futures.TimeoutError:
                future.cancel()
                return build_result(
                    tool.name,
                    status=ToolStatus.TIMEOUT,
                    summary=f"{tool.name} exceeded its {ctx.config.tool_timeout_s:.0f}s budget.",
                    error=f"tool timeout after {timeout_s:.0f}s",
                    duration_ms=_elapsed_ms(started),
                )
            except LimitExceeded as exc:
                return build_result(
                    tool.name,
                    status=ToolStatus.DENIED,
                    summary="Scan budget exhausted during execution.",
                    denial_reason=exc.message,
                    duration_ms=_elapsed_ms(started),
                )
            except ToolUnavailableError as exc:
                # The budget was spent, but no target contact happened; hand it back.
                ctx.limits.release("tool_calls")
                return build_result(
                    tool.name,
                    status=ToolStatus.ERROR,
                    summary=f"{tool.name} is unavailable in this environment.",
                    error=str(exc),
                    duration_ms=_elapsed_ms(started),
                )
            except ToolExecutionError as exc:
                return build_result(
                    tool.name,
                    status=ToolStatus.ERROR,
                    summary=f"{tool.name} could not complete: {exc}",
                    error=str(exc),
                    duration_ms=_elapsed_ms(started),
                )
            except Exception as exc:  # noqa: BLE001 - a tool bug must not kill the scan
                return build_result(
                    tool.name,
                    status=ToolStatus.ERROR,
                    summary=f"{tool.name} raised {type(exc).__name__}.",
                    error=f"{type(exc).__name__}: {exc}",
                    duration_ms=_elapsed_ms(started),
                )

        return self._finalize(tool, outcome, ctx, started)

    def _finalize(
        self,
        tool: Tool,
        outcome: ToolOutcome,
        ctx: ToolContext,
        started: float,
    ) -> ToolResult:
        data = outcome.data_dict()
        truncated = False
        budget = ctx.config.max_payload_chars
        rendered_size = len(repr(data))
        if rendered_size > budget:
            data, truncated = _truncate_payload(
                data,
                budget,
                priority_fields=outcome.priority_fields,
                droppable_fields=outcome.droppable_fields,
            )

        findings = _dedupe_within(outcome.findings)
        return build_result(
            tool.name,
            status=ToolStatus.OK,
            summary=outcome.summary,
            data=data,
            duration_ms=_elapsed_ms(started),
            truncated=truncated,
            findings=findings,
            artifacts=outcome.artifacts,
        )

def _elapsed_ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)


def _format_validation_error(exc: ValidationError) -> str:
    """Render a Pydantic error as short, actionable guidance for the planner."""
    problems: list[str] = []
    for error in exc.errors()[:8]:
        location = ".".join(str(part) for part in error.get("loc", ())) or "(root)"
        problems.append(f"{location}: {error.get('msg', 'invalid')}")
    return "; ".join(problems)


def _dedupe_within(findings: list[Finding]) -> list[Finding]:
    """Collapse findings raised twice by the same tool within one call."""
    seen: set[str] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = finding.dedup_key()
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def _truncate_payload(
    data: dict[str, Any],
    budget: int,
    *,
    priority_fields: tuple[str, ...] = (),
    droppable_fields: tuple[str, ...] = (),
) -> tuple[dict[str, Any], bool]:
    """Trim a payload deterministically to the AI's character budget.

    Three escalating strategies, because the goal is to degrade gracefully rather than to
    drop whatever happens to be last:

    1. Keep every item but strip ``droppable_fields`` (prose) from each. The facts survive
       even when the explanation does not.
    2. Keep a prefix of each list. For ``priority_fields`` the tool has already ordered
       entries most-important-first, so a prefix keeps what matters.
    3. Keep a short prefix of five.

    Every shortened list gets an explicit ``<field>_truncated`` marker **and** the original
    length in ``<field>_total``. Without that, a truncated payload is indistinguishable from
    a complete one - exactly the kind of silent lie that makes a security report
    untrustworthy.
    """
    truncated = False
    result: dict[str, Any] = {}
    for key, value in data.items():
        if isinstance(value, list) and value:
            result[key] = list(value)
        else:
            result[key] = value

    if len(repr(result)) <= budget:
        return result, truncated

    # Step 1: keep every item, drop the declared prose. Only for prioritised lists, where
    # keeping the full set of important entries is worth losing the explanations.
    if droppable_fields:
        compacted = _drop_fields_within_budget(
            result, budget, priority_fields=priority_fields, droppable_fields=droppable_fields
        )
        if compacted is not None:
            return compacted, True

    # Step 2: shorten the prioritised lists, trim-first-last, so the important entries
    # survive. Non-prioritised lists are left alone here; they are handled by step 3.
    result, truncated = _prefix_prioritised_lists(result, budget, priority_fields)
    if len(repr(result)) <= budget:
        return result, truncated

    # Step 3: keep a short prefix of every list. Last resort.
    trimmed: dict[str, Any] = {}
    for key, value in result.items():
        if isinstance(value, list):
            trimmed[key] = value[:5]
            if len(value) > 5:
                trimmed[f"{key}_truncated"] = True
                trimmed.setdefault(f"{key}_total", len(value))
                if key in priority_fields:
                    trimmed.setdefault(f"{key}_omitted", len(value) - 5)
                truncated = True
        else:
            trimmed[key] = value
    return trimmed, truncated


def _prefix_prioritised_lists(
    data: dict[str, Any], budget: int, priority_fields: tuple[str, ...]
) -> tuple[dict[str, Any], bool]:
    """Shrink prioritised lists to the longest prefix that fits the whole payload.

    A binary search rather than a fixed half-budget guess: the previous heuristic kept only
    three of twenty-seven entries while the payload was less than half the budget, which is
    the sort of silent information loss that makes a report untrustworthy.
    """
    truncated = False
    result = dict(data)

    for key in priority_fields:
        value = result.get(key)
        if not isinstance(value, list) or not value:
            continue
        if len(repr(result)) <= budget:
            break

        low, high = 1, len(value)
        best = 1
        while low <= high:
            mid = (low + high) // 2
            probe = dict(result)
            probe[key] = value[:mid]
            if len(repr(probe)) <= budget:
                best = mid
                low = mid + 1
            else:
                high = mid - 1

        if best < len(value):
            result[key] = value[:best]
            result[f"{key}_truncated"] = True
            result[f"{key}_total"] = len(value)
            result[f"{key}_omitted"] = len(value) - best
            truncated = True
    return result, truncated


def _drop_fields_within_budget(
    data: dict[str, Any],
    budget: int,
    *,
    priority_fields: tuple[str, ...],
    droppable_fields: tuple[str, ...],
) -> dict[str, Any] | None:
    """Drop ``droppable_fields`` from every item, progressively, until the payload fits.

    Returns ``None`` when even the fully-stripped payload is still too large, so the caller
    can fall back to dropping items instead.

    The number of items kept is fixed first, and the *number of fields per item* is what
    shrinks. Doing it the other way round is what produces reports where the important rows
    are missing - the failure mode this whole mechanism exists to avoid.
    """
    droppable = list(droppable_fields)

    for cut in range(0, len(droppable) + 1):
        removed = set(droppable[:cut])
        candidate: dict[str, Any] = {}
        for key, value in data.items():
            if isinstance(value, list) and value and key in priority_fields:
                stripped_items = [
                    {field: item_value for field, item_value in item.items() if field not in removed}
                    if isinstance(item, dict)
                    else item
                    for item in value
                ]
                candidate[key] = stripped_items
                if removed:
                    candidate[f"{key}_fields_omitted"] = sorted(removed)
                    candidate.setdefault(f"{key}_total", len(value))
            else:
                candidate[key] = value

        if len(repr(candidate)) <= budget:
            return candidate
    return None


__all__ = [
    "Tool",
    "ToolNotFoundError",
    "ToolRegistry",
]
