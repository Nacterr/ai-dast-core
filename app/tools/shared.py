"""Shared plumbing for tool bodies: scope gating and page resolution.

These helpers exist so each tool body reads as security logic rather than
boilerplate, and so the scope gate is applied identically everywhere. Every
target-contacting tool begins with :func:`require_in_scope`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.policy.scope import ScopeDecision
from app.tools.base import ToolExecutionError


class ScopeDenied(ToolExecutionError):
    """The requested URL is outside the scan scope.

    Raised (rather than returned) so a tool body cannot accidentally continue with
    an out-of-scope URL: the dispatcher turns it into a normal ``error`` result and
    the planner sees exactly why it was refused.
    """

    def __init__(self, decision: ScopeDecision) -> None:
        super().__init__(f"out of scope: {decision.reason}")
        self.decision = decision


def require_in_scope(ctx: Any, url: str, *, resolve: bool = True) -> ScopeDecision:
    """Validate a URL against the scope guard or raise :class:`ScopeDenied`."""
    decision = ctx.scope.check_url(url, resolve=resolve)
    if not decision.allowed:
        raise ScopeDenied(decision)
    return decision


def require_page(ctx: Any, page_id: str | None) -> Any:
    """Resolve a page handle, or raise with a message the planner can act on."""
    browser = ctx.browser
    handle = browser.get_handle(page_id)
    if handle is None:
        available = ", ".join(browser.handles) or "(none)"
        hint = (
            "Call browser_open first to create a page."
            if not browser.handles
            else f"Available page ids: {available}."
        )
        raise ToolExecutionError(
            f"no page available for page_id={page_id!r}. {hint}"
        )
    return handle


@dataclass
class PageBudget:
    """Tracks how many distinct pages a scan has opened against its budget."""

    def reserve(self, ctx: Any) -> None:
        ctx.limits.reserve("pages")


def clean_text(value: Any, limit: int = 200) -> str:
    """Collapse whitespace and bound a string taken from untrusted HTML."""
    if not isinstance(value, str):
        return ""
    collapsed = " ".join(value.split())
    if len(collapsed) > limit:
        return collapsed[: limit - 1] + "\u2026"
    return collapsed


def scope_annotate(ctx: Any, url: str) -> tuple[bool, str]:
    """Return ``(in_scope, reason)`` without performing DNS resolution.

    Used when annotating links in a report: we want to tell the planner whether a
    link is *fetchable*, without spending a lookup on every link on a page.
    """
    decision = ctx.scope.check_url(url, resolve=False)
    return decision.allowed, ("in scope" if decision.allowed else decision.reason)


__all__ = [
    "PageBudget",
    "ScopeDenied",
    "clean_text",
    "require_in_scope",
    "require_page",
    "scope_annotate",
]
