"""Scan context: the controlled resources a tool is allowed to use.

A tool body receives exactly one of these and nothing else. It has no shell, no
filesystem handle outside the artifact directory, no raw socket, and no way to read
the AI's conversation. That confinement is what makes "the AI can only use our
tools" a structural property rather than a prompt instruction.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.models.scan import ScanConfig, ScanSession
from app.policy.limits import LimitTracker
from app.policy.permissions import ConfirmationGate, PermissionSet, RequestPolicy
from app.policy.scope import ScopeGuard
from app.tools.async_runtime import LoopRunner
from app.tools.browser import BrowserSession, BrowserSettings
from app.tools.http_client import SafeHttpClient


@dataclass
class ToolContext:
    """Everything a tool needs, and nothing more.

    Browser and HTTP resources are created lazily: a passive-only scan should never
    pay for launching Chromium, and a scan that fails before any tool runs should
    not leave a browser process behind.
    """

    session: ScanSession
    scope: ScopeGuard
    limits: LimitTracker
    artifact_dir: Path
    permissions: PermissionSet = field(default_factory=PermissionSet)
    policy: RequestPolicy | None = None
    confirmation: ConfirmationGate = field(default_factory=ConfirmationGate)
    runner: LoopRunner = field(default_factory=LoopRunner)
    quiet: bool = False
    event_sink: Callable[[str], None] | None = None
    exchange_sink: Callable[[Any], None] | None = None

    _http: SafeHttpClient | None = field(default=None, init=False, repr=False)
    _browser: BrowserSession | None = field(default=None, init=False, repr=False)
    # Tools that ran under this context, in order. The registry appends here on every
    # successful call, so a tool can report real progress even when it is invoked directly
    # rather than through the orchestrator (which keeps its own fuller trace).
    tool_observations: list[tuple[str, str]] = field(default_factory=list, init=False, repr=False)

    def record_tool_run(self, name: str, status: str) -> None:
        """Note that a tool ran, for progress reporting."""
        self.tool_observations.append((name, status))

    def tools_run(self) -> list[str]:
        """Distinct tools that completed successfully under this context."""
        seen: list[str] = []
        for name, status in self.tool_observations:
            if status == "ok" and name not in seen:
                seen.append(name)
        return seen

    def __post_init__(self) -> None:
        if self.policy is None:
            self.policy = RequestPolicy(self.permissions)
        self.artifact_dir.mkdir(parents=True, exist_ok=True)

    # -- resources --------------------------------------------------------- #

    @property
    def config(self) -> ScanConfig:
        return self.session.config

    @property
    def http(self) -> SafeHttpClient:
        """The scope-aware HTTP client, created on first use.

        The exchange sink, when present, feeds the harness's transaction log so that
        ``get_http_history`` can report what was requested without re-requesting anything.
        """
        if self._http is None:
            self._http = SafeHttpClient(
                self.scope,
                self.limits,
                user_agent=self.config.user_agent,
                body_limit_bytes=self.config.response_body_limit_bytes,
                timeout_s=self.config.request_timeout_s,
                exchange_sink=self.exchange_sink,
            )
        return self._http

    @property
    def browser(self) -> BrowserSession:
        """The Playwright session, launched on first use."""
        if self._browser is None:
            self._browser = BrowserSession(
                self.runner,
                self.scope,
                artifact_dir=self.artifact_dir,
                settings=BrowserSettings(
                    navigation_timeout_ms=int(self.config.request_timeout_s * 1000)
                ),
                user_agent=self.config.user_agent,
            )
        return self._browser

    @property
    def browser_started(self) -> bool:
        return self._browser is not None and self._browser.started

    # -- logging ----------------------------------------------------------- #

    def emit(self, message: str) -> None:
        """Report progress. Never used for control flow."""
        if self.event_sink is not None:
            self.event_sink(message)
        elif not self.quiet:
            print(message, flush=True)

    # -- lifecycle --------------------------------------------------------- #

    def close(self) -> None:
        """Release every resource. Safe to call twice; never raises."""
        if self._browser is not None:
            self._browser.close()
            self._browser = None
        if self._http is not None:
            self._http.close()
            self._http = None
        self.runner.stop()

    def __enter__(self) -> ToolContext:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def resource_summary(self) -> dict[str, Any]:
        """What was actually allocated, for the report and for tests."""
        return {
            "http_client_created": self._http is not None,
            "browser_started": self.browser_started,
            "browser_pages": len(self._browser.handles) if self._browser else 0,
            "artifact_dir": str(self.artifact_dir),
        }
