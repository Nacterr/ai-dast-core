"""Controlled headless browser (Playwright).

The browser is the harness's hands. The AI never touches Playwright; it can only
call ``browser_open`` and the ``extract_*`` tools, which read from pages this
module already opened.

Four invariants this module enforces:

1. **Scope is checked before the page is opened** by the tool, and again on every
   request the page issues, here. A page cannot widen its own reach.
2. **Off-scope top-level navigations are blocked**, which is what stops a target
   from redirecting the scan into a third party.
3. **Off-scope script-initiated traffic is blocked** (fetch/XHR/WebSocket), because
   that is the channel that carries exfiltrated data.
4. **Cookies and storage are never persisted.** A fresh context per scan, no user
   data directory, and a clean teardown.

Known and documented limitation: third-party *subresources* a page needs to render
(scripts, stylesheets, fonts, images, media) are allowed to load from any host.
Blocking them breaks most real sites and would make discovery useless. See
``docs/SECURITY-MODEL.md`` for the reasoning and the residual risk.
"""

from __future__ import annotations

import hashlib
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

from app.policy.scope import ScopeGuard
from app.tools.async_runtime import LoopRunner

# Resource types whose *destination* is decided by page script rather than by the
# document's markup. These must always be in scope.
_SCRIPT_INITIATED_TYPES: frozenset[str] = frozenset({"fetch", "xhr", "websocket", "eventsource"})

# Resource types a document legitimately pulls from third parties to render.
_RENDER_TYPES: frozenset[str] = frozenset(
    {"script", "stylesheet", "image", "font", "media", "manifest", "other", "beacon", "ping"}
)

_MAX_RECORDED_BLOCKS = 100
_MAX_CONSOLE_ERRORS = 25
_MAX_CONSOLE_MESSAGE_CHARS = 300


@dataclass
class BlockedRequest:
    """One request the browser refused to make."""

    url: str
    resource_type: str
    reason: str
    is_navigation: bool = False


@dataclass
class PageHandle:
    """A page opened by this scan."""

    page_id: str
    url: str
    final_url: str
    status_code: int | None
    title: str
    content_type: str
    html: str
    redirect_chain: list[str] = field(default_factory=list)
    out_of_scope_redirect: str | None = None
    blocked_requests: list[BlockedRequest] = field(default_factory=list)
    console_errors: list[str] = field(default_factory=list)
    screenshot_path: str | None = None
    notes: list[str] = field(default_factory=list)
    javascript_enabled: bool = True
    opened_at: float = field(default_factory=time.monotonic)

    @property
    def html_sha256(self) -> str:
        return hashlib.sha256(self.html.encode("utf-8", errors="replace")).hexdigest()

    @property
    def html_bytes(self) -> int:
        return len(self.html.encode("utf-8", errors="replace"))

    def match_counts(self) -> dict[str, int]:
        """Blocked-request counts grouped by reason, for the summary line."""
        counts: dict[str, int] = {}
        for blocked in self.blocked_requests:
            counts[blocked.reason] = counts.get(blocked.reason, 0) + 1
        return counts


@dataclass
class BrowserSettings:
    """Behavioural settings for the browser session."""

    navigation_timeout_ms: int = 20_000
    default_wait_until: str = "domcontentloaded"
    viewport_width: int = 1366
    viewport_height: int = 900
    locale: str = "en-US"
    timezone: str = "UTC"
    # A single Chromium flag set kept deliberately small; anything more exotic
    # belongs in a profile, not in the default path.
    args: tuple[str, ...] = (
        "--disable-dev-shm-usage",
        "--no-first-run",
        "--no-default-browser-check",
    )


class BrowserUnavailableError(RuntimeError):
    """Raised when Playwright or its browser binary cannot be started."""


class BrowserSession:
    """Wraps a Playwright Chromium context for the duration of one scan."""

    def __init__(
        self,
        runner: LoopRunner,
        scope: ScopeGuard,
        *,
        artifact_dir: Path,
        settings: BrowserSettings | None = None,
        user_agent: str | None = None,
    ) -> None:
        self._runner = runner
        self._scope = scope
        self._artifact_dir = artifact_dir
        self._settings = settings or BrowserSettings()
        self._user_agent = user_agent
        self._playwright: Any = None
        self._browser: Any = None
        self._context: Any = None
        self._no_js_contexts: list[Any] = []
        self._pages: dict[str, Any] = {}
        self._handles: dict[str, PageHandle] = {}
        self._order: list[str] = []
        self._started = False

    # -- lifecycle --------------------------------------------------------- #

    @property
    def started(self) -> bool:
        return self._started

    def start(self) -> None:
        """Launch Chromium. Raises :class:`BrowserUnavailableError` on failure."""
        if self._started:
            return
        self._runner.start()
        try:
            self._runner.submit(self._start_async(), timeout=90.0)
        except BrowserUnavailableError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise BrowserUnavailableError(
                f"could not start Playwright Chromium: {type(exc).__name__}: {exc}. "
                "Install browsers with: python -m playwright install chromium"
            ) from exc
        self._started = True

    async def _start_async(self) -> None:
        try:
            from playwright.async_api import async_playwright
        except ImportError as exc:  # pragma: no cover - dependency error path
            raise BrowserUnavailableError(
                "the 'playwright' package is not installed; run: pip install playwright"
            ) from exc

        self._playwright = await async_playwright().start()
        try:
            self._browser = await self._playwright.chromium.launch(
                headless=True, args=list(self._settings.args)
            )
        except Exception as exc:  # noqa: BLE001
            with_suppress = getattr(self._playwright, "stop", None)
            if with_suppress is not None:
                try:
                    await with_suppress()
                except Exception:  # noqa: BLE001
                    pass
            raise BrowserUnavailableError(
                f"Chromium failed to launch: {exc}. "
                "Install browsers with: python -m playwright install chromium"
            ) from exc

        self._context = await self._browser.new_context(
            viewport={
                "width": self._settings.viewport_width,
                "height": self._settings.viewport_height,
            },
            locale=self._settings.locale,
            timezone_id=self._settings.timezone,
            ignore_https_errors=False,
            java_script_enabled=True,
            **({"user_agent": self._user_agent} if self._user_agent else {}),
        )
        self._context.set_default_navigation_timeout(self._settings.navigation_timeout_ms)
        self._context.set_default_timeout(self._settings.navigation_timeout_ms)

    def close(self) -> None:
        """Tear everything down. Never raises: shutdown must not mask errors."""
        if not self._started and self._playwright is None:
            return
        try:
            self._runner.submit(self._close_async(), timeout=30.0)
        except Exception:  # noqa: BLE001
            pass
        finally:
            self._started = False
            self._pages.clear()
            self._context = None
            self._browser = None
            self._playwright = None

    async def _close_async(self) -> None:
        targets: list[tuple[Any, str]] = [(context, "close") for context in self._no_js_contexts]
        targets.extend(
            [
                (self._context, "close"),
                (self._browser, "close"),
                (self._playwright, "stop"),
            ]
        )
        for target, method in targets:
            if target is None:
                continue
            try:
                await getattr(target, method)()
            except Exception:  # noqa: BLE001
                pass
        self._no_js_contexts.clear()

    # -- page access ------------------------------------------------------- #

    @property
    def handles(self) -> dict[str, PageHandle]:
        return dict(self._handles)

    def latest_page_id(self) -> str | None:
        return self._order[-1] if self._order else None

    def get_handle(self, page_id: str | None) -> PageHandle | None:
        """Fetch a page handle, defaulting to the most recently opened page."""
        if page_id is None:
            page_id = self.latest_page_id()
        if page_id is None:
            return None
        return self._handles.get(page_id)

    def evaluate(self, page_id: str, script: str, *, timeout: float = 20.0) -> Any:
        """Run one of the harness's fixed extraction snippets in a live page.

        ``script`` must come from :mod:`app.tools.js_snippets`; it is never assembled
        from AI-supplied data. Playwright's ``page.evaluate`` is a coroutine, so the call
        is marshalled onto the event-loop thread - calling it directly from a tool would
        silently return an un-awaited coroutine.

        Returns ``None`` when the page is not live (for example a JavaScript-disabled
        capture, whose page was already closed); callers then fall back to parsing the
        saved HTML.
        """
        page = self._pages.get(page_id)
        if page is None:
            return None
        try:
            return self._runner.submit(page.evaluate(script), timeout=timeout)
        except Exception:  # noqa: BLE001 - extraction failures fall back to HTML parsing
            return None

    def is_live(self, page_id: str) -> bool:
        """Whether a page handle still has a live, scriptable page behind it."""
        return page_id in self._pages

    def list_pages(self) -> list[dict[str, Any]]:
        return [
            {
                "page_id": handle.page_id,
                "url": handle.final_url or handle.url,
                "title": handle.title,
                "status_code": handle.status_code,
                "html_bytes": handle.html_bytes,
            }
            for handle in self._handles.values()
        ]

    # -- navigation -------------------------------------------------------- #

    def open(
        self,
        url: str,
        *,
        decision: Any,
        wait_until: Literal["domcontentloaded", "load", "networkidle"] = "domcontentloaded",
        wait_ms: int = 500,
        screenshot: bool = False,
        full_page: bool = False,
        disable_javascript: bool = False,
    ) -> PageHandle:
        """Navigate to an already scope-checked URL and capture the page.

        ``decision`` is the :class:`~app.policy.scope.ScopeDecision` produced by the
        caller. It is required (not optional) so that no code path can open a URL
        without having asked the scope guard first.
        """
        self.start()
        if not getattr(decision, "allowed", False):
            raise ValueError("refusing to open a URL whose scope decision is not allowed")
        return self._runner.submit(
            self._open_async(
                url,
                wait_until=wait_until,
                wait_ms=wait_ms,
                screenshot=screenshot,
                full_page=full_page,
                disable_javascript=disable_javascript,
            ),
            timeout=(self._settings.navigation_timeout_ms / 1000.0) + wait_ms / 1000.0 + 45.0,
        )

    async def _open_async(
        self,
        url: str,
        *,
        wait_until: str,
        wait_ms: int,
        screenshot: bool,
        full_page: bool,
        disable_javascript: bool,
    ) -> PageHandle:
        page_id = f"p{uuid.uuid4().hex[:8]}"
        context = await self._context_for(java_script_enabled=not disable_javascript)
        page = await context.new_page()

        blocked: list[BlockedRequest] = []
        console_errors: list[str] = []
        notes: list[str] = []

        await page.route("**/*", _make_route_handler(self._scope, blocked, notes))

        page.on(
            "console",
            lambda message: _record_console(message, console_errors),
        )
        page.on("pageerror", lambda error: _record_page_error(error, console_errors))

        response = None
        out_of_scope_redirect: str | None = None
        try:
            response = await page.goto(url, wait_until=wait_until)
        except Exception as exc:  # noqa: BLE001 - navigation failures are data, not crashes
            notes.append(f"navigation raised {type(exc).__name__}: {str(exc)[:200]}")

        if wait_ms:
            try:
                await page.wait_for_timeout(wait_ms)
            except Exception:  # noqa: BLE001
                pass

        html = ""
        try:
            html = await page.content()
        except Exception as exc:  # noqa: BLE001
            notes.append(f"could not read page content: {type(exc).__name__}")
        effective_html = html if isinstance(html, str) else ""

        final_url = url
        try:
            final_url = page.url
        except Exception:  # noqa: BLE001
            pass

        # Detect an off-scope main-frame URL. The route handler aborts these, so
        # this is a second, independent check on the same invariant.
        final_decision = self._scope.check_url(final_url, resolve=False)
        if not final_decision.allowed:
            out_of_scope_redirect = final_url
            notes.append(f"final URL is out of scope and was not fetched: {final_decision.reason}")

        status_code: int | None = None
        if response is not None:
            try:
                status_code = response.status
            except Exception:  # noqa: BLE001
                status_code = None

        title = ""
        try:
            title = (await page.title())[:500]
        except Exception:  # noqa: BLE001
            pass

        content_type = ""
        if response is not None:
            try:
                headers = await response.all_headers()
                content_type = str(headers.get("content-type", ""))[:200]
            except Exception:  # noqa: BLE001
                pass

        screenshot_rel: str | None = None
        if screenshot:
            screenshot_rel = await self._capture_screenshot(page, page_id, full_page, notes)

        redirect_chain: list[str] = []
        if response is not None:
            try:
                request = response.request
                chain: list[str] = []
                cursor = request.redirected_from
                while cursor is not None:
                    chain.append(cursor.url)
                    cursor = cursor.redirected_from
                redirect_chain = list(reversed(chain)) + [request.url]
            except Exception:  # noqa: BLE001
                redirect_chain = []

        handle = PageHandle(
            page_id=page_id,
            url=url,
            final_url=final_url,
            status_code=status_code,
            title=title,
            content_type=content_type,
            html=effective_html,
            redirect_chain=redirect_chain,
            out_of_scope_redirect=out_of_scope_redirect,
            blocked_requests=blocked[:_MAX_RECORDED_BLOCKS],
            console_errors=console_errors[:_MAX_CONSOLE_ERRORS],
            screenshot_path=screenshot_rel,
            notes=notes,
            javascript_enabled=not disable_javascript,
        )

        if not disable_javascript:
            self._pages[page_id] = page
        else:
            # A JS-disabled page still has useful static HTML; keep the handle but
            # close the live page so the resource is not held for the whole scan.
            try:
                await page.close()
            except Exception:  # noqa: BLE001
                pass

        self._handles[page_id] = handle
        self._order.append(page_id)
        return handle

    async def _context_for(self, *, java_script_enabled: bool) -> Any:
        """Return the context to use for the requested JS mode.

        A JS-disabled view needs a separate context because the flag is per-context
        in Playwright, not per-page. Those throwaway contexts are tracked so they can
        be closed with the session.
        """
        if self._context is None:
            raise BrowserUnavailableError("browser context is not available")
        if java_script_enabled:
            return self._context
        context = await self._browser.new_context(
            viewport={
                "width": self._settings.viewport_width,
                "height": self._settings.viewport_height,
            },
            locale=self._settings.locale,
            timezone_id=self._settings.timezone,
            ignore_https_errors=False,
            java_script_enabled=False,
            **({"user_agent": self._user_agent} if self._user_agent else {}),
        )
        context.set_default_navigation_timeout(self._settings.navigation_timeout_ms)
        self._no_js_contexts.append(context)
        return context

    async def _capture_screenshot(
        self, page: Any, page_id: str, full_page: bool, notes: list[str]
    ) -> str | None:
        try:
            self._artifact_dir.mkdir(parents=True, exist_ok=True)
            target = self._artifact_dir / f"{page_id}.png"
            await page.screenshot(path=str(target), full_page=full_page)
            return str(target.name)
        except Exception as exc:  # noqa: BLE001
            notes.append(f"screenshot failed: {type(exc).__name__}")
            return None

    # -- cookies ----------------------------------------------------------- #

    def cookies(self) -> list[dict[str, Any]]:
        """All cookies Playwright currently holds. Never persisted to disk."""
        if not self._started or self._context is None:
            return []
        try:
            raw = self._runner.submit(self._context.cookies(), timeout=20.0)
        except Exception:  # noqa: BLE001
            return []
        return [dict(cookie) for cookie in raw or []]


def _make_route_handler(scope: ScopeGuard, blocked: list[BlockedRequest], notes: list[str]):
    """Build the Playwright route handler that enforces scope at request time."""

    async def handler(route, request) -> None:  # type: ignore[no-untyped-def]
        url = request.url
        resource_type = (request.resource_type or "other").lower()
        is_navigation = bool(request.is_navigation_request())

        decision = scope.check_url(url, resolve=False)
        if decision.allowed:
            await route.continue_()
            return

        if is_navigation:
            blocked.append(
                BlockedRequest(url=url, resource_type=resource_type,
                               reason=f"off-scope navigation: {decision.reason}", is_navigation=True)
            )
            await route.abort("blockedbyclient")
            return

        if resource_type in _SCRIPT_INITIATED_TYPES:
            blocked.append(
                BlockedRequest(
                    url=url,
                    resource_type=resource_type,
                    reason=f"off-scope {resource_type} upload/request: {decision.reason}",
                )
            )
            await route.abort("blockedbyclient")
            return

        if resource_type in _RENDER_TYPES:
            # Permitted so the page can render. The destination is still recorded
            # so the report can disclose third-party contact.
            if len(blocked) < _MAX_RECORDED_BLOCKS:
                blocked.append(
                    BlockedRequest(
                        url=url,
                        resource_type=resource_type,
                        reason=f"allowed third-party subresource ({resource_type})",
                    )
                )
            await route.continue_()
            return

        blocked.append(
            BlockedRequest(
                url=url,
                resource_type=resource_type,
                reason=f"unknown resource type {resource_type!r} outside scope",
            )
        )
        await route.abort("blockedbyclient")

    return handler


def _record_console(message: Any, sink: list[str]) -> None:
    try:
        if getattr(message, "type", "") != "error":
            return
        text = str(getattr(message, "text", ""))[:_MAX_CONSOLE_MESSAGE_CHARS]
        if text:
            sink.append(text)
    except Exception:  # noqa: BLE001
        pass


def _record_page_error(error: Any, sink: list[str]) -> None:
    try:
        sink.append(f"pageerror: {str(error)[:_MAX_CONSOLE_MESSAGE_CHARS]}")
    except Exception:  # noqa: BLE001
        pass


def origin_of(url: str) -> str:
    """Return ``scheme://host[:port]`` for a URL, or an empty string."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return ""
    if not parts.scheme or not parts.hostname:
        return ""
    port = f":{parts.port}" if parts.port else ""
    return f"{parts.scheme.lower()}://{parts.hostname.lower()}{port}"
