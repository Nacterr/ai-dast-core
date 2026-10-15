"""A tiny dedicated event-loop thread.

Playwright's async API needs a running asyncio loop, but the scan orchestrator is
deliberately synchronous: the AI planner does blocking LLM calls and the tool
dispatcher must be easy to reason about and to test.

Rather than leak ``async``/``await`` through the whole application, one loop lives
on its own thread for the lifetime of a scan. Everything else submits coroutines to
it and blocks on the returned future. One loop also means one Playwright transport
and one browser process, which is exactly the resource model we want.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import contextlib
import threading
import time
from collections.abc import Awaitable, Callable
from typing import Any, TypeVar

T = TypeVar("T")

DEFAULT_START_TIMEOUT_S = 20.0
DEFAULT_SHUTDOWN_TIMEOUT_S = 15.0


class LoopRunner:
    """Owns a background thread with a running asyncio event loop."""

    def __init__(self, name: str = "dsh-async-loop") -> None:
        self._name = name
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._started = threading.Event()
        self._stopped = threading.Event()
        self._lock = threading.Lock()

    # -- lifecycle --------------------------------------------------------- #

    @property
    def loop(self) -> asyncio.AbstractEventLoop:
        if self._loop is None:
            raise RuntimeError("LoopRunner is not running")
        return self._loop

    @property
    def running(self) -> bool:
        return self._loop is not None and not self._stopped.is_set()

    def start(self, timeout: float = DEFAULT_START_TIMEOUT_S) -> None:
        """Start the loop thread. Idempotent."""
        with self._lock:
            if self.running:
                return
            self._stopped.clear()
            self._started.clear()
            self._thread = threading.Thread(target=self._run, name=self._name, daemon=True)
            self._thread.start()
        if not self._started.wait(timeout=timeout):
            raise TimeoutError(f"event loop thread {self._name!r} did not start in {timeout}s")

    def stop(self, timeout: float = DEFAULT_SHUTDOWN_TIMEOUT_S) -> None:
        """Stop the loop and join the thread. Safe to call more than once."""
        loop = self._loop
        if loop is None:
            return
        with contextlib.suppress(RuntimeError):
            loop.call_soon_threadsafe(loop.stop)
        thread = self._thread
        if thread is not None:
            thread.join(timeout=timeout)
        self._stopped.set()
        self._loop = None
        self._thread = None

    def _run(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._loop = loop
        self._started.set()
        try:
            loop.run_forever()
        finally:
            try:
                pending = [task for task in asyncio.all_tasks(loop) if not task.done()]
                for task in pending:
                    task.cancel()
                if pending:
                    loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
                loop.run_until_complete(loop.shutdown_asyncgens())
            except Exception:  # noqa: BLE001 - shutdown must never raise
                pass
            finally:
                loop.close()
                self._stopped.set()

    # -- work submission --------------------------------------------------- #

    def submit(self, coro: Awaitable[T], timeout: float | None = None) -> T:
        """Run ``coro`` on the loop thread and block for its result."""
        if not self.running:
            self.start()
        future = asyncio.run_coroutine_threadsafe(_ensure_coro(coro), self.loop)
        try:
            return future.result(timeout=timeout)
        except concurrent.futures.TimeoutError as exc:
            future.cancel()
            raise TimeoutError(f"coroutine did not finish within {timeout}s") from exc

    def run(self, fn: Callable[[], T], timeout: float | None = None) -> T:
        """Run a plain callable *on* the loop thread (for loop-bound objects)."""
        if not self.running:
            self.start()
        return self.submit(_wrap_sync(fn), timeout=timeout)

    def sleep(self, seconds: float) -> None:
        """Sleep without blocking the loop thread."""
        if seconds > 0:
            self.submit(asyncio.sleep(seconds))

    def wait_idle(self, timeout: float = 5.0) -> bool:
        """Best-effort wait until no tasks are pending. Never raises."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                pending = self.submit(_pending_task_count(), timeout=1.0)
            except Exception:  # noqa: BLE001
                return False
            if pending == 0:
                return True
            time.sleep(0.05)
        return False


async def _ensure_coro(awaitable: Awaitable[T]) -> T:
    return await awaitable


async def _wrap_sync(fn: Callable[[], T]) -> T:
    return fn()


async def _pending_task_count() -> int:
    current = asyncio.current_task()
    return len([task for task in asyncio.all_tasks() if task is not current and not task.done()])
