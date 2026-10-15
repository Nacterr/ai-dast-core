"""Resource limits and rate limiting.

Limits are enforced *before* the work happens (reserve-then-execute), not measured
afterwards, so a runaway planner cannot exceed a budget even briefly. Every budget
lives in :class:`~app.models.scan.ScanConfig`; this module is the enforcement
mechanism and holds no policy of its own.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

from app.models.scan import ScanConfig


class LimitExceeded(RuntimeError):
    """Raised when a reserved budget is already exhausted.

    Carries a machine-readable ``kind`` so the tool dispatcher can turn it into a
    clean ``denied`` result instead of a crash.
    """

    def __init__(self, kind: str, message: str) -> None:
        super().__init__(message)
        self.kind = kind
        self.message = message


@dataclass
class Budget:
    """A named integer budget with a hard ceiling."""

    name: str
    limit: int
    used: int = 0

    @property
    def remaining(self) -> int:
        return max(0, self.limit - self.used)

    @property
    def exhausted(self) -> bool:
        return self.used >= self.limit

    def reserve(self, amount: int = 1) -> None:
        """Consume ``amount`` from the budget, or raise :class:`LimitExceeded`."""
        if amount < 0:
            raise ValueError("cannot reserve a negative amount")
        if self.used + amount > self.limit:
            raise LimitExceeded(
                self.name,
                f"{self.name} budget exhausted ({self.used}/{self.limit} used, "
                f"{amount} requested)",
            )
        self.used += amount

    def release(self, amount: int = 1) -> None:
        """Give budget back, e.g. when a call never reached the network."""
        self.used = max(0, self.used - amount)


@dataclass
class RateLimiter:
    """Thread-safe token-bucket limiter applied to outbound requests.

    A bucket (rather than a fixed sleep) allows a short burst and then settles to
    the configured steady rate, which keeps scans fast without hammering a target.
    """

    rate_per_second: float
    burst: int = 4
    _tokens: float = field(init=False)
    _last: float = field(init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)
    _total_wait_s: float = field(default=0.0, init=False)

    def __post_init__(self) -> None:
        if self.rate_per_second <= 0:
            raise ValueError("rate_per_second must be positive")
        self._tokens = float(max(1, self.burst))
        self._last = time.monotonic()

    @property
    def total_wait_s(self) -> float:
        return self._total_wait_s

    def acquire(self) -> float:
        """Block until a token is available. Returns the seconds waited.

        Raises :class:`LimitExceeded` if the required wait exceeds the caller's
        tolerance, so a scan can never stall indefinitely on rate limiting.
        """
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            self._last = now
            self._tokens = min(float(self.burst), self._tokens + elapsed * self.rate_per_second)

            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return 0.0

            needed = 1.0 - self._tokens
            wait_s = needed / self.rate_per_second
            # Cap a single wait so a misconfigured rate cannot hang the scan.
            if wait_s > 30.0:
                raise LimitExceeded(
                    "rate_limit",
                    f"rate limiter would need to wait {wait_s:.1f}s for a request token",
                )
            self._total_wait_s += wait_s
            # Spend the tokens we are about to earn by waiting, so concurrent
            # callers queue behind this one instead of all sleeping at once.
            self._tokens = 0.0
            self._last = now

        time.sleep(wait_s)
        return wait_s


class LimitTracker:
    """Holds every budget for one scan and the mechanism to enforce them."""

    def __init__(self, config: ScanConfig, *, clock=time.monotonic) -> None:
        self.config = config
        self._clock = clock
        self.started_at = clock()
        self._lock = threading.Lock()
        self.budgets: dict[str, Budget] = {
            "steps": Budget("steps", config.max_steps),
            "tool_calls": Budget("tool_calls", config.max_tool_calls),
            "pages": Budget("pages", config.max_pages),
            "requests": Budget("requests", config.max_requests),
            "exposed_file_checks": Budget(
                "exposed_file_checks", config.max_exposed_file_checks
            ),
        }
        self.rate_limiter = RateLimiter(config.requests_per_second)

    # -- budgets ----------------------------------------------------------- #

    def reserve(self, kind: str, amount: int = 1) -> None:
        budget = self.budgets.get(kind)
        if budget is None:
            raise KeyError(f"unknown budget: {kind}")
        with self._lock:
            budget.reserve(amount)

    def release(self, kind: str, amount: int = 1) -> None:
        budget = self.budgets.get(kind)
        if budget is not None:
            with self._lock:
                budget.release(amount)

    def check_scan_deadline(self) -> None:
        """Raise when the whole-scan wall-clock budget is gone."""
        elapsed = self._clock() - self.started_at
        if elapsed > self.config.scan_timeout_s:
            raise LimitExceeded(
                "scan_timeout",
                f"scan exceeded its {self.config.scan_timeout_s:.0f}s wall-clock budget "
                f"({elapsed:.0f}s elapsed)",
            )

    @property
    def elapsed_s(self) -> float:
        return self._clock() - self.started_at

    # -- request path ------------------------------------------------------ #

    def before_request(self) -> None:
        """Reserve one HTTP request and apply rate limiting.

        This is the single choke point for outbound traffic: tools call it before
        every request, including redirect hops.
        """
        self.check_scan_deadline()
        self.reserve("requests")
        self.rate_limiter.acquire()

    # -- snapshot ---------------------------------------------------------- #

    def snapshot(self) -> dict[str, int]:
        """Counters for the report."""
        snap = {name: budget.used for name, budget in self.budgets.items()}
        snap["step_limit"] = self.config.max_steps
        snap["tool_call_limit"] = self.config.max_tool_calls
        snap["page_limit"] = self.config.max_pages
        snap["request_limit"] = self.config.max_requests
        return snap

    def describe_remaining(self) -> str:
        """Compact text for the planner, so it can budget its own steps."""
        parts = [
            f"{name}: {budget.remaining}/{budget.limit} left"
            for name, budget in self.budgets.items()
            if name in {"steps", "tool_calls", "pages", "requests"}
        ]
        parts.append(f"scan time: {max(0.0, self.config.scan_timeout_s - self.elapsed_s):.0f}s left")
        return "; ".join(parts)
