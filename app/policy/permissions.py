"""Capabilities, argument guarding and confirmation gates.

Three separate questions, deliberately kept in separate objects:

1. :class:`Capability` / :class:`PermissionSet` - *what kind of thing* may this
   process do at all? Shell execution is never granted, so even a compromised tool
   has no path to it.
2. :class:`ArgumentGuard` - *do the arguments look like an attempt to smuggle in a
   command, a payload, or a raw request?* The AI supplies values; it must never
   supply intent expressed as code.
3. :class:`ConfirmationGate` - *does a human agree?* Required for anything that
   mutates the target.

The layer is intentionally paranoid and slightly denylist-y: the structural
defence is that the AI can only choose a registered tool name and fill in typed
parameters. These checks catch the "obvious escape attempt" class and provide an
explicit, auditable failure instead of a silent one.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from app.models.tools import ToolMeta


class Capability(StrEnum):
    """A kind of privileged action a tool may request."""

    HTTP_EGRESS = "http_egress"
    """Send an HTTP(S) request to an in-scope host."""

    BROWSER = "browser"
    """Drive the shared headless browser instance."""

    DNS_LOOKUP = "dns_lookup"
    """Resolve hostnames."""

    WRITE_ARTIFACT = "write_artifact"
    """Write files under the run's artifact directory."""

    ACTIVE_SCAN = "active_scan"
    """Perform actions that may modify target state. Off by default."""

    INJECTION_PROBE = "injection_probe"
    """Send harness-owned injection payloads into parameters.

    Separate from ``active_scan`` on purpose. An operator may be willing to let the harness
    ask a server which HTTP methods it supports while not being willing to let it put quote
    characters into a query parameter. Those are different appetites and they get different
    switches.
    """

    PRIVATE_NETWORK = "private_network"
    """Reach RFC1918/loopback addresses. Off by default."""


class ForbiddenCapability(StrEnum):
    """Capabilities that are *never* granted in this application.

    These exist as explicit constants so tests can assert their absence and so the
    intent is visible in code review.
    """

    SHELL = "shell"
    """Execute a shell command."""

    RAW_HTTP = "raw_http"
    """Send an arbitrary, unvalidated HTTP request built by the AI."""

    ARBITRARY_PAYLOAD = "arbitrary_payload"
    """Generate and deliver an attacker-chosen payload."""

    FILE_WRITE_UNBOUNDED = "file_write_unbounded"
    """Write outside the artifact directory."""

    SCOPE_MUTATION = "scope_mutation"
    """Widen the scan scope at runtime."""


@dataclass
class PermissionSet:
    """The capabilities granted to tools in this process.

    Defaults reflect the MVP: read-only discovery and passive analysis over HTTP
    and a browser, nothing that executes code or writes outside the run directory.
    """

    granted: set[Capability] = field(
        default_factory=lambda: {
            Capability.HTTP_EGRESS,
            Capability.BROWSER,
            Capability.DNS_LOOKUP,
            Capability.WRITE_ARTIFACT,
        }
    )
    denied: set[ForbiddenCapability] = field(
        default_factory=lambda: set(ForbiddenCapability)
    )

    def allows(self, capability: Capability | str) -> bool:
        try:
            return Capability(capability) in self.granted
        except ValueError:
            return False

    def check(self, required: Iterable[Capability | str]) -> str | None:
        """Return a denial reason, or ``None`` when everything required is granted."""
        missing = [str(cap) for cap in required if not self.allows(cap)]
        if missing:
            return (
                f"capability not granted: {', '.join(missing)}. "
                f"Granted: {', '.join(sorted(c.value for c in self.granted)) or '(none)'}"
            )
        return None

    def grant(self, capability: Capability) -> None:
        """Explicitly grant an extra capability (e.g. private network, active scan)."""
        self.granted.add(capability)

    def revoke(self, capability: Capability) -> None:
        self.granted.discard(capability)

    def assert_forbidden_absent(self) -> None:
        """Sanity check: the never-granted set must not overlap the granted set."""
        overlap = {cap.value for cap in self.granted} & {cap.value for cap in self.denied}
        if overlap:
            raise AssertionError(f"forbidden capabilities were granted: {sorted(overlap)}")

    def describe(self) -> dict[str, list[str]]:
        return {
            "granted": sorted(cap.value for cap in self.granted),
            "never_granted": sorted(cap.value for cap in self.denied),
        }


# --------------------------------------------------------------------------- #
# Argument guarding
# --------------------------------------------------------------------------- #

# Keys the AI must never be able to set. Tool schemas already forbid unknown
# fields, so hitting one of these means something bypassed validation; treat it as
# an escape attempt rather than a mistake.
_FORBIDDEN_KEYS: frozenset[str] = frozenset(
    {
        "command",
        "cmd",
        "commands",
        "shell",
        "script",
        "exec",
        "execute",
        "eval",
        "system",
        "popen",
        "subprocess",
        "os_command",
        "terminal",
        "payload",
        "raw_payload",
        "exploit",
        "raw_request",
        "raw_response",
        "http_raw",
        "request_line",
        "headers_raw",
        "code",
        "python",
        "bash",
        "powershell",
        "file_path",
        "write_file",
        "path",
        "output_path",
        "target_hosts",
        "allowed_hosts",
        "scope",
        "new_scope",
        "capabilities",
        "permissions",
    }
)

# Value-level patterns. These are *tripwires for an obviously hostile value*, not a
# general-purpose payload detector. A carefully crafted injection string can pass
# them; the real protection is that no MVP tool forwards a value into a query,
# template or command. See docs/SECURITY-MODEL.md for the honest boundaries.
_VALUE_TRIPWIRES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]"), "control characters in value"),
    (re.compile(r"(?i)\$\{|\{\{|\{%|#\{"), "template-expression syntax in value"),
    (re.compile(r"<script", re.IGNORECASE), "inline script tag in value"),
    (re.compile(r"(?i)javascript:\s*[^\s]"), "javascript: URI in value"),
    (re.compile(r"\.\.[/\\]"), "path traversal sequence in value"),
    (re.compile(r"(?i)\bunion\s+(all\s+)?select\b"), "SQL UNION SELECT syntax in value"),
    (re.compile(r"(?i)\bor\s+1\s*=\s*1\b"), "SQL tautology in value"),
    (re.compile(r"(?i)\b(?:nc|netcat|curl|wget|bash|sh|cmd|powershell)\s+-"), "shell command in value"),
    (re.compile(r"\|\s*(?:sh|bash|nc)\b"), "shell pipe in value"),
    (re.compile(r"(?i)\b(?:exec|eval|system)\s*\("), "code-execution call in value"),
)


@dataclass(frozen=True)
class ArgumentVerdict:
    """Result of screening a tool's arguments."""

    allowed: bool
    reason: str = ""
    offending_key: str = ""

    def __bool__(self) -> bool:
        return self.allowed


class ArgumentGuard:
    """Screens tool arguments before the tool body runs."""

    def __init__(
        self,
        forbidden_keys: frozenset[str] = _FORBIDDEN_KEYS,
        triples: tuple[tuple[re.Pattern[str], str], ...] = _VALUE_TRIPWIRES,
        max_value_length: int = 4096,
        max_nesting: int = 4,
    ) -> None:
        self.forbidden_keys = forbidden_keys
        self.tripwires = triples
        self.max_value_length = max_value_length
        self.max_nesting = max_nesting

    def screen(self, args: Mapping[str, Any]) -> ArgumentVerdict:
        """Recursively screen arguments. Returns the first violation found."""
        return self._walk(args, depth=0, path="args")

    def _walk(self, value: Any, *, depth: int, path: str) -> ArgumentVerdict:
        if depth > self.max_nesting:
            return ArgumentVerdict(False, f"arguments nested deeper than {self.max_nesting}", path)

        if isinstance(value, Mapping):
            for key, item in value.items():
                key_str = str(key)
                normalized = key_str.strip().lower()
                if normalized in self.forbidden_keys:
                    return ArgumentVerdict(
                        False,
                        f"argument key {key_str!r} is reserved and may never be supplied by the AI",
                        key_str,
                    )
                verdict = self._walk(item, depth=depth + 1, path=f"{path}.{key_str}")
                if not verdict.allowed:
                    return verdict
            return ArgumentVerdict(True)

        if isinstance(value, (list, tuple)):
            if len(value) > 64:
                return ArgumentVerdict(False, f"argument list {path} has too many items", path)
            for index, item in enumerate(value):
                verdict = self._walk(item, depth=depth + 1, path=f"{path}[{index}]")
                if not verdict.allowed:
                    return verdict
            return ArgumentVerdict(True)

        if isinstance(value, str):
            if len(value) > self.max_value_length:
                return ArgumentVerdict(
                    False,
                    f"argument {path} is longer than {self.max_value_length} characters",
                    path,
                )
            for pattern, reason in self.tripwires:
                if pattern.search(value):
                    return ArgumentVerdict(False, f"{reason} in {path}", path)
            return ArgumentVerdict(True)

        if value is None or isinstance(value, (bool, int, float)):
            return ArgumentVerdict(True)

        return ArgumentVerdict(False, f"argument {path} has unsupported type {type(value).__name__}", path)


# --------------------------------------------------------------------------- #
# Confirmation
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ConfirmationRequest:
    """What the human is being asked to approve."""

    tool: ToolMeta
    args: Mapping[str, Any]
    reason: str = ""
    preview: str = ""

    def render(self) -> str:
        lines = [
            "Confirmation required",
            f"  tool      : {self.tool.name} [{self.tool.category.value}]",
            f"  mutates   : {'yes' if self.tool.mutates_target else 'no'}",
        ]
        if self.reason:
            lines.append(f"  reason    : {self.reason}")
        if self.args:
            rendered = ", ".join(f"{k}={v!r}" for k, v in list(self.args.items())[:8])
            lines.append(f"  arguments : {rendered}")
        if self.preview:
            lines.append(f"  preview   : {self.preview}")
        return "\n".join(lines)


Confirmer = Callable[[ConfirmationRequest], bool]


class ConfirmationGate:
    """Decides whether a human has approved a confirming tool call."""

    def __init__(
        self,
        confirmer: Confirmer | None = None,
        *,
        interactive: bool = True,
        auto_approve: bool = False,
    ) -> None:
        self._confirmer = confirmer
        self.interactive = interactive
        self.auto_approve = auto_approve
        self._audit: list[dict[str, Any]] = []

    @property
    def audit(self) -> list[dict[str, Any]]:
        """Every decision made, for the report."""
        return list(self._audit)

    def request(self, request: ConfirmationRequest) -> tuple[bool, str]:
        """Return ``(approved, reason)``."""
        if self.auto_approve:
            self._record(request, True, "auto-approved")
            return True, "auto-approved"
        if self._confirmer is not None:
            approved = bool(self._confirmer(request))
            self._record(request, approved, "custom confirmer" if approved else "declined by confirmer")
            return approved, ("approved" if approved else "declined by the confirmation callback")
        if not self.interactive:
            self._record(request, False, "non-interactive")
            return False, (
                "confirmation required but the session is non-interactive; "
                "re-run with --yes or approve interactively"
            )
        approved = self._prompt(request)
        self._record(request, approved, "interactive" if approved else "declined interactively")
        return approved, ("approved interactively" if approved else "declined by the operator")

    @staticmethod
    def _prompt(request: ConfirmationRequest) -> bool:
        print()
        print(request.render())
        try:
            answer = input("Approve this action? [y/N] ").strip().lower()
        except EOFError:
            return False
        return answer in {"y", "yes"}

    def _record(self, request: ConfirmationRequest, approved: bool, how: str) -> None:
        self._audit.append(
            {
                "tool": request.tool.name,
                "approved": approved,
                "how": how,
                "arguments": dict(request.args),
            }
        )


# --------------------------------------------------------------------------- #
# Request policy: the combined preflight used by the dispatcher
# --------------------------------------------------------------------------- #


@dataclass
class PreflightOutcome:
    """Combined result of permissions + argument screening."""

    allowed: bool
    reason: str = ""
    stage: str = ""


class RequestPolicy:
    """Combines permissions and argument screening into one preflight call."""

    def __init__(
        self,
        permissions: PermissionSet | None = None,
        argument_guard: ArgumentGuard | None = None,
    ) -> None:
        self.permissions = permissions or PermissionSet()
        self.permissions.assert_forbidden_absent()
        self.argument_guard = argument_guard or ArgumentGuard()

    def preflight(self, tool: ToolMeta, args: Mapping[str, Any]) -> PreflightOutcome:
        capability_reason = self.permissions.check(tool.capabilities)
        if capability_reason:
            return PreflightOutcome(False, capability_reason, stage="permissions")

        verdict = self.argument_guard.screen(args)
        if not verdict.allowed:
            return PreflightOutcome(False, verdict.reason, stage="arguments")

        return PreflightOutcome(True)
