"""The tool contract.

Everything the AI is allowed to do is expressed as a :class:`Tool`. A tool is a
declared capability with a typed contract, not a function the AI can improvise
with. The three parts are deliberately separate:

* :class:`ToolMeta` - the published description (what the AI sees).
* the request model - the validated argument contract (what the AI may ask for).
* the executor - harness code that performs the work (what actually happens).

The AI never appears in the third part. It cannot run a shell, cannot compose an
HTTP request, and cannot invent a payload, because no such parameter exists in any
request model and no executor would accept one.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

from app.models.finding import Finding
from app.models.tools import StrictModel, ToolMeta, ToolResult, ToolStatus


class ToolExecutionError(RuntimeError):
    """A tool body failed in a way the AI should see as a normal error result."""


class ToolUnavailableError(RuntimeError):
    """A tool exists in the registry but its dependency is unavailable."""


@dataclass
class ToolOutcome:
    """What a tool body returns to the dispatcher.

    Tools return *data*, not a :class:`ToolResult`. The dispatcher owns the envelope
    (status, timing, truncation) so that behaviour is uniform across every tool.
    """

    summary: str
    data: StrictModel | dict[str, Any] | None = None
    findings: list[Finding] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    # Names of list-valued data fields whose entries are ordered most-important-first, so a
    # budget truncation keeps the interesting ones rather than the first ones. A tool that
    # cannot order its output itself should not claim this.
    priority_fields: tuple[str, ...] = field(default_factory=tuple)
    # Field names that may be dropped from an item before any item is dropped entirely,
    # used only when the payload cannot fit otherwise. Tools declare the prose fields here
    # so that the *facts* survive even when the explanation does not.
    droppable_fields: tuple[str, ...] = field(default_factory=tuple)

    def data_dict(self) -> dict[str, Any]:
        if self.data is None:
            return {}
        if isinstance(self.data, StrictModel):
            return self.data.model_dump(mode="json", exclude_none=False)
        return dict(self.data)


def ordered(
    *,
    summary: str,
    data: StrictModel | dict[str, Any] | None = None,
    findings: list[Finding] | None = None,
    artifacts: list[str] | None = None,
    notes: list[str] | None = None,
    priority_fields: tuple[str, ...],
) -> ToolOutcome:
    """Return an outcome whose named list fields are already sorted most-important-first.

    Use this when the payload can be large and a truncated tail would otherwise hide the
    entries that matter. The dispatcher keeps a prefix, so putting the important entries
    first is what makes truncation lossy in the right direction.
    """
    return ToolOutcome(
        summary=summary,
        data=data,
        findings=list(findings or []),
        artifacts=list(artifacts or []),
        notes=list(notes or []),
        priority_fields=priority_fields,
    )


class ToolExecutor(Protocol):
    """Signature every tool body implements.

    ``ctx`` carries the scan's controlled resources (scope, HTTP client, browser).
    ``request`` is always an instance of the tool's declared request model, so a
    body can rely on its fields being present and typed.
    """

    def __call__(self, ctx: Any, request: Any) -> ToolOutcome: ...


@dataclass(frozen=True)
class Tool:
    """A registered, executable capability."""

    meta: ToolMeta
    request_model: type[StrictModel]
    executor: Callable[..., ToolOutcome]

    @property
    def name(self) -> str:
        return self.meta.name

    @property
    def category(self) -> str:
        return self.meta.category.value

    def json_schema(self) -> dict[str, Any]:
        """JSON Schema for the request model, as handed to an LLM tool API."""
        schema = self.request_model.model_json_schema()
        # Pydantic emits a `title` for the root object; LLM APIs tolerate it but it
        # adds noise, so drop it and keep the rest verbatim.
        schema.pop("title", None)
        return schema

    def parse_args(self, raw: dict[str, Any]) -> StrictModel:
        """Validate raw AI-supplied arguments into the request model.

        Raises :class:`pydantic.ValidationError` on any mismatch; the dispatcher
        converts that into a ``denied`` result rather than an exception, so the AI
        learns from its own malformed call and can retry.
        """
        return self.request_model.model_validate(raw or {})

    def to_llm_spec(self, *, compact: bool = False) -> dict[str, Any]:
        schema = self.json_schema()
        if compact:
            # Strip verbose field descriptions from schema to fit strict TPM limits (e.g. Groq 8000 TPM)
            schema = dict(schema)
            if "properties" in schema and isinstance(schema["properties"], dict):
                compact_props = {}
                for k, v in schema["properties"].items():
                    prop = dict(v) if isinstance(v, dict) else v
                    if isinstance(prop, dict):
                        desc = str(prop.get("description") or "")
                        # Keep short descriptions that contain valid choices/names
                        if not ("available" in desc.lower() or "one of" in desc.lower() or len(desc) <= 60):
                            prop.pop("description", None)
                        prop.pop("title", None)
                    compact_props[k] = prop
                schema["properties"] = compact_props
            schema.pop("description", None)
            return {
                "type": "function",
                "function": {
                    "name": self.meta.name,
                    "description": f"[{self.meta.category.value}] {self.meta.summary}",
                    "parameters": schema,
                },
            }
        return self.meta.to_llm_spec(schema)

    def to_dict(self) -> dict[str, Any]:
        """Registry listing entry."""
        return {
            "name": self.meta.name,
            "category": self.meta.category.value,
            "summary": self.meta.summary,
            "capabilities": list(self.meta.capabilities),
            "requires_confirmation": self.meta.requires_confirmation,
            "mutates_target": self.meta.mutates_target,
            "produces_findings": self.meta.produces_findings,
            "implemented": self.meta.implemented,
            "tags": list(self.meta.tags),
        }


def ok(
    summary: str,
    data: StrictModel | dict[str, Any] | None = None,
    *,
    findings: list[Finding] | None = None,
    artifacts: list[str] | None = None,
    notes: list[str] | None = None,
    priority_fields: tuple[str, ...] = (),
    droppable_fields: tuple[str, ...] = (),
) -> ToolOutcome:
    """Convenience constructor for a successful tool outcome."""
    return ToolOutcome(
        summary=summary,
        data=data,
        findings=list(findings or []),
        artifacts=list(artifacts or []),
        notes=list(notes or []),
        priority_fields=priority_fields,
        droppable_fields=droppable_fields,
    )


def build_result(
    tool_name: str,
    *,
    status: ToolStatus,
    summary: str,
    data: dict[str, Any] | None = None,
    error: str | None = None,
    denial_reason: str | None = None,
    duration_ms: int = 0,
    truncated: bool = False,
    findings: list[Finding] | None = None,
    artifacts: list[str] | None = None,
) -> ToolResult:
    """Build the uniform result envelope."""
    return ToolResult(
        tool=tool_name,
        status=status,
        summary=summary,
        data=data or {},
        error=error,
        denial_reason=denial_reason,
        duration_ms=max(0, int(duration_ms)),
        truncated=truncated,
        findings=[finding.model_dump(mode="json") for finding in (findings or [])],
        artifacts=list(artifacts or []),
    )


def timed() -> float:
    """Monotonic clock helper, aliased so tools never import ``time`` directly."""
    return time.monotonic()
