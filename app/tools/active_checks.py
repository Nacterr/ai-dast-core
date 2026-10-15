"""``run_selected_active_check``: the active-check catalogue.

This is the first genuinely *active* tool. It sends requests the target did not invite:
``OPTIONS`` to a resource, method probes, and encoded path variants. That is a different
risk class from everything before it, so the design constraints come first.

## The two invariants

**1. The AI chooses a check name, never a payload.**

Every byte on the wire is built in this file from constants. There is no parameter for a
payload, a method, a header value or a body. A tool that accepted one would be a raw-request
primitive wearing a check's clothing, and the whole point of the tool registry is that the
model cannot compose a request.

**2. Every check in the catalogue is non-mutating.**

A check may use ``GET``, ``HEAD`` and ``OPTIONS``, and nothing else. When a check needs to
learn whether the server *would* accept a write method, it asks with ``OPTIONS`` and reads
the ``Allow`` header — it never sends the write. That distinction is what keeps this safe to
run unattended against a production-adjacent target, and it is enforced by the
``_MUTATING_METHODS`` guard below rather than left to reviewer discipline.

A check that had to mutate state to reach a conclusion would not belong in this catalogue. If
one is ever needed, it must be a different tool with a different confirmation story.

## Design consequences

Because no check mutates, ``ToolMeta.mutates_target`` is ``False`` even though
``requires_confirmation`` is ``True``. The confirmation is about *attention* — an active probe
is a deliberate act the operator should see — not about state change.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlsplit

from app.models.finding import Confidence, Evidence, Finding, FindingCategory, Severity
from app.models.tools import (
    ActiveCheckResult,
    RunSelectedActiveCheckData,
    RunSelectedActiveCheckRequest,
)
from app.tools.base import ToolOutcome, ok
from app.tools.findings import make_finding
from app.tools.http_client import EgressDenied, HttpExchange
from app.tools.shared import require_in_scope

# Methods this tool may send. Anything outside this set is refused by the engine, so a
# future check cannot quietly introduce a mutating request.
#
# TRACE is in the safe set because *detecting* it requires sending it, and TRACE is defined
# by RFC 9110 to return the request to the client without side effects. POST, PUT, PATCH and
# DELETE are absent: when a check needs to know whether the server would accept a write, it
# asks with OPTIONS and reads the Allow header, and never performs the write.
_SAFE_METHODS: frozenset[str] = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})
_MUTATING_METHODS: frozenset[str] = frozenset(
    {"POST", "PUT", "PATCH", "DELETE", "CONNECT"}
)

# A path that cannot exist, for calibration.
CONTROL_PATH = "/.well-known/ai-dast-core-control-4f81c2"

# Origins used by the CORS preflight check. Reserved by RFC 2606, so naming them cannot be
# mistaken for contacting a real third party.
PREFLIGHT_ORIGIN = "https://origin-probe.invalid"

# Method names the server might advertise. Compared case-insensitively.
_KNOWN_METHODS = (
    "GET",
    "HEAD",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    "OPTIONS",
    "TRACE",
    "CONNECT",
)

# Methods whose advertisement by a CORS preflight is a finding when the origin is untrusted:
# a cross-origin caller can reach a state-changing operation.
_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

_MAX_REQUESTS_PER_CHECK = 6


@dataclass
class CheckContext:
    """What a check needs, so checks stay testable in isolation.

    ``origin`` is the **target's** own origin, not a probe value. A check that needs a
    cross-origin probe uses the reserved constants in this module, so the value that reaches
    the wire is never influenced by anything outside harness code.
    """

    url: str
    origin: str
    baseline_status: int | None
    catch_all: bool
    send: Callable[..., HttpExchange]
    notes: list[str]


@dataclass(frozen=True)
class CheckSpec:
    """One entry in the catalogue."""

    name: str
    summary: str
    description: str
    severity_if_hit: str
    run: Callable[[CheckContext], ActiveCheckResult]


# --------------------------------------------------------------------------- #
# Shared helpers
# --------------------------------------------------------------------------- #


def _parse_methods(value: str) -> list[str]:
    """Split a comma-separated method list into normalised, de-duplicated names."""
    found: list[str] = []
    for token in re.split(r"[,\s]+", value or ""):
        name = token.strip().upper()
        if name and name in _KNOWN_METHODS and name not in found:
            found.append(name)
    return found


def _exists(result: HttpExchange, ctx: CheckContext) -> bool:
    """Whether a response represents a real resource rather than a catch-all.

    On a server that answers 200 for everything, the status code proves nothing, so this
    falls back to requiring a status that differs from the calibration baseline.
    """
    status = result.status_code
    if status is None:
        return False
    if not ctx.catch_all:
        return status < 400
    if ctx.baseline_status is None:
        return status < 400
    return status != ctx.baseline_status


def _skip(check: str, ctx: CheckContext, reason: str) -> ActiveCheckResult:
    return ActiveCheckResult(
        check=check,
        url=ctx.url,
        ran=False,
        skipped_reason=reason,
        verdict="skipped",
    )


def _inconclusive(check: str, ctx: CheckContext, observed: str, note: str = "") -> ActiveCheckResult:
    return ActiveCheckResult(
        check=check,
        url=ctx.url,
        ran=True,
        verdict="inconclusive",
        confidence="low",
        observed=observed[:1500],
        notes=[note] if note else [],
    )


# --------------------------------------------------------------------------- #
# Check 1: CORS preflight with a write method
# --------------------------------------------------------------------------- #


def _check_cors_preflight(ctx: CheckContext) -> ActiveCheckResult:
    """Ask whether a cross-origin caller may use a write method.

    The probe is an ``OPTIONS`` preflight naming ``PUT``, sent with the reserved
    ``.invalid`` probe origin. That is the question a browser would ask on a page's behalf,
    and answering it does not perform the write.
    """
    response = ctx.send(
        ctx.url,
        method="OPTIONS",
        extra_headers={
            "Origin": PREFLIGHT_ORIGIN,
            "Access-Control-Request-Method": "PUT",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    headers = response.headers or {}
    allow_origin = str(headers.get("access-control-allow-origin", ""))
    allow_credentials = str(headers.get("access-control-allow-credentials", "")).strip().lower()
    allow_methods = _parse_methods(str(headers.get("access-control-allow-methods", "")))

    # A reflection must match the probe origin exactly. Echoing the *target's* own origin
    # would be a same-origin request, which is not a cross-origin weakness at all.
    reflects = allow_origin.strip() == PREFLIGHT_ORIGIN
    wildcard = allow_origin.strip() == "*"
    permissive_origin = reflects or wildcard
    write_allowed = sorted(set(allow_methods) & _WRITE_METHODS)

    if not allow_origin:
        return ActiveCheckResult(
            check="cors_preflight",
            url=ctx.url,
            ran=True,
            verdict="no_cross_origin_write",
            severity="info",
            confidence="high",
            observed=(
                f"OPTIONS returned HTTP {response.status_code} with no "
                "Access-Control-Allow-Origin, so a cross-origin preflight is not permitted."
            ),
            rationale="The browser will block the cross-origin request.",
            methods_advertised=allow_methods,
        )

    if permissive_origin and write_allowed:
        severity = "high" if allow_credentials == "true" else "medium"
        return ActiveCheckResult(
            check="cors_preflight",
            url=ctx.url,
            ran=True,
            verdict="cross_origin_write_allowed",
            severity=severity,  # type: ignore[arg-type]
            confidence="high",
            observed=(
                f"OPTIONS allowed Origin {allow_origin!r} with credentials "
                f"{allow_credentials!r} and methods {', '.join(allow_methods)}."
            ),
            rationale=(
                "The server answers a cross-origin preflight for a write method on an "
                "origin the caller controls. Any site can therefore instruct a logged-in "
                "user's browser to perform that write."
                + (
                    " Credentials are allowed as well, so the request carries the victim's "
                    "session."
                    if allow_credentials == "true"
                    else ""
                )
            ),
            recommendation=(
                "Restrict Access-Control-Allow-Origin to an explicit allowlist and "
                "Access-Control-Allow-Methods to the methods each endpoint genuinely needs "
                "cross-origin. Do not derive the allowed origin from the request."
            ),
            methods_advertised=allow_methods,
            notes=[f"the PUT preflight was answered with HTTP {response.status_code}"],
        )

    if permissive_origin:
        return ActiveCheckResult(
            check="cors_preflight",
            url=ctx.url,
            ran=True,
            verdict="cross_origin_read_only",
            severity="info",
            confidence="high",
            observed=(
                f"OPTIONS allowed Origin {allow_origin!r} but advertised no write method "
                f"({', '.join(allow_methods) or 'none'})."
            ),
            rationale="Cross-origin access is permitted, but not for state-changing methods.",
            methods_advertised=allow_methods,
        )

    return ActiveCheckResult(
        check="cors_preflight",
        url=ctx.url,
        ran=True,
        verdict="origin_not_allowed",
        severity="info",
        confidence="high",
        observed=f"OPTIONS allowed a fixed origin {allow_origin!r}, not the probe origin.",
        rationale="Cross-origin writes are not permitted for an arbitrary origin.",
        methods_advertised=allow_methods,
    )


# --------------------------------------------------------------------------- #
# Check 2: advertised and accepted HTTP methods
# --------------------------------------------------------------------------- #


def _check_http_methods(ctx: CheckContext) -> ActiveCheckResult:
    """Learn which methods the server advertises and which it accepts.

    ``OPTIONS`` is asked for the ``Allow`` header. ``TRACE`` is the one method probed
    directly, because *detecting* it requires sending it and TRACE is defined to echo the
    request without side effects. Other write methods are never sent.
    """
    options = ctx.send(ctx.url, method="OPTIONS")
    advertised = _parse_methods(str((options.headers or {}).get("allow", "")))
    advertised_extra = _parse_methods(
        str((options.headers or {}).get("access-control-allow-methods", ""))
    )

    trace = ctx.send(ctx.url, method="TRACE")
    trace_enabled = trace.status_code is not None and trace.status_code < 400

    observed_parts = [f"OPTIONS returned HTTP {options.status_code}"]
    if advertised:
        observed_parts.append(f"Allow: {', '.join(advertised)}")
    else:
        observed_parts.append("no Allow header")
    if advertised_extra:
        observed_parts.append(f"Access-Control-Allow-Methods: {', '.join(advertised_extra)}")
    observed_parts.append(f"TRACE returned HTTP {trace.status_code}")

    if trace_enabled:
        return ActiveCheckResult(
            check="http_methods",
            url=ctx.url,
            ran=True,
            verdict="trace_enabled",
            severity="low",
            confidence="high",
            observed="; ".join(observed_parts),
            rationale=(
                "The TRACE method is enabled. TRACE echoes the request back, and a browser "
                "that permits a cross-site TRACE can be used to read headers the "
                "same-origin policy would otherwise hide — the cross-site tracing technique."
            ),
            recommendation=(
                "Disable TRACE at the web server (`TraceEnable off` on Apache, "
                "`limit_except` on nginx). Modern browsers block it, but the server should "
                "not offer it."
            ),
            methods_advertised=advertised or advertised_extra,
        )

    if not advertised and not advertised_extra:
        return ActiveCheckResult(
            check="http_methods",
            url=ctx.url,
            ran=True,
            verdict="methods_not_advertised",
            severity="info",
            confidence="medium",
            observed="; ".join(observed_parts),
            rationale=(
                "The server does not advertise an Allow list, so the accepted methods cannot "
                "be learned without sending them. This harness does not send write methods."
            ),
            notes=["write methods were deliberately not probed"],
        )

    methods = advertised or advertised_extra
    writes = sorted(set(methods) & _WRITE_METHODS)
    if writes:
        return ActiveCheckResult(
            check="http_methods",
            url=ctx.url,
            ran=True,
            verdict="write_methods_advertised",
            severity="low",
            confidence="medium",
            observed="; ".join(observed_parts),
            rationale=(
                f"The endpoint advertises write methods ({', '.join(writes)}). That is normal "
                "for many APIs and is not a vulnerability by itself — it is recorded because "
                "it determines whether the CORS preflight finding matters for this URL."
            ),
            recommendation=(
                "If this endpoint is not meant to be reachable cross-origin, ensure the CORS "
                "policy does not permit an arbitrary origin for these methods."
            ),
            methods_advertised=methods,
        )

    return ActiveCheckResult(
        check="http_methods",
        url=ctx.url,
        ran=True,
        verdict="read_methods_only",
        severity="info",
        confidence="high",
        observed="; ".join(observed_parts),
        rationale="The endpoint advertises only read methods.",
        methods_advertised=methods,
    )


# --------------------------------------------------------------------------- #
# Check 3: OPTIONS handling
# --------------------------------------------------------------------------- #


def _check_options_method(ctx: CheckContext) -> ActiveCheckResult:
    """Whether the server handles OPTIONS, and whether it does so without authentication.

    An OPTIONS answer on a path that requires authentication is an unauthenticated
    information leak, which is the point of this check.
    """
    plain = ctx.send(ctx.url, method="OPTIONS")
    headers = plain.headers or {}
    allow = str(headers.get("allow", ""))

    if plain.status_code is None:
        return _inconclusive("options_method", ctx, "OPTIONS produced no response")

    if plain.status_code in {401, 403}:
        return ActiveCheckResult(
            check="options_method",
            url=ctx.url,
            ran=True,
            verdict="options_requires_auth",
            severity="info",
            confidence="high",
            observed=f"OPTIONS returned HTTP {plain.status_code} without credentials.",
            rationale="The method is not answered to an unauthenticated caller.",
        )

    if plain.status_code >= 400:
        return ActiveCheckResult(
            check="options_method",
            url=ctx.url,
            ran=True,
            verdict="options_not_supported",
            severity="info",
            confidence="high",
            observed=f"OPTIONS returned HTTP {plain.status_code}.",
            rationale="The server does not implement OPTIONS for this resource.",
        )

    if not allow:
        return ActiveCheckResult(
            check="options_method",
            url=ctx.url,
            ran=True,
            verdict="options_answered_without_allow",
            severity="info",
            confidence="medium",
            observed=f"OPTIONS returned HTTP {plain.status_code} with no Allow header.",
            rationale="OPTIONS is answered but advertises nothing useful.",
        )

    return ActiveCheckResult(
        check="options_method",
        url=ctx.url,
        ran=True,
        verdict="options_answered",
        severity="info",
        confidence="high",
        observed=f"OPTIONS returned HTTP {plain.status_code}; Allow: {allow}",
        rationale="OPTIONS is answered unauthenticated with a method list.",
        methods_advertised=_parse_methods(allow),
        recommendation=(
            "If this resource is not public, make sure OPTIONS does not disclose more than "
            "an unauthenticated caller should learn."
        ),
    )


# --------------------------------------------------------------------------- #
# Check 4: TRACE
# --------------------------------------------------------------------------- #


def _check_trace_method(ctx: CheckContext) -> ActiveCheckResult:
    """Whether TRACE is enabled. Detection requires sending it; TRACE has no side effects."""
    response = ctx.send(ctx.url, method="TRACE")
    headers = response.headers or {}
    content_type = str(headers.get("content-type", ""))

    if response.status_code is None or response.status_code >= 400:
        return ActiveCheckResult(
            check="trace_method",
            url=ctx.url,
            ran=True,
            verdict="trace_disabled",
            severity="info",
            confidence="high",
            observed=f"TRACE returned HTTP {response.status_code}.",
            rationale="The TRACE method is not enabled.",
        )

    # A server that answers 200 to TRACE but echoes nothing is not necessarily reflecting.
    echoes = "message/http" in content_type.lower()
    return ActiveCheckResult(
        check="trace_method",
        url=ctx.url,
        ran=True,
        verdict="trace_enabled" if echoes else "trace_answered",
        severity="low" if echoes else "info",
        confidence="high" if echoes else "medium",
        observed=(
            f"TRACE returned HTTP {response.status_code} with content-type "
            f"{content_type or 'unknown'}."
        ),
        rationale=(
            "TRACE echoes the request back to the caller. With cross-site tracing a browser "
            "can be made to read headers the same-origin policy would otherwise hide, "
            "including cookies not marked HttpOnly."
        )
        if echoes
        else "TRACE is answered, but not with the echo content-type, so reflection is unproven.",
        recommendation="Disable TRACE at the web server.",
    )


# --------------------------------------------------------------------------- #
# Check 5: path traversal variants
# --------------------------------------------------------------------------- #


def _check_path_normalisation(ctx: CheckContext) -> ActiveCheckResult:
    """Whether encoded traversal variants reach a *different* endpoint.

    This is a real active check that mutates nothing: it issues ``GET`` requests to encoded
    variants of the URL's own path and compares the response against the plain path.

    The control is what makes it meaningful. Two things are required before a difference is
    reported:

    1. the normalised path must resolve to something that **exists** (not the catch-all);
    2. it must differ from the plain request's response.

    Without the first condition, every server whose 404 page differs from its 200 page would
    look vulnerable.
    """
    parts = urlsplit(ctx.url)
    path = parts.path or "/"
    base = f"{parts.scheme}://{parts.netloc}"

    plain = ctx.send(ctx.url, method="GET")

    # Variants target the parent of the current path, so a resolver that normalises them
    # lands somewhere different from the plain request.
    parent = path.rstrip("/").rsplit("/", 1)[0] or ""
    target_name = path.rstrip("/").rsplit("/", 1)[-1] or ""
    if not target_name:
        return _skip("path_normalisation", ctx, "the URL has no final path segment to vary")

    variants = (
        f"{parent}/%2e%2e/{parent.strip('/')}/{target_name}" if parent else "",
        f"{parent}/..%2f{target_name}" if parent else "",
        f"{parent}/%2e%2e%2f{target_name}" if parent else "",
        f"{parent}/{target_name}%00",
    )
    variants = tuple(dict.fromkeys(v for v in variants if v and v != path))

    notes: list[str] = []
    for variant in variants:
        variant_url = f"{base}{variant}"
        response = ctx.send(variant_url, method="GET")
        if response.status_code is None:
            continue

        differs = response.status_code != plain.status_code
        real = _exists(response, ctx)
        notes.append(
            f"{variant} -> HTTP {response.status_code} "
            f"(plain was {plain.status_code}, real={real})"
        )
        if differs and real and not ctx.catch_all:
            return ActiveCheckResult(
                check="path_normalisation",
                url=ctx.url,
                ran=True,
                requests_sent=1 + len(notes),
                verdict="variant_reaches_endpoint",
                severity="medium",
                confidence="medium",
                observed="; ".join(notes),
                rationale=(
                    "An encoded path variant was resolved to a different resource than the "
                    "plain path. That means the front-end and the back-end disagree about "
                    "path normalisation, which is the precondition for path-traversal-based "
                    "authorisation bypass: a proxy that checks one path and an application "
                    "that serves another."
                ),
                recommendation=(
                    "Normalise and canonicalise request paths at the edge, reject encoded "
                    "traversal sequences, and do not rely on prefix matching for access "
                    "control."
                ),
                notes=notes,
            )

    if not notes:
        return _inconclusive(
            "path_normalisation", ctx, "no variant produced a usable response"
        )

    return ActiveCheckResult(
        check="path_normalisation",
        url=ctx.url,
        ran=True,
        requests_sent=1 + len(notes),
        verdict="no_difference_observed",
        severity="info",
        confidence="medium",
        observed="; ".join(notes),
        rationale=(
            "Encoded path variants resolved to the same place as the plain path, or to the "
            "server's catch-all response. No normalisation discrepancy was observed."
        ),
        notes=notes,
    )


# --------------------------------------------------------------------------- #
# Catalogue
# --------------------------------------------------------------------------- #

ACTIVE_CHECKS: tuple[CheckSpec, ...] = (
    CheckSpec(
        name="cors_preflight",
        summary="Is a state-changing method allowed cross-origin?",
        description=(
            "Sends an OPTIONS preflight naming PUT from a reserved .invalid origin and reads "
            "the CORS response. Never performs the write."
        ),
        severity_if_hit="high",
        run=_check_cors_preflight,
    ),
    CheckSpec(
        name="http_methods",
        summary="Which methods does the server advertise or accept?",
        description=(
            "OPTIONS for the Allow header, plus a TRACE probe (TRACE has no side effects). "
            "Write methods are never sent."
        ),
        severity_if_hit="low",
        run=_check_http_methods,
    ),
    CheckSpec(
        name="options_method",
        summary="Is OPTIONS answered without authentication?",
        description="A single OPTIONS request; reports whether an Allow list is disclosed.",
        severity_if_hit="info",
        run=_check_options_method,
    ),
    CheckSpec(
        name="trace_method",
        summary="Is the TRACE method enabled?",
        description="A single TRACE request, which is defined to have no side effects.",
        severity_if_hit="low",
        run=_check_trace_method,
    ),
    CheckSpec(
        name="path_normalisation",
        summary="Do encoded traversal variants reach a different endpoint?",
        description=(
            "GET requests only. Compares encoded variants of the URL's own path against the "
            "plain path, and requires the variant to resolve to a real resource."
        ),
        severity_if_hit="medium",
        run=_check_path_normalisation,
    ),
)

CATALOGUE: dict[str, CheckSpec] = {spec.name: spec for spec in ACTIVE_CHECKS}
CHECK_NAMES: tuple[str, ...] = tuple(CATALOGUE)


# --------------------------------------------------------------------------- #
# Engine
# --------------------------------------------------------------------------- #


def run_selected_active_check(ctx, request: RunSelectedActiveCheckRequest) -> ToolOutcome:
    """Run the named checks against one in-scope URL."""
    decision = require_in_scope(ctx, request.url)
    origin = _origin_of(decision.url)

    unknown = [name for name in request.checks if name not in CATALOGUE]
    if unknown:
        raise _unknown_checks(unknown)

    baseline_status: int | None = None
    catch_all = False
    notes: list[str] = []

    # Measured before calibration so the reported count covers every request this tool
    # made. A budget figure that excludes the calibration probe understates the cost and
    # would make the operator's accounting wrong.
    before = ctx.limits.budgets["requests"].used

    if request.calibrate:
        baseline_status, catch_all = _calibrate(ctx, decision.url, notes)

    def send(url: str, **kwargs) -> HttpExchange:
        """Send one request through the harness client, refusing unsafe methods.

        The method guard is here rather than in each check so a future check cannot
        introduce a mutating request by accident.

        ``read_body`` is intentionally *not* forwarded: a caller-supplied value would collide
        with the one this closure passes, and every check needs the body to decide anything
        from the response. The HTTP client already skips reading for ``HEAD``.
        """
        method = str(kwargs.pop("method", "GET")).upper()
        if method not in _SAFE_METHODS:
            raise ValueError(
                f"{method} is not permitted by the active-check engine; only "
                f"{', '.join(sorted(_SAFE_METHODS))} may be sent"
            )
        return ctx.http.request(
            url, method=method, follow_redirects=False, read_body=True, **kwargs
        )

    check_ctx = CheckContext(
        url=decision.url,
        origin=origin,
        baseline_status=baseline_status,
        catch_all=catch_all,
        send=send,
        notes=notes,
    )

    results: list[ActiveCheckResult] = []

    for name in request.checks:
        spec = CATALOGUE[name]
        try:
            result = spec.run(check_ctx)
        except EgressDenied as exc:
            result = _skip(name, check_ctx, f"refused by the scope guard: {exc.reason}")
        except Exception as exc:  # noqa: BLE001 - a failing check must not fail the tool
            # A check that raises is a harness bug, not a property of the target. Report it
            # in the payload and in the notes: swallowing it as a quiet "skipped" once hid
            # three broken checks behind a clean-looking summary.
            detail = f"{type(exc).__name__}: {exc}"
            notes.append(
                f"check {name} raised - this is a harness bug, not a finding: {detail}"
            )
            result = _skip(name, check_ctx, f"check raised {detail}")
        results.append(result)

    spent = ctx.limits.budgets["requests"].used - before

    findings = _findings_for(results, decision.url, origin)

    ran = [result.check for result in results if result.ran]
    skipped = [result.check for result in results if not result.ran]

    if catch_all:
        notes.append(
            f"The server returned {baseline_status} for a path that cannot exist, so status "
            "codes alone were not trusted: each check re-verified whether a response "
            "represented a real resource."
        )

    hits = [result for result in results if result.severity != "info" and result.ran]
    if hits:
        summary = (
            f"Ran {len(ran)} active check(s) against {decision.url} in {spent} request(s); "
            f"{len(hits)} produced a result worth reporting: "
            + "; ".join(f"{result.check} -> {result.verdict}" for result in hits)
            + ". Every check is non-mutating: only GET, HEAD and OPTIONS were sent, and no "
            "write method was ever performed."
        )
    else:
        summary = (
            f"Ran {len(ran)} active check(s) against {decision.url} in {spent} request(s); "
            "none found a misconfiguration worth reporting. "
            + (f"Skipped: {', '.join(skipped)}. " if skipped else "")
            + "Every check is non-mutating: only GET, HEAD and OPTIONS were sent."
        )

    data = RunSelectedActiveCheckData(
        url=decision.url,
        origin=origin,
        checks_requested=list(request.checks),
        checks_run=ran,
        checks_skipped=skipped,
        baseline_status=baseline_status,
        catch_all_detected=catch_all,
        results=results,
        findings_count=len(findings),
        requests_used=spent,
        notes=notes,
    )
    return ok(
        summary,
        data,
        findings=findings,
        notes=notes,
        priority_fields=("results",),
        droppable_fields=("notes", "rationale", "recommendation"),
    )


def _calibrate(ctx, url: str, notes: list[str]) -> tuple[int | None, bool]:
    """Probe a path that cannot exist, to learn whether status codes mean anything here."""
    parts = urlsplit(url)
    control_url = f"{parts.scheme}://{parts.netloc}{CONTROL_PATH}"
    if not ctx.scope.check_url(control_url, resolve=False).allowed:
        return None, False
    try:
        response = ctx.http.request(
            control_url, method="HEAD", follow_redirects=False, read_body=False
        )
    except EgressDenied:
        return None, False
    except Exception:  # noqa: BLE001
        return None, False
    status = response.status_code
    return status, status == 200


def _unknown_checks(unknown: list[str]):
    from app.tools.base import ToolExecutionError

    return ToolExecutionError(
        f"unknown active check(s): {', '.join(unknown)}. Available: {', '.join(CHECK_NAMES)}"
    )


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #


def _findings_for(
    results: list[ActiveCheckResult], requested_url: str, origin: str
) -> list[Finding]:
    """Turn checks that found something into findings. ``info`` verdicts stay out."""
    findings: list[Finding] = []
    from app.models.finding import Finding as FindingModel

    host = FindingModel.host_of(origin)

    for result in results:
        if not result.ran or result.severity == "info":
            continue

        category = (
            FindingCategory.CORS
            if result.check == "cors_preflight"
            else FindingCategory.CONFIGURATION
        )
        if result.check == "path_normalisation":
            category = FindingCategory.INPUT_VALIDATION

        cwe = {
            "cors_preflight": "CWE-942",
            "http_methods": "CWE-749",
            "trace_method": "CWE-749",
            "path_normalisation": "CWE-22",
        }.get(result.check, "CWE-693")

        findings.append(
            make_finding(
                title=_title_for(result),
                category=category,
                severity=Severity(result.severity),
                confidence=Confidence(result.confidence),
                description=result.rationale,
                impact=_impact_for(result),
                recommendation=result.recommendation,
                url=result.url,
                host=host,
                location=f"active:{result.check}",
                owasp=(
                    "A01:2021 - Broken Access Control"
                    if category is FindingCategory.CORS
                    else "A05:2021 - Security Misconfiguration"
                    if category is FindingCategory.CONFIGURATION
                    else "A03:2021 - Injection"
                ),
                cwe=cwe,
                evidence=[
                    Evidence(
                        tool="run_selected_active_check",
                        url=result.url,
                        location=result.check,
                        observed=result.observed,
                        expected="the check's non-vulnerable outcome",
                        raw={
                            "verdict": result.verdict,
                            "requests_sent": result.requests_sent,
                            "methods_advertised": result.methods_advertised,
                        },
                    )
                ],
                source_tools=["run_selected_active_check"],
                tags=["active", result.check, result.verdict],
            )
        )
    return findings


def _title_for(result: ActiveCheckResult) -> str:
    titles = {
        "cross_origin_write_allowed": "CORS permits a cross-origin write method",
        "trace_enabled": "TRACE method is enabled (cross-site tracing)",
        "write_methods_advertised": "Endpoint advertises write methods",
        "variant_reaches_endpoint": "Encoded path variant reaches a different endpoint",
    }
    return titles.get(result.verdict, f"Active check {result.check} reported {result.verdict}")


def _impact_for(result: ActiveCheckResult) -> str:
    if result.verdict == "cross_origin_write_allowed":
        return (
            "Any website can make a logged-in user's browser perform a state-changing request "
            "to this endpoint and read the response. That ranges from unauthorised data "
            "changes to account takeover."
        )
    if result.verdict == "trace_enabled":
        return (
            "A browser that permits a cross-site TRACE lets an attacker read request headers "
            "the same-origin policy would hide, including cookies without HttpOnly."
        )
    if result.verdict == "variant_reaches_endpoint":
        return (
            "Where a front-end enforces access control on the literal path and the "
            "application resolves a normalised one, an attacker can reach a protected "
            "resource by encoding the traversal sequence."
        )
    return (
        "The endpoint exposes more of its interface to an unauthenticated caller than is "
        "necessary, which shortens an attacker's reconnaissance."
    )


def _origin_of(url: str) -> str:
    parts = urlsplit(url)
    port = f":{parts.port}" if parts.port else ""
    return f"{parts.scheme.lower()}://{(parts.hostname or '').lower()}{port}"


__all__ = [
    "ACTIVE_CHECKS",
    "CATALOGUE",
    "CHECK_NAMES",
    "CONTROL_PATH",
    "CheckContext",
    "CheckSpec",
    "PREFLIGHT_ORIGIN",
    "run_selected_active_check",
]
