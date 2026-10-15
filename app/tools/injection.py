"""``run_injection_check``: error-based, read-only injection detection.

This is the answer to "can injection testing be done without handing the model a payload?"
It can, and the shape is the answer:

    **The payloads live here. The AI names a technique and a parameter.**

Everything that makes this a *scanner* rather than an *exploit* follows from that:

* The payloads are module constants. A caller cannot supply one, because there is no field
  for one. `ArgumentGuard` is irrelevant to this path — it screens caller input, and this
  tool never puts caller input on the wire.
* Detection is **error-based only**. A syntax error in the server's own query reveals that the
  parameter reaches query construction unescaped. Nothing is extracted.
* There is **no union, no boolean-blind, no time-based, no stacked statement**. Those are
  exploitation, they extract or destroy data, and they are the ones that can damage a target.
  Their absence is the point.
* Every probe is a **read-only `GET`**. The technique works by making the server's *own* query
  malformed — never by adding a statement to it.

## Why error-based detection is the right first technique

It has the best signal-to-noise ratio available to a scanner: a database error string is
either present or it is not, and its absence from the baseline makes a coincidence unlikely.
It is also the least intrusive way to learn the same fact. A boolean-blind probe has to run
the query many times and can be mistaken for load; a quote-character probe runs it once.

## The honest limitation

An error-based probe only finds injection that *produces an error*. A well-configured
application that hides database errors, or a query that is vulnerable but tolerates a quote,
will be missed. Absence of a finding here is not evidence of safety, and the report says so.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

from app.models.finding import Confidence, Evidence, Finding, FindingCategory, Severity
from app.models.tools import (
    InjectionFindingResult,
    InjectionProbe,
    RunInjectionCheckData,
    RunInjectionCheckRequest,
)
from app.tools.base import ToolOutcome, ok
from app.tools.findings import make_finding
from app.tools.http_client import EgressDenied, HttpExchange
from app.tools.shared import require_in_scope

# Hard cap on requests, so a URL with many parameters cannot turn one tool call into a
# sweep. The tool reports its own request count so the budget stays honest.
MAX_PARAMETERS = 12
MAX_PROBES_PER_PARAMETER = 3
MAX_BODY_CHARS = 60_000


@dataclass(frozen=True)
class Payload:
    """One harness-owned probe value."""

    value: str
    label: str
    # How this payload is expected to reveal injection.
    kind: str


# --------------------------------------------------------------------------- #
# Payload catalogues
# --------------------------------------------------------------------------- #

# Minimal syntax-breaking characters. Each is a single token that makes a string literal or
# an expression malformed in SQL. None of them adds a statement, and none of them can change
# data: they are quotes, parentheses and comment openers.
SQL_ERROR_PAYLOADS: tuple[Payload, ...] = (
    Payload(value="'", label="single quote", kind="quote"),
    Payload(value="\"", label="double quote", kind="quote"),
    # A quote followed by a comment opener closes a string literal and comments out whatever
    # the query appends after it. Still read-only: a SELECT with a trailing comment returns
    # rows, it does not modify any.
    Payload(value="'--", label="quote with line comment", kind="comment"),
)

# Operator-shaped values for document stores. `$ne` and `$gt` are comparison operators; if the
# server passes the value straight into a query object, the response shape changes.
NOSQL_OPERATOR_PAYLOADS: tuple[Payload, ...] = (
    Payload(value="[$ne]=null", label="not-equal operator", kind="operator"),
    Payload(value="[$gt]=", label="greater-than operator", kind="operator"),
    Payload(value="[$regex]=.*", label="regex operator", kind="operator"),
)

PAYLOADS_BY_TECHNIQUE: dict[str, tuple[Payload, ...]] = {
    "sql_error": SQL_ERROR_PAYLOADS,
    "nosql_operator": NOSQL_OPERATOR_PAYLOADS,
}

TECHNIQUES: tuple[str, ...] = tuple(PAYLOADS_BY_TECHNIQUE)


# --------------------------------------------------------------------------- #
# Error signatures
# --------------------------------------------------------------------------- #

# Database error strings, grouped by engine. Matching one of these in a response that did not
# contain it in the baseline is strong evidence that a query was broken by our input.
#
# Deliberately specific rather than broad: a bare "error" would match half the web, and a
# false "you have SQL injection" is the most expensive false positive a scanner can produce.
SQL_ERROR_SIGNATURES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("mysql", re.compile(r"SQL syntax.{0,80}MySQL", re.IGNORECASE | re.DOTALL)),
    ("mysql", re.compile(r"check the manual that corresponds to your (?:MySQL|MariaDB)", re.IGNORECASE)),
    ("mysql", re.compile(r"Warning.{0,40}mysql_(?:query|fetch)", re.IGNORECASE)),
    ("postgresql", re.compile(r"PostgreSQL.{0,80}ERROR", re.IGNORECASE | re.DOTALL)),
    ("postgresql", re.compile(r"pg_query\(\)|pg_exec\(\)", re.IGNORECASE)),
    ("postgresql", re.compile(r"unterminated quoted string", re.IGNORECASE)),
    ("postgresql", re.compile(r"syntax error at or near", re.IGNORECASE)),
    ("mssql", re.compile(r"Microsoft OLE DB Provider for SQL Server", re.IGNORECASE)),
    ("mssql", re.compile(r"Unclosed quotation mark after the character string", re.IGNORECASE)),
    ("mssql", re.compile(r"Incorrect syntax near", re.IGNORECASE)),
    ("oracle", re.compile(r"ORA-\d{4,5}", re.IGNORECASE)),
    ("oracle", re.compile(r"Oracle error|quoted string not properly terminated", re.IGNORECASE)),
    ("sqlite", re.compile(r"SQLite3?::(?:Error|Exception)", re.IGNORECASE)),
    ("sqlite", re.compile(r"sqlite3\.OperationalError|unrecognized token", re.IGNORECASE)),
    ("sqlite", re.compile(r'near ".*": syntax error', re.IGNORECASE)),
    ("generic", re.compile(r"You have an error in your SQL syntax", re.IGNORECASE)),
    ("generic", re.compile(r"valid MySQL result resource", re.IGNORECASE)),
    ("generic", re.compile(r"supplied argument is not a valid (?:MySQL|PostgreSQL)", re.IGNORECASE)),
)

# Statuses that mean "the request was rejected" rather than "the application answered".
_REJECTION_STATUS = frozenset({400, 500, 502, 503})


def run_injection_check(ctx, request: RunInjectionCheckRequest) -> ToolOutcome:
    """Probe the URL's query parameters for error-based injection."""
    decision = require_in_scope(ctx, request.url)
    payloads = PAYLOADS_BY_TECHNIQUE[request.technique]

    before = ctx.limits.budgets["requests"].used
    notes: list[str] = []

    parts = urlsplit(decision.url)
    explicit = request.canonical_query.strip()
    if explicit:
        # The canonical query replaces whatever the URL carried: it declares both the
        # parameter names *and* their seed values, so the baseline request and every probe
        # must be built from it. Using it only for the names would leave the server seeing no
        # parameter at all, and the whole probe would be meaningless.
        effective_parts = parts._replace(query=explicit)
        effective_url = urlunsplit(effective_parts)
        if not ctx.scope.check_url(effective_url, resolve=False).allowed:
            return ok(
                f"The URL built from canonical_query was refused by the scope guard, so "
                "nothing was probed: {effective_url}",
                RunInjectionCheckData(
                    url=decision.url,
                    technique=request.technique,
                    payloads_available=len(payloads),
                    notes=notes,
                ),
            )
        parts = effective_parts
        target_url = effective_url
        query_pairs = parse_qs(explicit, keep_blank_values=True)
    else:
        target_url = decision.url
        query_pairs = parse_qs(parts.query, keep_blank_values=True)

    available = list(query_pairs)
    if not available:
        return ok(
            f"{decision.url} carries no query parameters, so there is nothing to probe. "
            "Supply canonical_query with the parameter names to test, or pick a URL that "
            "already has a query string.",
            RunInjectionCheckData(
                url=decision.url,
                technique=request.technique,
                payloads_available=len(payloads),
                notes=notes,
            ),
        )

    requested = [name for name in request.parameters if name]
    if requested:
        tested = [name for name in requested if name in available]
        skipped = [name for name in requested if name not in available]
        if skipped:
            notes.append(
                f"these parameter names are not present in the URL and were skipped: "
                f"{', '.join(skipped)}. Use canonical_query to declare their values."
            )
    else:
        tested = available
        skipped = []

    tested = tested[:MAX_PARAMETERS]
    if len(available) > MAX_PARAMETERS:
        notes.append(
            f"the URL has {len(available)} parameters; only the first {MAX_PARAMETERS} were "
            "probed, to bound the number of requests one tool call can make."
        )

    # One baseline request with the parameters at their original values. Its body is the
    # reference every probe is compared against, so an error string the application always
    # emits is not mistaken for injection.
    baseline = _send(ctx, target_url, notes)
    baseline_status = baseline.status_code if baseline else None
    baseline_body = _body_of(baseline)
    baseline_length = len(baseline_body) if baseline is not None else None

    if baseline is None or baseline_status is None:
        return ok(
            f"Could not obtain a baseline response from {target_url}, so there is nothing "
            "to compare a probe against. No payloads were sent.",
            RunInjectionCheckData(
                url=decision.url,
                technique=request.technique,
                payloads_available=len(payloads),
                notes=notes,
            ),
        )

    probes: list[InjectionProbe] = []
    results: list[InjectionFindingResult] = []

    for parameter in tested:
        result, parameter_probes = _probe_parameter(
            ctx=ctx,
            url=target_url,
            parts=parts,
            parameter=parameter,
            payloads=payloads[:MAX_PROBES_PER_PARAMETER],
            baseline_status=baseline_status,
            baseline_body=baseline_body,
            baseline_length=baseline_length or 0,
            notes=notes,
        )
        results.append(result)
        probes.extend(parameter_probes)

    findings = _findings_for(results, decision.url)
    vulnerable = [result for result in results if result.vulnerable]
    spent = ctx.limits.budgets["requests"].used - before

    if vulnerable:
        summary = (
            f"Tested {len(tested)} parameter(s) of {decision.url} with the "
            f"{request.technique} technique in {spent} request(s); {len(vulnerable)} produced "
            f"a database error that the baseline did not: "
            + ", ".join(result.parameter for result in vulnerable)
            + ". The payloads are harness constants and every probe was a read-only GET. This "
            "confirms error-based injection; it does not extract any data."
        )
    else:
        summary = (
            f"Tested {len(tested)} parameter(s) of {decision.url} with the "
            f"{request.technique} technique in {spent} request(s); no error-based injection "
            "was detected. The payloads are harness constants and every probe was a read-only "
            "GET. This does not prove the parameters are safe: an application that suppresses "
            "database errors, or a query that tolerates the characters, will not be detected "
            "this way."
        )

    data = RunInjectionCheckData(
        url=decision.url,
        technique=request.technique,
        parameters_tested=tested,
        parameters_skipped=skipped,
        baseline_status=baseline_status,
        baseline_length=baseline_length,
        results=results,
        probes=probes,
        vulnerable_count=len(vulnerable),
        requests_used=spent,
        payloads_available=len(payloads),
        notes=notes,
    )
    return ok(
        summary,
        data,
        findings=findings,
        notes=notes,
        priority_fields=("results", "probes"),
        droppable_fields=("notes", "description", "recommendation"),
    )


# --------------------------------------------------------------------------- #
# Probing
# --------------------------------------------------------------------------- #


def _probe_parameter(
    *,
    ctx,
    url: str,
    parts,
    parameter: str,
    payloads: tuple[Payload, ...],
    baseline_status: int,
    baseline_body: str,
    baseline_length: int,
    notes: list[str],
) -> tuple[InjectionFindingResult, list[InjectionProbe]]:
    """Send each payload to one parameter and decide whether it revealed injection."""
    probes: list[InjectionProbe] = []
    payloads_sent = 0

    for index, payload in enumerate(payloads):
        probe_url = _inject(url, parts, parameter, payload.value)
        if not ctx.scope.check_url(probe_url, resolve=False).allowed:
            notes.append(f"{parameter}: a probe URL was refused by the scope guard")
            break

        response = _send(ctx, probe_url, notes)
        payloads_sent += 1
        if response is None or response.status_code is None:
            probes.append(
                InjectionProbe(
                    parameter=parameter,
                    payload_index=index,
                    payload_label=payload.label,
                    baseline_status=baseline_status,
                )
            )
            continue

        body = _body_of(response)
        signature = _match_error_signature(body)
        # Only a signature that is *absent* from the baseline counts. An application that
        # always prints a database error mentions it on both requests.
        if signature and _match_error_signature(baseline_body):
            signature = ""
        length_delta = len(body) - baseline_length

        probe = InjectionProbe(
            parameter=parameter,
            payload_index=index,
            payload_label=payload.label,
            status_code=response.status_code,
            baseline_status=baseline_status,
            error_signature=signature,
            length_delta=length_delta,
            behaviour_changed=(
                response.status_code != baseline_status
                or (signature != "")
                or abs(length_delta) > max(64, baseline_length // 10)
            ),
        )
        probes.append(probe)

    return _conclude(parameter, payloads_sent, probes, baseline_status), probes


def _conclude(
    parameter: str,
    payloads_sent: int,
    probes: list[InjectionProbe],
    baseline_status: int,
) -> InjectionFindingResult:
    """Turn the probe results for one parameter into a verdict.

    A signature match is the strong signal. A behaviour change alone is *recorded but not
    reported as a finding*: a parameter that changes the response shape is normal for any
    real application, and treating that as injection is how scanners earn their reputation
    for noise.
    """
    matching = [probe for probe in probes if probe.error_signature]

    if matching:
        signature = matching[0].error_signature
        engine = _engine_for(signature)
        return InjectionFindingResult(
            parameter=parameter,
            technique="sql_error",
            vulnerable=True,
            verdict="error_based_injection",
            severity="high",
            confidence="high",
            description=(
                f"Sending {matching[0].payload_label!r} in the {parameter!r} parameter made "
                f"the server return a database error ({engine}) that the baseline request did "
                "not. The parameter reaches query construction without being escaped, so it "
                "can carry SQL."
            ),
            recommendation=(
                "Use parameterised queries or prepared statements for this parameter. Do not "
                "build SQL by string concatenation, and do not rely on escaping alone. Also "
                "stop returning raw database errors to clients: they turn a blind flaw into a "
                "directly exploitable one."
            ),
            error_signature=signature,
            probes_sent=payloads_sent,
            baseline_requests=1,
        )

    changed = [probe for probe in probes if probe.behaviour_changed]
    if changed:
        return InjectionFindingResult(
            parameter=parameter,
            technique="sql_error",
            vulnerable=False,
            verdict="behaviour_changed_without_error",
            severity="info",
            confidence="low",
            description=(
                f"The {parameter!r} parameter changed the response "
                f"(status or length) for {len(changed)} of {len(probes)} probe(s), but no "
                "database error was produced. A response that varies with its input is normal, "
                "so this is recorded and not reported as a finding."
            ),
            probes_sent=payloads_sent,
            baseline_requests=1,
        )

    if all(probe.status_code is None for probe in probes):
        return InjectionFindingResult(
            parameter=parameter,
            technique="sql_error",
            vulnerable=False,
            verdict="probes_failed",
            severity="info",
            confidence="low",
            description=f"No probe against {parameter!r} produced a usable response.",
            probes_sent=payloads_sent,
            baseline_requests=1,
        )

    return InjectionFindingResult(
        parameter=parameter,
        technique="sql_error",
        vulnerable=False,
        verdict="no_error_observed",
        severity="info",
        confidence="medium",
        description=(
            f"No database error was produced by {len(probes)} probe(s) against {parameter!r}. "
            "That is the expected result for a correctly parameterised query, but it is also "
            "what a server that suppresses errors looks like."
        ),
        probes_sent=payloads_sent,
        baseline_requests=1,
    )


def _send(ctx, url: str, notes: list[str]) -> HttpExchange | None:
    """One read-only GET. The method is not a parameter: probes are never anything else."""
    try:
        return ctx.http.request(url, method="GET", follow_redirects=False, read_body=True)
    except EgressDenied as exc:
        notes.append(f"request refused by the scope guard: {exc.reason}")
        return None
    except Exception as exc:  # noqa: BLE001 - a failed probe is data, not a crash
        notes.append(f"probe failed ({type(exc).__name__}): {exc}")
        return None


def _inject(url: str, parts, parameter: str, payload: str) -> str:
    """Return the URL with one parameter's value replaced by a payload.

    Built with ``urlencode`` so the payload is percent-encoded into a legal query string.
    The server decodes it back into the quote character, which is the whole point; encoding
    is transport, not sanitisation.
    """
    pairs = parse_qs(parts.query, keep_blank_values=True)
    new_pairs: list[tuple[str, str]] = []
    for key, values in pairs.items():
        if key == parameter:
            # A single value per probe keeps the comparison against the baseline meaningful.
            new_pairs.append((key, payload))
        else:
            for value in values:
                new_pairs.append((key, value))
    query = urlencode(new_pairs)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))


def _body_of(exchange: HttpExchange | None) -> str:
    if exchange is None:
        return ""
    return (exchange.body_prefix or "")[:MAX_BODY_CHARS]


def _match_error_signature(body: str) -> str:
    """Return the matched database error text, or an empty string."""
    if not body:
        return ""
    for engine, pattern in SQL_ERROR_SIGNATURES:
        match = pattern.search(body)
        if match:
            return f"[{engine}] {match.group(0)[:200]}"
    return ""


def _engine_for(signature: str) -> str:
    match = re.match(r"\[([a-z]+)\]", signature)
    return match.group(1) if match else "unknown"


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #


def _findings_for(results: list[InjectionFindingResult], requested_url: str) -> list[Finding]:
    """One finding per vulnerable parameter, with the error text as evidence."""
    from app.models.finding import Finding as FindingModel

    host = FindingModel.host_of(requested_url)
    findings: list[Finding] = []

    for result in results:
        if not result.vulnerable:
            continue
        engine = _engine_for(result.error_signature)
        findings.append(
            make_finding(
                title=f"Error-based SQL injection in the '{result.parameter}' parameter",
                category=FindingCategory.INPUT_VALIDATION,
                severity=Severity(result.severity),
                confidence=Confidence(result.confidence),
                description=result.description,
                impact=(
                    "An attacker who can inject SQL can read data the application can read, "
                    "and depending on the database account may modify or delete it. The "
                    "error message also discloses the database engine, which narrows the "
                    "attack considerably."
                ),
                recommendation=result.recommendation,
                url=requested_url,
                host=host,
                location=f"parameter:{result.parameter}",
                owasp="A03:2021 - Injection",
                cwe="CWE-89",
                evidence=[
                    Evidence(
                        tool="run_injection_check",
                        url=requested_url,
                        location=result.parameter,
                        observed=(
                            f"a harness-owned syntax probe produced: {result.error_signature}"
                        ),
                        expected=(
                            "a normal response, or a generic error that does not disclose the "
                            "database engine"
                        ),
                        raw={
                            "technique": result.technique,
                            "verdict": result.verdict,
                            "engine": engine,
                            "probes_sent": result.probes_sent,
                        },
                    )
                ],
                references=[
                    "https://owasp.org/Top10/A03_2021-Injection/",
                    "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                ],
                source_tools=["run_injection_check"],
                tags=["active", "injection", "sqli", engine],
            )
        )
    return findings


__all__ = [
    "MAX_PARAMETERS",
    "MAX_PROBES_PER_PARAMETER",
    "NOSQL_OPERATOR_PAYLOADS",
    "PAYLOADS_BY_TECHNIQUE",
    "Payload",
    "SQL_ERROR_PAYLOADS",
    "SQL_ERROR_SIGNATURES",
    "TECHNIQUES",
    "_inject",
    "_match_error_signature",
    "run_injection_check",
]
