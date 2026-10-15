# Architecture

## The one-sentence version

The AI decides *what to do next* by returning a `PlannerDecision` that can only name a
registered tool and supply schema-shaped arguments; the harness decides *what is
possible* by owning scope, permissions, budgets, egress, the browser and the report.

## Why this shape

An autonomous agent with shell access is powerful and hard to bound. This project takes
the opposite position: the planner is the *least* privileged component in the system.

```
                       ┌──────────────────────────────────────────┐
   AI planner ────────►│  PlannerDecision                         │
  (untrusted)          │  action: "tool" | "finish"               │
                       │  tool:   str   (must be registered)      │
                       │  args:   dict  (must match the schema)   │
                       └──────────────────┬───────────────────────┘
                                          │
                       ┌──────────────────▼───────────────────────┐
                       │  ToolRegistry.dispatch()   ← THE CHOKE   │
                       │  1 lookup   2 availability               │
                       │  3 permissions + argument screen         │
                       │  4 confirmation (if required)            │
                       │  5 schema validation                     │
                       │  6 budget reservation                    │
                       │  7 execution (bounded by timeout)        │
                       │  8 payload truncation                    │
                       └──────────────────┬───────────────────────┘
                                          │
                       ┌──────────────────▼───────────────────────┐
                       │  tool executor                           │
                       │  ScopeGuard ──► Playwright / httpx       │
                       └──────────────────┬───────────────────────┘
                                          │
                        findings + attack surface + trace
                                          │
                       ┌──────────────────▼───────────────────────┐
                       │  harness state ──► report.json / .md     │
                       └──────────────────────────────────────────┘
```

A `PlannerDecision` cannot express a shell command, a raw HTTP request, a payload, or a
scope change. Those actions are not forbidden by a rule the model might talk its way
around — they are absent from the data structure. That is the central design choice.

## Layers

### `app/models` — the contracts

Every trust boundary is a Pydantic model with `extra="forbid"`.

* `tools.py` — one request model and one data model per tool. The request models *are*
  the AI's parameter surface: they are converted to JSON Schema and handed to the model,
  then used again to validate what comes back. Two independent layers agree on the shape
  and neither trusts the model's text.
* `finding.py` — `Finding`, `Evidence`, and the identity rule
  (`category + host + location`).
* `scan.py` — `ScanConfig`, `ScopePolicy`, `ScanSession`, `AttackSurface`, `ScanReport`,
  `PlannerDecision`.

### `app/policy` — the rules

Small, dependency-light, and unit-testable without a network.

* `scope.py` — `ScopeGuard`. The security boundary. Checks scheme, host allowlist,
  exclusion list, port, path prefix, embedded credentials, IP-literal obfuscation, and
  every resolved address (so a public hostname pointing at `127.0.0.1` is refused).
  Also exposes the wildcard matcher: `*.example.com` matches sub-domains but never the
  apex, which is the safer default.
* `limits.py` — `Budget`, `LimitTracker`, `RateLimiter`. Budgets are *reserved before*
  the work happens, so a runaway planner cannot overshoot even briefly.
* `permissions.py` — `Capability`, `PermissionSet`, `ArgumentGuard`,
  `ConfirmationGate`, `RequestPolicy`. `ForbiddenCapability` names the capabilities that
  are never granted, so `assert_forbidden_absent()` can prove at startup that they are
  not present.

### `app/tools` — the capabilities

* `registry.py` — the allowlist and the dispatch pipeline above.
* `base.py` — the `Tool` contract: metadata + request model + executor. Tool bodies
  return a `ToolOutcome` (data); the dispatcher owns the envelope (status, timing,
  truncation) so behaviour is uniform.
* `context.py` — `ToolContext`. What a tool body receives: the session, the scope guard,
  the budget tracker, the artifact directory, and *lazily created* HTTP and browser
  resources. No shell, no unbounded filesystem, no raw socket.
* `browser.py` — the Playwright session. Uses a dedicated event-loop thread
  (`async_runtime.py`) so the orchestrator stays synchronous. Installs a route handler
  that re-checks scope on every request the page makes.
* `http_client.py` — `SafeHttpClient`. Redirects are followed **manually** because
  automatic following would perform the hop before the scope guard could inspect it.
* `discovery.py`, `passive_checks.py` — the six MVP tools.
* `js_snippets.py` — the only JavaScript the harness executes in a page. Static
  constants, never assembled from AI input, and read-only against the DOM.
* `findings.py` — finding factories plus the security-header knowledge base (severity,
  impact, recommendation, OWASP/CWE mapping). Keeping this as data means severity is a
  harness decision, not a model opinion.
* `catalog.py` — the concrete registry. The single place where capabilities are declared.

### `app/orchestrator` — the loop

* `planner.py` — `ScriptedPlanner` (deterministic playbook) and `LlmPlanner`
  (OpenAI-compatible tool calling). Both return the same `PlannerDecision`. The system
  prompt states the prohibitions explicitly *and* the code enforces them independently.
* `loop.py` — `ScanRunner`. Asks the planner for a decision, dispatches it, folds the
  result into harness state, repeats until `finish` or a budget runs out. Findings are
  re-hydrated from `ToolResult` dicts into `Finding` models, stamped with the trace index
  that produced them, then deduplicated.

### `app/reports` — the deliverable

`json_report.py` builds `ScanReport` purely from session state, renders Markdown, and
writes both. The planner's only contribution is its executive-summary text, which is
recorded under `planner.notes` and labelled as commentary.

## Data flow of one tool call

```
planner.decide()                 -> PlannerDecision(tool="check_headers", args={"url": ...})
ScanRunner._execute_decision()   -> ToolCall
registry.dispatch()              -> preflight -> request model -> execute -> ToolResult
passive_checks.check_headers()   -> ScopeGuard.check_url() -> SafeHttpClient.request()
                                 -> HeaderReport + [Finding, ...]
loop._stamp_evidence()           -> evidence.tool_call_index = trace index
ScanRunner.run() finally         -> _dedupe_findings() -> sort_findings()
build_report()                   -> ScanReport -> report.json + report.md
```

## Budgets

Every budget lives in `ScanConfig` and is enforced by `LimitTracker`:

| Budget | Default | Enforced at |
| --- | --- | --- |
| `max_steps` | 24 | before asking the planner again |
| `max_tool_calls` | 80 | in `dispatch()`, before execution |
| `max_pages` | 15 | in `browser_open`, before navigation |
| `max_requests` | 120 | in `LimitTracker.before_request()`, per redirect hop |
| `requests_per_second` | 4 | token bucket in `RateLimiter` |
| `request_timeout_s` | 15 | httpx client |
| `tool_timeout_s` | 45 | thread-pool future in the dispatcher |
| `scan_timeout_s` | 600 | checked at the top of every loop iteration and before every request |

## Extensibility

Adding a tool means three things: a request/data model pair in `app/models/tools.py`, an
executor in the relevant tool module, and an entry in `app/tools/catalog.py` declaring
its capabilities. That is deliberately all — the registry has no plugin discovery, so no
code path can introduce a capability that was not reviewed and declared.

## Known trade-offs

* **Third-party subresources are allowed to load.** Blocking CDN scripts, fonts and
  analytics breaks most real sites and makes discovery useless. The rule is: markup-driven
  subresources may cross the origin boundary (and are recorded); script-driven
  `fetch`/XHR/WebSocket may not. See SECURITY-MODEL.md.
* **The tool-timeout thread is not cancellable.** A hung tool leaks its thread until the
  process exits. Bounded by `tool_timeout_s` and acceptable for a single-scan CLI; it
  would need a subprocess boundary for a long-lived server.
* **`ArgumentGuard` is a denylist.** It catches obvious escape syntax and reserved keys,
  but a crafted string can pass it. The real protection is that no MVP tool forwards a
  caller-supplied value into a query, template, or command.
* **One browser context per scan.** No session isolation between scans because there is
  exactly one scan per process. A server would need one context per tenant.
