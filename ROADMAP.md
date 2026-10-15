# Roadmap

The MVP is complete and deliberately small. This document records what comes next, in the
order the design supports it, and — for the active tools — the specific controls that must
exist *before* any of them is callable.

## Design rule for everything below

No active capability is added to the registry as callable until all four controls exist:

1. the capability is declared in `ToolMeta.capabilities`;
2. `PermissionSet` grants it only via explicit operator opt-in (`--active`);
3. the confirmation gate is wired and exercised for that tool;
4. no payload, method, header, or body is ever supplied by the AI — the model names a
   check and a target, and harness code owns everything else.

---

## Done

### Result tools (was Phase 2) — `get_scan_status`, `get_alerts`, `get_http_history`

Free, read-only views over harness state. They send no traffic and consume no budget, so a
planner can check its own progress without spending the budget it is conserving. This is
what makes an LLM planner able to reason over a whole engagement rather than the last tool
result, and it was the prerequisite for everything else.

`get_scan_status` also returns `suggestions`: gaps derived from harness state (in-scope URLs
whose headers are unchecked, checks not yet run, state-changing forms with no CSRF token).
The model is free to ignore them; they exist so it does not have to rediscover the gap.

Supporting work this required:

* `AttackSurface.http_history` — a bounded transaction log fed by an `exchange_sink`
  callback on the HTTP client, so the history is recorded once, centrally, including
  refused redirects.
* `ScanRunner` attributes each exchange to the trace index that caused it.
* The report now embeds the transaction log and the redirect chains, which makes a
  finding's provenance checkable rather than merely asserted.

### `read_robots` (first of the "finish the passive surface" group)

Fetches `/robots.txt`, `/sitemap.xml` and `/.well-known/security.txt` at an origin. The
**paths are harness constants**; the AI chooses only the origin, which is what keeps this
from becoming a content-discovery scanner. Wildcard rules are dropped rather than expanded,
because expanding them means guessing paths.

### `analyze_exposed_files`

Probes a fixed catalogue of 27 well-known paths across seven categories for readable
repository metadata, dotenv files, database dumps, backups and debug endpoints. The first
tool with a **path list**, so it introduced the controls the active tools will also need:

* a **dedicated budget** (`max_exposed_file_checks`) so discovery cannot starve the checks
  that produce findings;
* **soft-404 calibration** — a control path that cannot exist is probed first, and if it
  answers 200 then status codes are ignored and every hit must pass a content-signature or
  content-type check;
* **redaction** — a hit records the *shape* of a signature match, never the secret value;
* a **content-length ceiling** per entry, so a 2 MB HTML page is not mistaken for a dotenv.

### Payload truncation that degrades in the right direction

Fixing the truncation behaviour was a prerequisite for shipping a tool whose payload can
exceed the planner's context budget. The dispatcher now:

1. drops declared **prose** fields from items before dropping any item;
2. shrinks **prioritised** lists by binary search for the longest prefix that fits, rather
   than a fixed half-budget guess that kept three of twenty-seven entries while the payload
   was under half the limit;
3. always marks a shortened list with its original length, so a truncated payload cannot be
   mistaken for a complete one.

### `detect_technologies`

Fingerprints server, framework and front-end from headers, cookie names and body patterns
against a small, high-precision knowledge base. Scores **only** version disclosure, at low
severity: "this site runs React" is not a security defect, and reporting it as one trains
the reader to ignore the report.

### `analyze_cors`

Promoted out of `check_headers`, which now no longer assesses CORS at all. Doing it properly
needs a second probe with a different `Origin` to distinguish a fixed allowlist value from a
reflection, and a weaker check in two places would double-report the same misconfiguration at
two severities. Classifies five verdicts and deliberately does not report
`wildcard_no_credentials`, which is the correct configuration for a public API.

### `check_tls`

Negotiated protocol, cipher, certificate validity window, self-signed detection, and a
refusal to upgrade an `http://` URL to HTTPS — silently changing the scheme would contact an
endpoint the caller did not name and the operator did not authorise.

Supporting this required extracting `summarize_tls` from `SafeHttpClient` into a pure
function over an `ssl`-shaped object, so the certificate logic can be tested without a socket
and can survive a transport that exposes a partial API.

---

## Phase 1 — complete

All eight passive tools from the original design are now implemented:
`browser_open`, `extract_links`, `extract_forms`, `extract_scripts`, `read_robots`,
`check_headers`, `check_cookies`, `analyze_cors`, `check_tls`, `analyze_exposed_files`,
`detect_technologies`, plus the three result tools.

What is deliberately still absent from Phase 1, and why:

* **Cipher-suite enumeration and downgrade testing.** These need a TLS client of the
  harness's own rather than the HTTP transport's connection, and they are an active
  technique. They belong with Phase 3, behind the same controls.
* **Wordlist-driven content discovery.** `analyze_exposed_files` checks a fixed catalogue. A
  fuzzing primitive is an attack primitive, and the AI does not get one.

The `analyze_exposed_files` path-list machinery is the template for anything else with a
fixed path list — it is the pattern to copy, not to reinvent.

---

## Phase 3 — active checks, started

`run_selected_active_check` is implemented with a five-check catalogue. The design rules from
the top of this document are all satisfied:

1. capabilities declared — `("http_egress", "active_scan")`;
2. granted only by explicit operator opt-in (`--active`);
3. the confirmation gate is wired and exercised;
4. **no payload, method, header or body is ever supplied by the AI.** The request model has
   three fields — `url`, `checks`, `calibrate` — and nothing else.

### The constraint that shapes everything

**Every check in the catalogue is non-mutating, and that is enforced at runtime.** The engine
holds `_SAFE_METHODS = {GET, HEAD, OPTIONS, TRACE}` and refuses anything else, so a check
added later cannot quietly introduce a write. When a check needs to know whether the server
*would* accept a write, it asks with `OPTIONS` and reads the `Allow` header.

`ToolMeta.mutates_target` is therefore `False` while `requires_confirmation` is `True`: the
confirmation is about attention, not state change. A check that had to mutate state to reach
a conclusion would not belong in this catalogue — it would need to be a separate tool with a
separate confirmation story.

### Shipped checks

| Check | Technique | Why it is safe |
| --- | --- | --- |
| `cors_preflight` | `OPTIONS` naming PUT from a reserved `.invalid` origin | Never sends the PUT |
| `http_methods` | `OPTIONS` + `TRACE` | TRACE is defined to have no side effects |
| `options_method` | `OPTIONS` | Idempotent by definition |
| `trace_method` | `TRACE` | Idempotent by definition |
| `path_normalisation` | `GET` of encoded path variants | Read-only, and requires the variant to resolve to a real resource |

### What is deliberately still missing

**Broader injection coverage.** The implemented `run_injection_check` tool provides
harness-owned, read-only SQL error probes and NoSQL operator probes. It deliberately does not
attempt XSS, SSTI, command injection, union/boolean-blind/time-based SQLi, or stacked
statements. Any future injection technique must keep the same shape: payloads live in reviewed
harness code, while the AI chooses only a typed technique and parameter name. `ArgumentGuard`
is not the safety boundary for those payloads.

**Cipher enumeration and TLS downgrade testing.** These need a TLS client of the harness's
own rather than the HTTP transport's connection.

**Methods that mutate.** Out of scope by construction, not by omission.

---

## Phase 4 — the remaining mutating tools

### `run_zap_baseline`

Wrap the OWASP ZAP baseline scan as a subprocess.

* Preconditions: ZAP runs in a container or a pinned local install with a fixed add-on
  set; its target list is generated from `ScopePolicy`, never from AI input; its output is
  parsed into `Finding` models with evidence pointing at the trace entry; the request
  budget is shared with the harness, not duplicated.
* Note: ZAP will make far more requests than `max_requests` allows. Either the budget is
  raised explicitly for this tool with operator consent, or the tool is refused when the
  remaining budget is insufficient. Do not silently bypass the budget.

### `run_openapi_scan`

Consume an OpenAPI/Swagger document from the artifact directory and exercise each declared
operation.

* Preconditions: the spec is placed by the operator, not fetched from the target; every
  operation's server URL is re-checked against the scope; request bodies are generated
  from the schema with **no** attacker-controlled values; `readOnly` operations only, by
  default, with state-changing operations behind a second confirmation.
* This is the highest-value active tool for API testing and the most dangerous, because a
  generated POST can mutate real data.

### `run_authenticated_crawl`

Crawl while authenticated.

* Preconditions: a credential store that keeps secrets out of the report, logs and tool
  results; per-scan session isolation; explicit operator consent per credential; a
  redaction layer over every tool result; and a rule that the planner never sees a
  credential value, only the name of a session it may use.
* Also requires the report to distinguish "tested unauthenticated" from "tested as user X",
  which is a report schema change.

---

## Phase 5 — service surface

The HTTP service already exists; these are the improvements it needs.

* **Streaming progress.** The job API is poll-based. Server-sent events would remove the
  polling loop without changing the job model.
* **Persistent finding store.** Currently each run is independent. A store keyed by
  `(target_host, dedup_key)` would let consecutive runs report "new / still present /
  resolved" instead of a flat list.
* **Baseline diffing.** `ScanReport` already carries stable finding ids; comparing two runs
  by id is a small change with a large usability gain in CI.
* **Per-caller identity.** The API key is a single bearer credential with no per-caller
  scope, rate limit or attribution. A production deployment needs a real identity in front.
* **Report formats.** SARIF for code-scanning dashboards, JUnit XML for CI, and an HTML
  view of the Markdown.

---

## Phase 6 — deliberate non-goals

Recorded so they are not added by accident.

* **Shell execution.** The whole design rests on the model having no code-execution path.
  Adding one would make every guarantee in SECURITY-MODEL.md conditional on prompt
  quality.
* **Model-authored HTTP requests.** Same reason. A "raw request" tool is a
  general-purpose attack primitive with no scope semantics.
* **Model-authored payloads.** Payloads belong in reviewed harness code where they can be
  audited, tested, and bounded.
* **Runtime scope mutation by the model.** Scope is resolved from CLI input before the
  scan and is not writable afterwards. If a scan needs a wider scope, the operator
  restarts it with a wider scope and a new authorisation record.
* **MCP integration before the result tools exist.** MCP would expose more tools to the
  model without first making the existing surface observable. Phase 2 is the prerequisite.
