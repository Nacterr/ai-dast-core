# ai-dast-core

A **scope-restricted web DAST scanner** in which an AI planner decides *what to do next*
and the harness decides *what is possible*.

The AI is a component, not an operator. It can choose a tool and fill in typed
parameters. It cannot run a shell, compose an HTTP request, invent a payload, widen the
scope, or reach a host outside the allowlist — because no such capability is exposed to
it anywhere in the codebase. Findings come from observed tool output, never from the
model's prose.

This design follows the architecture of [usestrix/strix](https://github.com/usestrix/strix)
(tool registry + agent loop + sandboxed execution), but inverts its threat model. Strix
gives an autonomous agent a full offensive toolkit inside a container and trusts the
container. This project gives a constrained planner a fixed, typed, read-only tool
catalogue and trusts nothing — every outbound action passes a scope guard, a permission
check, a budget check and an argument screen first.

---

## What the AI does and does not do

**The AI does exactly this:**

| Responsibility | Where it happens |
| --- | --- |
| Analyse the target and attack surface | `app/orchestrator/planner.py` |
| Choose the next tool | `PlannerDecision` |
| Supply valid, typed parameters | validated against the tool's Pydantic request model |
| Read results | bounded tool-result messages |
| Decide whether to continue or stop | `action: "tool" \| "finish"` |
| Classify and prioritise findings | severity/confidence on harness-produced findings |
| Contribute to the report | executive summary text, labelled as commentary |

**The AI cannot:**

| Forbidden action | Structural reason |
| --- | --- |
| Run a shell command | no tool accepts a command; `ForbiddenCapability.SHELL` is never granted |
| Send a self-composed HTTP request | the only HTTP tools build their own requests; there is no raw-request parameter |
| Generate arbitrary payloads | no request model has a payload field; `ArgumentGuard` flags payload syntax |
| Change the scope | `ScopePolicy` is resolved once, from CLI input, and is not writable at runtime |
| Reach a non-allowlisted host | `ScopeGuard` refuses before any socket is opened |
| Submit forms / authenticate / upload | no tool offers it; the MVP tool set is read-only |

These are not prompt instructions. They are properties of the type system and the
dispatch pipeline, and the test suite asserts them.

---

## Quickstart

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt   # Windows
# .venv/bin/python   -m pip install -r requirements.txt   # macOS / Linux
.venv/Scripts/python -m playwright install chromium
```

Run against a target you own:

```bash
python -m app.main scan https://staging.example.com --authorized-by "you@example.com"
```

That prints the resolved scope, the tool catalogue and the budgets, asks you to confirm
you are authorised, then scans. Results land in `runs/<name>/report.json` and
`report.md`.

Exit codes: `0` clean, `2` high or critical findings, `3` usage/authorisation problem,
`4` runtime error.

> **Hướng dẫn đầy đủ bằng tiếng Việt: [docs/HUONG-DAN-SU-DUNG.md](docs/HUONG-DAN-SU-DUNG.md)**
> — cài đặt, ba chế độ chạy, dùng Web UI, gọi API, đọc báo cáo, xử lý sự cố.

### Or run it as a service

So scans can be driven from outside the CLI:

```bash
python -m app.main serve --api-allowed-host "*.example.com" --port 8093
```

Then open <http://127.0.0.1:8093/> for the web UI, or POST to the API:

```bash
curl -X POST http://127.0.0.1:8093/v1/scans \
  -H 'Content-Type: application/json' \
  -d '{"target":"https://staging.example.com","authorized_by":"you@example.com"}'
```

The critical property of the service: **the CLI's human is trusted, the API's caller is
not.** `--api-allowed-host` is the operator's authorisation and is fixed for the process
lifetime. A request can only *narrow* it — there is no field for allowed hosts, for
permissions, or for a raw tool call. An exposed bind without an API key refuses to start.

### Scan the bundled demo target

The repository ships a deliberately insecure local target so you can see the whole
pipeline work without touching anything real:

```bash
# terminal 1
python -m tools.demo_target --port 8099

# terminal 2
python -m app.main scan http://127.0.0.1:8099 --allow-private --yes \
    --authorized-by "demo" --run-name demo --rate 20
```

Expected: ~17 host-level findings (1 high, 4 medium, 6 low, 6 info) covering a wildcard
CORS policy with credentials, missing HSTS/CSP/X-Frame-Options, three cookies missing
`Secure`/`HttpOnly`/`SameSite`, server banner disclosure, and harvested API routes.

### Inspect the tool surface without scanning anything

```bash
python -m app.main tools                # human-readable catalogue
python -m app.main tools --schema       # with the exact JSON Schemas the AI is given
python -m app.main tools --json         # machine-readable
```

### Use an AI planner

```bash
export DAST_API_KEY=sk-...
python -m app.main scan https://example.com --planner llm --model gpt-4o-mini

# any OpenAI-compatible endpoint works, including local servers
python -m app.main scan https://example.com --planner llm --model qwen3 \
    --base-url http://localhost:8000/v1
```

`--planner scripted` (the default) is a deterministic recon playbook. It is a real
planner, not a stub: it follows the same MVP flow a human would, needs no API key, and
gives the test suite something concrete to exercise.

---

## The tool registry

The registry in `app/tools/catalog.py` is the complete allowlist. Any name not in it is
refused. There is no dynamic import and no `eval`.

### Discovery — `browser_open`, `extract_links`, `extract_forms`, `extract_scripts`, `read_robots`

| Tool | Capability | What it does | Cost |
| --- | --- | --- | --- |
| `browser_open` | `browser` | One navigation in the controlled headless browser; returns a `page_id` | 1 page |
| `extract_links` | — | Links, form actions, scripts, frames, images, annotated `in_scope` | free |
| `extract_forms` | — | Forms with fields and login/upload/missing-CSRF heuristics | free |
| `extract_scripts` | — | Script sources, inline excerpts, API-route candidates, redacted secret hints | free |
| `read_robots` | `http_egress` | robots.txt, sitemap.xml, security.txt at the origin; derives in-scope paths | ≤3 requests |

### Passive analysis — `check_headers`, `check_cookies`, `analyze_cors`, `check_tls`, `analyze_exposed_files`, `detect_technologies`

| Tool | Capability | What it does | Cost |
| --- | --- | --- | --- |
| `check_headers` | `http_egress` | One request; grades HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, COOP, CORP, X-Permitted-Cross-Domain-Policies, plus banner disclosure | 1 request |
| `check_cookies` | `http_egress` | One request; `Set-Cookie` flags across the redirect chain. Values are never stored — only length and a hash | 1 request |
| `analyze_cors` | `http_egress` | Probes with a fixed `.invalid` Origin and classifies the policy. A second probe confirms a reflection | 1–3 requests |
| `check_tls` | `http_egress` | One handshake; negotiated protocol, cipher, certificate validity window and self-signed detection. Never upgrades `http://` to HTTPS | 1 request |
| `analyze_exposed_files` | `http_egress` | Probes a fixed catalogue of well-known paths for readable `/.git/HEAD`, `.env`, database dumps, backups and debug endpoints. Soft-404 calibrated, content-signature confirmed | ≤1 HEAD per path, from a dedicated budget |
| `detect_technologies` | `http_egress` | One request; fingerprints server, framework and front-end from headers, cookies and body patterns | 1 request |

**CORS is assessed by `analyze_cors`, not `check_headers`.** Doing it properly needs a second
probe with a different `Origin` to tell a fixed allowlist value apart from a reflection, and a
weaker check in two places would report the same misconfiguration twice at two severities. The
verdicts that matter:

| Verdict | Severity | Meaning |
| --- | --- | --- |
| `reflects_origin_with_credentials` | high | Any site can read authenticated responses — account takeover |
| `null_origin` | high | Anything in a sandboxed frame can read the response |
| `reflects_origin` | medium | Any site can read the response |
| `wildcard_with_credentials` | medium | Browsers reject this; the configuration is broken, not exploitable |
| `wildcard_no_credentials` | *not a finding* | That is the correct config for a public API |

The `Origin` header is a **harness constant** — there is no request field for it, because a
caller-controlled `Origin` would be an injection into a trust decision the browser makes on
the user's behalf.

`analyze_exposed_files` is the first tool with a **path list**, so it carries four extra
guardrails worth knowing about:

1. **The paths are harness constants.** The AI chooses an origin and, optionally, which
   *categories* to probe. It cannot name a path, so this cannot become a general content
   scanner.
2. **Its own budget** — `max_exposed_file_checks`, separate from `max_requests`, so content
   discovery cannot starve the header and cookie checks that produce findings.
3. **Soft-404 calibration.** Before trusting any status code, it probes a path that cannot
   exist. If that also returns `200`, status codes are treated as meaningless and every hit
   must additionally pass a **content-signature** or content-type check.
4. **It never stores file content.** A hit is recorded as path, status, content type, length
   and severity, with a *redacted* signature match — for a `.env` that is
   `DB_PASSWORD=<redacted>`, never the secret.

A hit is a factual observation ("this path returned a dotenv-shaped body"). Whether it
matters depends on what is in the file, which this tool deliberately does not read out.

### Result — `get_scan_status`, `get_alerts`, `get_http_history`

Free, read-only views over what the scan already knows. They send no traffic and consume
no budget, which matters for prompt design: the planner can check its own progress as often
as it likes without spending the budget it is trying to conserve. They are also what turns a
planner that saw only the last tool result into one that can reason over the whole
engagement.

| Tool | Returns |
| --- | --- |
| `get_scan_status` | Progress, remaining budget, tools already run, and **suggestions** derived from harness state (unchecked in-scope URLs, unrun checks) |
| `get_alerts` | Findings so far, filtered by severity / category / host |
| `get_http_history` | Every recorded HTTP exchange, including redirect chains and blocked redirects |

### Active — 
un_selected_active_check and 
un_injection_check (opt-in)

The only tools that send requests the target did not invite. Both are off by default and each
needs its own capability **and** the confirmation gate.

| Tool | Capability | Opt-in | What it does |
| --- | --- | --- | --- |
| 
un_selected_active_check | ctive_scan | --active | Method, CORS-preflight and path-normalisation checks |
| 
un_injection_check | injection_probe | --injection | Error-based, read-only SQL injection detection |

**The capabilities are separate on purpose.** Being willing to ask a server which HTTP methods
it supports is a different decision from being willing to put quote characters into its
parameters. --injection-only grants the second without the first.

In both tools, **the AI chooses a name, never a payload**. There is no request field for a
method, a header, a body or a payload, because a tool that accepted one would be a raw-request
primitive wearing a check\'s clothing.

#### 
un_selected_active_check

| Check | What it asks | Sends |
| --- | --- | --- |
| cors_preflight | May a cross-origin caller use a **write** method? | OPTIONS naming PUT from a reserved .invalid origin — **never the PUT itself** |
| http_methods | Which methods does the endpoint advertise or accept? | OPTIONS + TRACE |
| options_method | Is OPTIONS answered without authentication? | OPTIONS |
| 	race_method | Is TRACE enabled (cross-site tracing)? | TRACE, defined to have no side effects |
| path_normalisation | Do encoded traversal variants resolve differently? | GET only |

**Every check is non-mutating, and that is enforced rather than merely documented.** The
engine holds a _SAFE_METHODS allowlist of {GET, HEAD, OPTIONS, TRACE} and refuses anything
else at runtime, so a future check cannot introduce a write by accident. When a check needs to
know whether the server *would* accept a write, it asks with OPTIONS and reads the Allow
header.

#### 
un_injection_check

This is the answer to "can injection testing be done without handing the model a payload?" It
can, and the shape is the answer: **the payloads live in harness code; the AI names a technique
and a parameter.**

| Technique | Payloads | Detection |
| --- | --- | --- |
| `sql_error` | a single quote, a double quote, a quote with a comment opener | a database error that was **absent from the baseline** |
| `nosql_operator` | `[$ne]=null`, `[$gt]=`, `[$regex]=.*` | a behaviour change those operators produce |

Every probe is a **read-only GET**. The technique works by making the server\'s *own* query
malformed — never by adding a statement to it. There is **no union, no boolean-blind, no
time-based and no stacked-statement probe**, because those extract or destroy data. Their
absence is asserted by tests, not assumed.

Two things the detector refuses to do:

* **It only reports a signature absent from the baseline.** An application that always prints a
  database error is not flagged.
* **A response that merely varies is recorded, not reported.** Every real application\'s response
  varies with its input; treating that as injection is how scanners earn their reputation for
  noise.

ArgumentGuard is deliberately *not* the control here. It screens caller input, and this tool
never puts caller input on the wire — which is exactly why the payloads must live in harness
code.
### Declared but not implemented

`run_zap_baseline`, `run_authenticated_crawl` and `run_openapi_scan` are registered with
`implemented=False`, carry `requires_confirmation=True` and `mutates_target=True`, and the
dispatcher returns `not_implemented` if anything asks for them. **They are never offered to
the AI.** See [docs/ROADMAP.md](docs/ROADMAP.md) for the preconditions each one needs.

---

## Architecture

```
User: URL + scope
      │
      ▼
CLI (app/main.py) ──► build_scope_policy()  ──► ScopePolicy  (resolved once, immutable)
      │                                          │
      │  interactive authorisation confirmation   │
      ▼                                          ▼
ScanRunner (app/orchestrator/loop.py) ─────► ScopeGuard (app/policy/scope.py)
      │                                          │  every outbound action
      │  1. planner decision                     │
      │  2. registry.dispatch()  ────────────────┤
      │  3. fold result into session state       │
      └──────────────────────────────────────────┘
                              │
                              ▼
                     ToolRegistry.dispatch()
        lookup → availability → permissions → arguments
             → confirmation → schema validation → budget
                              │
                              ▼
                     tool executor (Playwright / httpx)
                              │
                              ▼
             findings ──► dedupe (category+host+location) ──► report.json / report.md
```

The dispatch pipeline is the choke point. Stages 1–6 are pure policy and touch no
network, which is why the security properties are testable without a live target.

Full design notes: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
Threat model and honest limits: [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md).

---

## Project layout

```
ai-dast-core/
├── app/
│   ├── main.py                    CLI: scan / tools / serve subcommands
│   ├── orchestrator/
│   │   ├── planner.py             ScriptedPlanner + LlmPlanner + the system prompt
│   │   └── loop.py                ScanRunner: the agent loop, dedupe, cancellation
│   ├── service/                   HTTP API + web UI (untrusted-caller boundary)
│   │   ├── api.py                 FastAPI app: routes, auth, error shape
│   │   ├── config.py              DeploymentConfig: the operator's authorisation
│   │   ├── jobs.py                JobStore: worker pool, persistence, cancellation
│   │   ├── models.py              API request/response contracts
│   │   └── static/index.html      self-contained web UI
│   ├── tools/
│   │   ├── registry.py            allowlist + the 8-stage dispatch pipeline
│   │   ├── base.py                Tool contract, ToolOutcome, result envelope
│   │   ├── context.py             ToolContext: the only resources a tool gets
│   │   ├── catalog.py             the six MVP tools + roadmap declarations
│   │   ├── browser.py             Playwright session with request-time scope checks
│   │   ├── http_client.py         scope-aware, rate-limited HTTP with manual redirects
│   │   ├── async_runtime.py       the dedicated event-loop thread
│   │   ├── discovery.py           browser_open, extract_links/forms/scripts
│   │   ├── passive_checks.py      check_headers, check_cookies
│   │   ├── findings.py            finding factories + security-header knowledge base
│   │   ├── js_snippets.py         the only JS the harness runs in a page (constants)
│   │   └── html_fallback.py       stdlib parsers for JS-disabled captures
│   ├── policy/
│   │   ├── scope.py               ScopeGuard: the security boundary
│   │   ├── permissions.py         capabilities, ArgumentGuard, confirmation gate
│   │   └── limits.py              budgets and the rate limiter
│   ├── models/
│   │   ├── tools.py               per-tool request/response contracts
│   │   ├── finding.py             Finding, Evidence, severity/confidence
│   │   └── scan.py                config, scope, session, attack surface, report
│   └── reports/
│       └── json_report.py         report.json + report.md
├── tests/                         416 tests, including a live local integration suite
├── tools/demo_target.py           deliberately insecure local target
├── tools/smoke_service.py         end-to-end HTTP smoke test
├── docs/                          guide (VI), architecture, security model, roadmap
├── requirements.txt
└── pyproject.toml
```

---

## Tests

```bash
.venv/Scripts/python -m pytest              # everything
.venv/Scripts/python -m pytest -m "not integration"   # fast, no browser, no sockets
.venv/Scripts/python -m pytest tests/test_scope.py    # the security boundary
```

Each finding carries an `evidence` array whose entries point at the exact tool call that
produced them, via `tool_call_index` into `tool_trace`. That is the difference between a
report and a list of guesses: if it cannot be traced back, it is not in the report.

416 tests. The interesting ones:

* `tests/test_scope.py` — adversarial scope bypasses: `https://allowed.com@evil.com`,
  decimal/hex/octal IP literals (`2130706433`, `0x7f000001`, `127.1`),
  `169.254.169.254`, wildcard-vs-apex matching, DNS rebinding to loopback.
* `tests/test_policy.py` — budget exhaustion, rate limiter, capability grants,
  `ArgumentGuard` against injected commands/payloads/template syntax.
* `tests/test_tools.py` — the core tools against a real browser and real HTTP.
* `tests/test_orchestrator.py` — full scans, the fake-LLM planner contract, and the
  guarantee that a hostile planner cannot escape the tool surface.
* `tests/test_service.py` — API authorisation: an untrusted request can never widen the
  deployment's scope, exceed its ceilings, or reach a private address.
* `tests/test_exposed_files.py` — the false-positive defences, run against both a normal
  server and a soft-404 catch-all: a `200` from a server that lies must not become a
  "your `.env` is public" finding.

---

## Design decisions worth knowing

**A finding must be traceable or it does not exist.** Every finding carries an `evidence`
array whose entries point at the exact tool call that produced them, via `tool_call_index`
into `tool_trace`. That is the difference between a report and a list of guesses.

**Content discovery is calibrated, not trusted.** `analyze_exposed_files` probes a path that
cannot exist before believing any status code. On a server that answers `200` for everything,
every hit must pass a content-signature check instead — the difference between a real
finding and a dozen false "your `.env` is public" reports.

**Truncation never hides the interesting rows.** Tool payloads that exceed the planner's
context budget are trimmed by dropping prose before items, and by keeping the *important*
items when items must go. A shortened list is always marked with its original length, so a
truncated payload cannot be mistaken for a complete one.

**Redirects are followed manually.** `httpx` would perform a redirect hop before the
scope guard could inspect its destination. `SafeHttpClient` disables automatic redirects
and validates, counts and rate-limits every hop itself.

**The browser needs a second scope check.** `ScopeGuard` runs before navigation *and*
inside a Playwright route handler, so a target cannot redirect the scan into a third
party (`off-scope navigation: ...`) or exfiltrate through `fetch`/XHR/WebSocket. Third-party
subresources the page needs to render are permitted but recorded in the report — the
residual risk is documented.

**Findings are identified by `category + host + location`, not by URL.** A missing CSP
header is a property of the origin. Keying on the full URL reported "CSP missing" once
per page and buried the real issues: the demo target produced 43 noisy findings before
this change and 17 actionable ones after, with every observation preserved as a separate
evidence row.

**Cookies are never stored.** Only the value length and a SHA-256 hash are recorded, which
is enough to detect a change and not enough to leak a session.

**The AI is told about prompt injection.** Page content is explicitly labelled untrusted
data in the planner's system prompt, and no tool feeds page text back as instructions.

---

## Authorised use only

This tool sends real requests to the target you name, records what it finds, and produces
a report. Only run it against systems you own or have **explicit, written permission** to
test, and stay within the agreed scope.

You alone are responsible for obtaining that authorisation and for complying with the law.
The software is provided "as is", without warranty of any kind, and the authors accept no
liability for misuse or for any damage caused by it.

Record who authorised the test with `--authorized-by` and `--authorization-note`: both are
written into `report.json` and `run.json` as your audit trail.
