# Security model

This document states what the harness actually guarantees, how each guarantee is
enforced, and — importantly — what it does *not* guarantee. A security tool that
overstates its own boundaries is worse than one that is merely limited.

## Trust boundaries

| Component | Trust level | Why |
| --- | --- | --- |
| CLI input (`scan` arguments) | **Trusted** | Supplied by the human operator, who is confirming authorisation |
| **HTTP API caller** | **Untrusted** | May be anyone holding the key, or a compromised client |
| **Deployment config** (`serve` flags) | **Trusted** | The operator's authorisation; fixed for the process lifetime |
| The AI planner | **Untrusted** | May hallucinate, may be manipulated by page content |
| Tool arguments from the AI | **Untrusted** | Validated against schemas, screened, then re-checked against scope |
| Target page content | **Untrusted** | Including anything that looks like an instruction |
| Target HTTP responses | **Untrusted** | Parsed defensively; never executed |
| LLM provider responses | **Untrusted** | Parsed as data; tool calls revalidated locally |
| Harness code (`app/policy`, `app/tools`, `app/service`) | **Trusted** | The reference monitor |

The last row is the honest caveat: this design protects against a misaligned or
manipulated *model*, and against a hostile *API caller*. It does not protect against a
malicious *commit to this repository*. Code review of `app/policy`, `app/tools` and
`app/service` is the control for that.

### The service boundary

Running `serve` changes who can ask for a scan, so it is worth stating precisely. The CLI's
human is trusted: they name the scope, the budgets and the authorisation, and the tool
does what they said. The API's caller is not.

Everything dangerous is therefore decided by the operator at startup and is **not
expressible in a request**. `ScanRequest` has no field for allowed hosts, no field for
capabilities, no field for a raw tool call, and no field that could reach a private
address unless the operator enabled it. `authorise_request()` computes the resolved scan as
the *intersection* of the deployment's authorisation and what the caller asked for, so a
caller can only ever narrow.

## Guarantees and their enforcement

### G1 — The AI cannot execute code

* `ForbiddenCapability.SHELL`, `RAW_HTTP`, `ARBITRARY_PAYLOAD`, `FILE_WRITE_UNBOUNDED`,
  `SCOPE_MUTATION` are never added to a `PermissionSet`.
* `PermissionSet.assert_forbidden_absent()` runs at startup and raises if the granted
  and forbidden sets ever overlap.
* No tool request model contains a command, script, or code field; the only JavaScript
  the harness runs is in `app/tools/js_snippets.py` as static constants.
* `ArgumentGuard` rejects reserved keys (`command`, `shell`, `exec`, `eval`, `payload`,
  `script`, `subprocess`, `scope`, `permissions`, …) and blocks nesting deeper than 4,
  lists longer than 64, and values longer than 4096 characters.
* Tests: `tests/test_policy.py::test_forbidden_capabilities_never_overlap_granted`,
  `::test_forbidden_argument_keys_are_rejected`.

### G2 — The AI cannot send an arbitrary HTTP request

* The only request-sending tools are `check_headers` and `check_cookies`. Both build
  their request in harness code from a URL and a fixed method enum.
* There is no header-injection, body-injection, or method-injection parameter.
* Tests: `tests/test_tools.py::test_extra_unknown_arguments_are_rejected`.

### G3 — The AI cannot generate a payload

* No request model has a payload field, and no tool forwards a caller-supplied value
  into a query, template, or command.
* `ArgumentGuard` tripwires flag template syntax (`{{`, `${`, `#{`), `<script`,
  `javascript:`, path traversal, SQL `UNION SELECT`/`OR 1=1`, and shell command shapes.
  These are **tripwires for obviously hostile values, not a payload detector** — see
  "What is not guaranteed" below.
* Tests: `tests/test_policy.py::test_value_tripwires_are_rejected`.

### G4 — The AI cannot leave the scope

`ScopeGuard.check_url()` refuses, in order:

1. empty, non-string, or >2048-character URLs;
2. URLs that fail to parse or have no host;
3. schemes outside `{http, https}` — `file:`, `gopher:`, `data:`, `javascript:`,
   `dict:`, `ftp:` are all refused;
4. an invalid port, or a port outside the allowed set (default `{80, 443}` plus the
   target's own port);
5. a path outside `path_prefixes` (default `/`);
6. URLs with embedded credentials (`https://allowed.com@evil.com`);
7. hosts matching the explicit exclusion list, or the always-blocked suffixes
   (`localhost`, `.local`, `.internal`, `.home.arpa`, `.onion`, `metadata.google.internal`);
8. hosts not matching any allowlist entry, where a wildcard `*.example.com` matches
   sub-domains but never the apex;
9. unresolvable hosts — refused *before* a request is spent;
10. IP literals in non-canonical notation, normalised first: `2130706433`, `0x7f000001`,
    `017700000001`, `127.1`, `[::1]`, `[::ffff:127.0.0.1]`;
11. any URL whose resolved addresses are private, loopback, link-local, CGNAT,
    multicast, reserved, unspecified, or 6to4-wrapping-private — unless the operator
    passed `--allow-private`.

The guard runs before every navigation, before every HTTP request, and before **every
redirect hop** (`SafeHttpClient` sets `follow_redirects=False` precisely so it can).

Tests: `tests/test_scope.py` — 65 cases, including
`::test_dns_rebinding_to_loopback_is_refused`,
`::test_obfuscated_and_internal_hosts_are_refused`,
`::test_embedded_credentials_are_refused`.

### G5 — The AI cannot escape the tool surface

* `ToolRegistry` is a fixed dictionary built in `catalog.py`. Unknown names return
  `denied` with the list of available tools.
* Tools with `implemented=False` (the roadmap active tools) return `not_implemented`
  and are excluded from `callable_tools()`, so they never appear in the model's tool list.
* `tests/test_orchestrator.py::test_registry_dispatch_is_the_only_tool_path` asserts the
  loop calls the registry and does not import executors directly.
* Tests: `::test_scan_records_a_denied_tool_call_in_the_trace`,
  `tests/test_tools.py::test_unknown_tool_is_denied`.

### G6 — The AI cannot exceed a budget

Every budget is *reserved before* the work happens (`LimitTracker.reserve`), not measured
afterwards, so an overshoot is impossible even briefly. `before_request()` is the single
choke point for outbound traffic and applies both the request budget and the rate limiter.
The scan deadline is checked at the top of every loop iteration and before every request.

Tests: `tests/test_policy.py::test_limit_tracker_enforces_every_named_budget`,
`tests/test_tools.py::test_tool_call_budget_is_enforced`.

### G7 — The AI cannot fabricate a finding

* Findings are constructed by harness code in `app/tools/findings.py` from values
  observed in a tool result. `Finding.description`, `impact` and `recommendation` come
  from the header knowledge base, not from the model.
* Each finding carries `Evidence` with the tool name and `tool_call_index`, pointing at
  the exact trace entry that produced it.
* The orchestrator re-hydrates findings from `ToolResult` dicts into validated `Finding`
  models, so a malformed payload raises rather than being written to the report.
* `tests/test_orchestrator.py::test_end_to_end_scan_produces_a_complete_report` asserts
  every finding has evidence with a valid in-range trace index.
* The model may classify and prioritise; its text lands in `ai_notes`, which is
  explicitly never treated as evidence.

### G8 — Prompt injection from the target is contained

* The planner's system prompt labels page content as untrusted data and states that only
  the system prompt and harness tool results carry authority.
* Page text never reaches the planner as a message role other than `tool` content, and
  tool results are harness-generated summaries, not raw page HTML.
* Even if the model were fully convinced by injected text, it can only emit a
  `PlannerDecision` — and G1–G6 apply regardless of why it emitted it.
* `extract_scripts` never returns credential *values*, only redacted hints.

### G9 — Cookies and credentials are not retained

* Cookie values are never stored: only `value_length` and `value_sha256`.
* Playwright uses a fresh context per scan, no persistent profile, no user data directory.
* Redirect hop `Authorization` handling is not implemented at all — the MVP has no
  authenticated mode, which is also why the report says the authenticated surface is untested.

### G10 — An API caller cannot widen the deployment's authorisation

This is the guarantee that makes `serve` safe to expose.

* `DeploymentConfig` is frozen at startup. There is no code path that adds a host or raises
  a ceiling afterwards.
* `authorise_request()` refuses a target whose host is not matched by
  `--api-allowed-host`, whose port is not in `--api-allowed-port`, whose scheme is not
  http/https, or that carries embedded credentials.
* A wildcard `*.example.com` matches sub-domains but never the apex, so a broad allowlist
  is still explicit about the apex.
* `scope_hosts` in a request can only name hosts the operator already permitted. It is a
  narrowing control, not an extension control.
* Private and loopback targets are refused unless the operator passed
  `--api-allow-private`. The request has no field that could grant it.
* Requested budgets are **clamped** to the operator's ceilings, not rejected, so a caller
  cannot consume more than the operator allowed and the resolved config is echoed in the
  report.
* `allow_active_tools` and `require_confirmation` are not request fields at all.
* The LLM API key is read from the service's environment by name; it is never accepted
  from a request.
* Additionally, enabling active scanning is impossible: `ToolMeta.implemented` is false for
  every active tool, so `callable_tools()` excludes them and the dispatcher returns
  `not_implemented` regardless of who asks.
* Tests: `tests/test_service.py` — 40 cases covering each of the above.

### G11 — The service cannot be published unauthenticated by accident

* `create_app()` raises if `bind_host` is not loopback and no API key was configured. A
  powerful scanner cannot be left on a network interface by a forgotten flag.
* `ai-dast-core serve` performs the same check before starting uvicorn, with a message that
  explains the risk and the fix.
* Key comparison uses `hmac.compare_digest`, so a wrong key cannot be discovered byte by byte.
* `auth_required` defaults to true for any non-loopback bind, and to true for a loopback
  bind that was given a key.

### G12 — The API cannot drive individual tools

* There is no endpoint that takes a tool name and arguments. The only write endpoint is
  `POST /v1/scans`, which runs a whole policy-bound scan.
* A caller therefore cannot use the service to send one crafted request; they can only ask
  for a scan, and the service's own planner and policy decide what that scan does.
* Test: `tests/test_service.py::test_no_endpoint_runs_a_single_tool`.

### G13 — Content discovery is calibrated, not trusted

`analyze_exposed_files` is the only tool that produces high-severity findings from a
*request pattern* rather than from a single observed response, so it carries extra controls.

* **The path list is harness-owned.** The AI chooses an origin and a category; it cannot name
  a path. There is no request field that accepts one.
* **A control path that cannot exist is probed first.** If the server answers `200` for it,
  every status code is treated as meaningless and every hit must additionally pass a
  content-signature or content-type check.
* **A generic error page is always rejected**, whatever the status code.
* **A response larger than the entry's `max_bytes` is rejected**: a 2 MB HTML page is a
  catch-all, not a dotenv file.
* **Secrets are never stored.** A hit records the *shape* of a signature match
  (`DB_PASSWORD=<redacted>`), never the value. Tests assert that the planted fake credentials
  never appear anywhere in the result or the report.
* **Its own budget** (`max_exposed_file_checks`) is separate from `max_requests`, so the
  sweep cannot starve the checks that produce findings.
* Tests: `tests/test_exposed_files.py`, run against both a normal server and a soft-404
  catch-all.

### G14 — Truncation cannot hide a finding

Tool payloads that exceed the planner's context budget are trimmed by a mechanism that
degrades in the right direction:

* declared **prose** fields are dropped from items before any item is dropped;
* prioritised lists shrink by binary search for the longest prefix that fits, so the
  entries the tool ranked as important are the ones that survive;
* a shortened list is always marked with `<field>_truncated` and its original length in
  `<field>_total`, so a truncated payload cannot be mistaken for a complete one.

Without this, a large `analyze_exposed_files` sweep could have silently hidden the
exposures it found. That would be a security failure of the reporting layer, not of the
tool.

### G15 — The harness cannot be used as a request forger

Two tools send request headers that are *harness constants*, and neither accepts them from the
caller. This matters because a caller-controlled header is a raw-request primitive, and a
caller-controlled `Origin` is worse than that: it is an injection into a trust decision the
browser makes on the user's behalf.

* `analyze_cors` sends `Origin: https://origin-probe.invalid`. `.invalid` is reserved by
  RFC 2606, so naming it can never be mistaken for contacting a real third party. There is no
  request field for the value; a request that tries to supply one is refused with the field
  named.
* `analyze_cors --probe-preflight` sends `Access-Control-Request-Method: GET` and
  `Access-Control-Request-Headers: content-type`, both fixed.
* `SafeHttpClient.request(extra_headers=...)` exists so a *tool* can set harness-chosen
  headers. No tool derives those headers from AI input.
* Tests: `tests/test_cors_tls.py::test_analyze_cors_origin_header_cannot_be_supplied_by_the_caller`.

### G16 — A scheme is never silently upgraded

`check_tls` on an `http://` URL reports that there is no TLS session and sends **no request**.
It does not retry over HTTPS. Silently changing the scheme would contact an endpoint the
caller did not name and the operator did not authorise, which is precisely the scope-escape
this harness refuses everywhere else.

Test: `tests/test_cors_tls.py::test_check_tls_declines_to_upgrade_a_plain_http_url`, which
asserts the request budget is unchanged.

### G17 — Budgets are charged exactly once per request

The request budget is charged by `SafeHttpClient`, which is the single choke point for
outbound traffic. Tools must not reserve it themselves.

This was a real bug: `analyze_cors` and `analyze_exposed_files` each reserved the request *and*
the client charged it again, so every probe cost double and a scan would have exhausted its
configured budget in half the requests the operator intended. The budget is a safety control,
so a silent doubling is a safety failure, not a cosmetic one.

Tests: `tests/test_cors_tls.py::test_analyze_cors_costs_one_or_two_requests` and
`::test_analyze_exposed_files_charges_each_request_once`, both of which also assert that the
transaction log contains exactly as many entries as the budget was charged for.



These are real, and deliberately stated rather than papered over.

**Third-party subresources are allowed to load.** A `browser_open` navigation will fetch
scripts, stylesheets, fonts, images and media from hosts other than the target, because
blocking them breaks most modern sites and makes discovery useless. The rule implemented
in `browser._make_route_handler` is:

* navigation, `fetch`, `xhr`, `websocket`, `eventsource` → **must be in scope**, else
  aborted and recorded;
* `script`, `stylesheet`, `image`, `font`, `media`, `manifest`, `beacon`, `ping`, `other`
  → allowed across origins, and **recorded in the report** so the operator can see which
  third parties the target contacted.

Consequence: running this against an internal-only target can cause that target's HTML to
request resources from public CDNs. The target's own egress policy is the control for
that; the report discloses what happened. This is unavoidable for any browser-based
scanner, and it is why the default scope is narrow and `--allow-private` is opt-in.

### G18 — Active checks cannot mutate the target

`run_selected_active_check` is the only tool that sends requests the target did not invite,
so its constraints are the strictest in the codebase and all of them are enforced in code:

* **The engine holds a method allowlist**, `_SAFE_METHODS = {GET, HEAD, OPTIONS, TRACE}`, and
  refuses any other method at runtime. A check added later cannot introduce a write by
  editing one function.
* **No check sends a write method.** When a check needs to know whether the server *would*
  accept one, it asks with `OPTIONS` and reads the `Allow` header. `POST`, `PUT`, `PATCH`,
  `DELETE` and `CONNECT` never reach the wire.
* **`ToolMeta.mutates_target` is `False`** while `requires_confirmation` is `True`. The
  confirmation is about attention, not state change — and the flag is not a claim, it is a
  consequence of the allowlist.
* **Two independent opt-ins are required**: the `active_scan` capability, granted only by
  `--active`, and the confirmation gate. Neither alone is enough.
* **The API can never enable it.** The service grants no `active_scan` capability and
  `ScanConfig.allow_active_tools` is not a request field.
* Tests: `tests/test_active_checks.py` — each check is run against a recording target and
  the methods it actually sends are asserted, which is stronger than scanning source text
  because it cannot be defeated by building a method name from a variable.

### G19 — A check failure is never hidden

A check that raises is recorded with its exception text, and a note is added saying `this is
a harness bug, not a finding`.

This was a real bug: an earlier version caught every exception and recorded a bare
`skipped`, which hid three broken checks behind a summary that read as though everything had
run. In a security tool, a failure that looks like a clean result is worse than a crash — the
operator would conclude the target was tested when it was not.

Test: `tests/test_active_checks.py::test_a_failing_check_is_reported_not_hidden`.

### G20 — A reported budget covers every request the tool made

`run_selected_active_check` measures its request count *before* calibration, so the figure it
reports includes the calibration probe. A budget that excluded it would understate the cost
and make the operator's accounting wrong.

## Known limitations

These are real, and deliberately stated rather than papered over.

**`ArgumentGuard` is a denylist.** A carefully crafted string can pass it. The structural
protection is that no MVP tool consumes a caller-supplied value in a dangerous position.
If you add an active-check tool that builds a query, you must add per-type validation at
that tool — do not rely on `ArgumentGuard`.

**No authenticated scanning.** There is no credential store and no session handling, so
anything behind a login is untested. Stated in every report's limitations.

**No active testing by default.** Active checks exist but are off unless the operator passes
`--active`, `--injection` or `--injection-only`. The catalogue remains limited to
non-mutating techniques: it does not fuzz, submit forms, upload files, or authenticate.

**Injection coverage is deliberately narrow.** `run_injection_check` owns its SQL syntax and
NoSQL operator payloads in harness code; the caller can choose only a typed technique and
parameter. It can detect error-based SQL injection and record NoSQL behaviour changes, but it
does not test XSS, SSTI, command injection, union/boolean-blind/time-based SQLi, or stacked
statements. A clean report therefore says nothing about those untested classes.

**Active checks are loud.** `OPTIONS` and `TRACE` requests to a production endpoint are
visible in access logs and may trip a WAF or an alerting rule. That is inherent to the
technique, not a defect — but schedule them accordingly.

**A path-catalogue sweep is not content discovery.** `analyze_exposed_files` checks a fixed
27-path list. It will not find an exposed file whose name is not on that list, and it does
not recurse, guess or fuzz. A real content-discovery tool enumerates wordlists; this
deliberately does not, because the AI cannot be given a fuzzing primitive without giving it
an attack primitive.

**Redaction means the report proves exposure, not contents.** For a `.env`, the harness
records that a credential-shaped assignment was present and its length. The operator must
open the file to assess the blast radius. That is intentional: the report should not become
a second copy of the secret.

**TLS introspection is best-effort.** `SafeHttpClient._tls_summary` reads the peer
certificate through the transport when the installed HTTP stack exposes it, and otherwise
reports `"certificate details not exposed by this HTTP transport"` rather than guessing.

**Findings are configuration weaknesses, not confirmed exploits.** A missing CSP header is
a real risk and a real finding, but nothing here proves exploitability. The report says so
in both the executive summary and the limitations.

**False negatives are the dominant error mode.** Five tools and a bounded crawl cannot
find what a manual assessment finds. A clean report means "the checks in
`checks_executed` passed", nothing more. This is stated in `ScanReport.limitations`.

**Denial of service against the target.** The rate limiter defaults to 4 requests/second
and the request budget to 120, which is gentle, but the operator is responsible for
choosing limits appropriate to the target's capacity. When running as a service this
matters more: `--api-max-rate` and `--max-concurrent-scans` are the controls, and the
default of one concurrent scan exists because a DAST tool that fans out is a
denial-of-service tool.

**The API key is a bearer credential with real power.** Anyone holding it can scan every
host in the allowlist. There is no per-caller identity, no per-caller scope, no rate limit
per key, and no audit of *which* caller submitted *which* job beyond the `authorized_by`
string the caller supplied. A production deployment should put this behind an
authenticating reverse proxy that injects a real identity, and treat `authorized_by` as a
claim to be verified rather than a fact.

## Operational guidance

* Always pass `--authorized-by` and `--authorization-note`. They are recorded in
  `report.json` and `run.json` as the audit trail for the engagement.
* Keep `--allow-private` off unless the target genuinely is on a private address.
  It disables the private-range check for the whole scan.
* Keep `--active` off. No active tool is implemented, so it only widens bookkeeping — but
  leaving it off keeps the intent explicit.
* Run with the default `--planner scripted` for a predictable, reproducible baseline, and
  with `--planner llm` when you want the planner to adapt to what it finds.
* Treat every report as a draft for human review. It is designed to accelerate a
  triage, not to replace one.
* **When running as a service**, keep the allowlist as narrow as the engagement allows.
  `*.example.com` is convenient and means anyone with the key can scan your entire estate.
  Keep `--api-allow-private` off. Keep `--max-concurrent-scans` at 1. Put TLS and a real
  identity in front of it before exposing it beyond a trusted network.

## Reporting a vulnerability

This is a security tool; a vulnerability in it is significant. If you find a way to
escape the scope guard, execute code through a tool, or fabricate a finding, please report
it privately to the maintainers rather than opening a public issue, and include the
`PlannerDecision` or tool call that triggers it.
