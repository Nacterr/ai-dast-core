### Active — `run_selected_active_check` and `run_injection_check` (opt-in)

The only tools that send requests the target did not invite. Both are off by default and each
needs its own capability **and** the confirmation gate.

| Tool | Capability | Opt-in | What it does |
| --- | --- | --- | --- |
| `run_selected_active_check` | `active_scan` | `--active` | Method, CORS-preflight and path-normalisation checks |
| `run_injection_check` | `injection_probe` | `--injection` | Error-based, read-only SQL injection detection |

**The capabilities are separate on purpose.** Being willing to ask a server which HTTP methods
it supports is a different decision from being willing to put quote characters into its
parameters. `--injection-only` grants the second without the first.

In both tools, **the AI chooses a name, never a payload**. There is no request field for a
method, a header, a body or a payload, because a tool that accepted one would be a raw-request
primitive wearing a check's clothing.

#### `run_selected_active_check`

| Check | What it asks | Sends |
| --- | --- | --- |
| `cors_preflight` | May a cross-origin caller use a **write** method? | `OPTIONS` naming PUT from a reserved `.invalid` origin — **never the PUT itself** |
| `http_methods` | Which methods does the endpoint advertise or accept? | `OPTIONS` + `TRACE` |
| `options_method` | Is `OPTIONS` answered without authentication? | `OPTIONS` |
| `trace_method` | Is TRACE enabled (cross-site tracing)? | `TRACE`, defined to have no side effects |
| `path_normalisation` | Do encoded traversal variants resolve differently? | `GET` only |

**Every check is non-mutating, and that is enforced rather than merely documented.** The engine
holds a `_SAFE_METHODS` allowlist of `{GET, HEAD, OPTIONS, TRACE}` and refuses anything else at
runtime, so a future check cannot introduce a write by accident. When a check needs to know
whether the server *would* accept a write, it asks with `OPTIONS` and reads the `Allow` header.

#### `run_injection_check`

This is the answer to "can injection testing be done without handing the model a payload?" It
can, and the shape is the answer: **the payloads live in harness code; the AI names a technique
and a parameter.**

| Technique | Payloads | Detection |
| --- | --- | --- |
| `sql_error` | a single quote, a double quote, a quote with a comment opener | a database error that was **absent from the baseline** |
| `nosql_operator` | `[$ne]`, `[$gt]`, `[$regex]` | a behaviour change those operators produce |

Every probe is a **read-only `GET`**. The technique works by making the server's *own* query
malformed — never by adding a statement to it. There is **no union, no boolean-blind, no
time-based and no stacked-statement probe**, because those extract or destroy data. Their
absence is asserted by tests, not assumed.

Two things the detector refuses to do:

* **It only reports a signature absent from the baseline.** An application that always prints a
  database error is not flagged.
* **A response that merely varies is recorded, not reported.** Every real application's response
  varies with its input; treating that as injection is how scanners earn their reputation for
  noise.

`ArgumentGuard` is deliberately *not* the control here. It screens caller input, and this tool
never puts caller input on the wire — which is exactly why the payloads must live in harness
code.

### Declared but not implemented
