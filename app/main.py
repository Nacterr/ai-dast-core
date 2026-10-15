"""Command-line interface.

Two subcommands:

* ``scan``   - run an authorised scan against a URL (the core flow).
* ``tools``  - list the tool catalogue, with JSON Schemas, without scanning anything.

The CLI is the place where the *human* sets the boundaries: the scope, the budgets, the
confirmation policy and the authorisation record. Everything the AI can do afterwards is
bounded by the choices made here, which is why the scope is printed back for confirmation
before any traffic is sent.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import sys
from pathlib import Path

from app import __version__
from app.models.scan import ScanConfig
from app.orchestrator.loop import ScanRunner
from app.orchestrator.planner import LlmPlanner, ScriptedPlanner
from app.policy.permissions import Capability, ConfirmationGate, PermissionSet
from app.policy.scope import ScopeGuard, build_scope_policy
from app.reports.json_report import build_report, tool_categories, write_report
from app.tools.catalog import build_default_registry

EXIT_OK = 0
EXIT_FINDINGS = 2
EXIT_USAGE = 3
EXIT_ERROR = 4


# --------------------------------------------------------------------------- #
# Parser
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ai-dast-core",
        description=(
            "Scope-restricted AI-assisted web DAST scanner. The AI chooses which tool to "
            "run; the harness enforces scope, permissions and budgets. Only scan systems "
            "you are authorised to test."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=_EPILOG,
    )
    parser.add_argument("--version", action="version", version=f"ai-dast-core {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="run a scan against an authorised target")
    scan.add_argument("target", help="target URL, for example https://example.com")
    scan.add_argument(
        "--scope-host",
        action="append",
        default=[],
        metavar="HOST",
        help=(
            "additional in-scope hostname (repeatable). Use '*.example.com' to include "
            "sub-domains. Only add hosts you are authorised to test."
        ),
    )
    scan.add_argument(
        "--exclude-host",
        action="append",
        default=[],
        metavar="HOST",
        help="hostname to deny even if it matches the scope (repeatable).",
    )
    scan.add_argument(
        "--allow-private",
        action="store_true",
        help=(
            "allow private/loopback targets (required for local testing). This widens what "
            "the scanner can reach, so only use it on a target you control."
        ),
    )
    scan.add_argument(
        "--authorized-by",
        default="",
        metavar="NAME",
        help="who authorised this test; recorded in the report as the audit trail.",
    )
    scan.add_argument(
        "--authorization-note",
        default="",
        metavar="TEXT",
        help="free-form note about the authorisation, recorded in the report.",
    )

    planner_group = scan.add_argument_group("planner")
    planner_group.add_argument(
        "--planner",
        choices=("scripted", "llm"),
        default="scripted",
        help=(
            "scripted: a deterministic recon playbook that needs no API key (default). "
            "llm: an AI planner that chooses tools via an OpenAI-compatible API."
        ),
    )
    planner_group.add_argument(
        "--model",
        default=os.environ.get("DAST_MODEL", "gpt-4o-mini"),
        help="model name for --planner llm (default: $DAST_MODEL or gpt-4o-mini).",
    )
    planner_group.add_argument(
        "--base-url",
        default=os.environ.get("DAST_BASE_URL", ""),
        help="OpenAI-compatible base URL, for example a local or gateway endpoint.",
    )

    limits = scan.add_argument_group("budgets")
    limits.add_argument("--max-steps", type=int, default=24, help="maximum planning steps.")
    limits.add_argument("--max-tool-calls", type=int, default=80, help="maximum tool calls.")
    limits.add_argument("--max-pages", type=int, default=15, help="maximum pages to open.")
    limits.add_argument("--max-requests", type=int, default=120, help="maximum HTTP requests.")
    limits.add_argument(
        "--rate", type=float, default=4.0, help="outbound requests per second (default 4)."
    )
    limits.add_argument(
        "--request-timeout", type=float, default=15.0, help="per-request timeout in seconds."
    )
    limits.add_argument(
        "--tool-timeout", type=float, default=45.0, help="per-tool timeout in seconds."
    )
    limits.add_argument(
        "--scan-timeout", type=float, default=600.0, help="whole-scan timeout in seconds."
    )

    execution = scan.add_argument_group("execution")
    execution.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="auto-approve actions that would otherwise prompt for confirmation.",
    )
    execution.add_argument(
        "--active",
        action="store_true",
        help=(
            "grant the active-scan capability: non-mutating method, CORS-preflight, "
            "path-normalisation and OpenAPI checks. Only GET, HEAD, OPTIONS and TRACE are ever sent."
        ),
    )
    execution.add_argument(
        "--openapi",
        action="store_true",
        help="grant the active-scan capability and probe OpenAPI / Swagger specifications.",
    )
    execution.add_argument(
        "--injection",
        action="store_true",
        help=(
            "grant the injection-probe capability: harness-owned, error-based, read-only "
            "payloads in query parameters. Separate from --active because being willing to "
            "ask a server which methods it supports is a different decision from being "
            "willing to put quote characters into its parameters. Use --injection-only for "
            "that alone."
        ),
    )
    execution.add_argument(
        "--injection-only",
        action="store_true",
        help="grant the injection-probe capability without the broader active-scan one.",
    )
    execution.add_argument(
        "--output-dir",
        type=Path,
        default=Path("runs"),
        help="directory that receives one folder per run (default: ./runs).",
    )
    execution.add_argument(
        "--run-name", default="", help="name for this run; defaults to a timestamp."
    )
    execution.add_argument(
        "--json", action="store_true", help="print the report JSON to stdout as well."
    )
    execution.add_argument(
        "--quiet", action="store_true", help="suppress progress output."
    )

    tools = subparsers.add_parser("tools", help="list the tool catalogue")
    tools.add_argument(
        "--category",
        choices=("discovery", "passive", "active", "result"),
        help="only show tools in this category.",
    )
    tools.add_argument(
        "--schema", action="store_true", help="include each tool's JSON schema."
    )
    tools.add_argument("--json", action="store_true", help="emit JSON instead of text.")

    serve = subparsers.add_parser(
        "serve",
        help="run the HTTP API and web UI so scans can be driven from outside",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=_SERVE_EPILOG,
    )
    serve.add_argument(
        "--api-allowed-host",
        action="append",
        default=[],
        metavar="HOST",
        help=(
            "hostname this service may EVER scan (repeatable). Use '*.example.com' for "
            "sub-domains. This is the deployment's authorisation: an API request can only "
            "narrow it, never widen it. Required."
        ),
    )
    serve.add_argument(
        "--api-denied-host",
        action="append",
        default=[],
        metavar="HOST",
        help="hostname to deny even if it matches the allowlist (repeatable).",
    )
    serve.add_argument(
        "--api-allowed-port",
        action="append",
        type=int,
        default=[],
        metavar="PORT",
        help="port the service may contact (repeatable; default 80 and 443).",
    )
    serve.add_argument(
        "--api-allow-private",
        action="store_true",
        help=(
            "authorise private/loopback targets. Needed to scan a local development "
            "server. Only enable this for networks you control: it lets a caller reach "
            "internal services."
        ),
    )
    serve.add_argument(
        "--api-allow-active",
        action="store_true",
        help="authorise active scan tools (CORS preflight, TRACE, HTTP methods, OpenAPI).",
    )
    serve.add_argument(
        "--api-allow-injection",
        action="store_true",
        help="authorise injection probe tools (error-based SQLi/NoSQLi).",
    )
    serve.add_argument(
        "--api-key",
        default=os.environ.get("DAST_SERVICE_KEY", ""),
        help="bearer token clients must present (default: $DAST_SERVICE_KEY).",
    )
    serve.add_argument(
        "--host", default="127.0.0.1", help="bind address (default 127.0.0.1)."
    )
    serve.add_argument("--port", type=int, default=8080, help="bind port (default 8080).")
    serve.add_argument(
        "--runs-dir",
        type=Path,
        default=Path("runs/service"),
        help="where job directories are written (default: ./runs/service).",
    )
    serve.add_argument(
        "--max-concurrent-scans",
        type=int,
        default=1,
        help="how many scans may run at once (default 1; raise with care).",
    )
    serve.add_argument("--api-max-steps", type=int, default=40)
    serve.add_argument("--api-max-tool-calls", type=int, default=120)
    serve.add_argument("--api-max-pages", type=int, default=20)
    serve.add_argument("--api-max-requests", type=int, default=200)
    serve.add_argument("--api-max-rate", type=float, default=10.0)
    serve.add_argument("--api-scan-timeout", type=float, default=600.0)
    serve.add_argument(
        "--api-planner-llm",
        action="store_true",
        help="also offer the AI planner to API callers (needs --api-model and $DAST_API_KEY).",
    )
    serve.add_argument(
        "--api-model",
        default=os.environ.get("DAST_MODEL", ""),
        help="model name for the AI planner (default: $DAST_MODEL).",
    )
    serve.add_argument(
        "--api-model-base-url",
        default=os.environ.get("DAST_BASE_URL", ""),
        help="OpenAI-compatible base URL for the AI planner.",
    )
    serve.add_argument("--reload", action="store_true", help="development auto-reload.")
    return parser


_EPILOG = """\
examples:
  # passive, unauthenticated assessment of your own site
  ai-dast-core scan https://staging.example.com --authorized-by "you@example.com"

  # include an API sub-domain, but never the legacy host
  ai-dast-core scan https://example.com --scope-host api.example.com \\
      --exclude-host legacy.example.com

  # scan a local development server (widens reach to private addresses)
  ai-dast-core scan http://127.0.0.1:8000 --allow-private

  # let an AI planner choose the tools
  DAST_API_KEY=... ai-dast-core scan https://example.com --planner llm --model gpt-4o-mini

  # inspect the tool surface without sending any traffic
  ai-dast-core tools --schema

Authorised use only. This tool sends real requests to the target you name. You are
responsible for having permission to test it.
"""


_SERVE_EPILOG = """\
The service is a scan *job* API: a caller submits a target, polls the job and reads the
report. There is no endpoint that runs a single tool, and a caller cannot widen the scope
the operator authorised.

examples:
  # local use, no API key needed, scanning one host you control
  ai-dast-core serve --api-allowed-host staging.example.com

  # scan a local development server (authorises private addresses)
  ai-dast-core serve --api-allowed-host 127.0.0.1 --api-allowed-port 8000 \\
      --api-allow-private

  # reachable from other machines: an API key is mandatory
  set DAST_SERVICE_KEY=long-random-secret
  ai-dast-core serve --api-allowed-host '*.example.com' --host 0.0.0.0 --port 8080

  # then, from anywhere:
  curl -H "Authorization: Bearer $DAST_SERVICE_KEY" -X POST http://HOST:8080/v1/scans \\
       -H 'Content-Type: application/json' \\
       -d '{"target":"https://staging.example.com","authorized_by":"you@example.com"}'

The web UI is served at http://HOST:PORT/ and the OpenAPI docs at http://HOST:PORT/docs.

Authorised use only. Binding to a non-loopback address requires an API key, and every
host you authorise here is reachable by anyone who holds that key.
"""


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            return _cmd_scan(args)
        if args.command == "tools":
            return _cmd_tools(args)
        if args.command == "serve":
            return _cmd_serve(args)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return EXIT_ERROR
    parser.error("unknown command")
    return EXIT_USAGE


# --------------------------------------------------------------------------- #
# scan
# --------------------------------------------------------------------------- #


def _cmd_scan(args: argparse.Namespace) -> int:
    # 1. Resolve the scope. Everything else is subordinate to this.
    try:
        scope = build_scope_policy(
            args.target,
            extra_hosts=args.scope_host,
            excluded_hosts=args.exclude_host,
            allow_private=args.allow_private,
            authorized_by=args.authorized_by,
            authorization_note=args.authorization_note,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    config = _build_config(args)
    permissions = PermissionSet()
    if args.allow_private:
        permissions.grant(Capability.PRIVATE_NETWORK)
    if args.active or getattr(args, "openapi", False):
        permissions.grant(Capability.ACTIVE_SCAN)
    # Injection probing is its own capability with its own switch: an operator may accept
    # method probing while refusing payload probing, and the reverse.
    if args.injection or args.injection_only:
        permissions.grant(Capability.INJECTION_PROBE)
    permissions.assert_forbidden_absent()

    registry = build_default_registry()
    planner, planner_meta = _build_planner(args, registry)

    _print_banner(scope, config, registry, planner_meta, args)

    run_dir = _run_directory(args)
    run_dir.mkdir(parents=True, exist_ok=True)

    confirmation = ConfirmationGate(
        interactive=sys.stdin.isatty(),
        auto_approve=bool(args.yes),
    )
    runner = ScanRunner(
        registry,
        planner=planner,
        artifact_dir=run_dir / "artifacts",
        permissions=permissions,
        confirmation=confirmation,
        quiet=args.quiet,
    )

    session = runner.create_session(scope, config)
    _write_run_metadata(run_dir, session, planner_meta, registry)

    # 2. Confirm the scope explicitly, interactively, before any traffic.
    if not args.yes and sys.stdin.isatty():
        if not _confirm_scope(scope):
            print("aborted before sending any traffic", file=sys.stderr)
            return EXIT_USAGE

    report = None
    try:
        runner.run(session)
    finally:
        report = build_report(
            session,
            registry,
            planner_name=planner_meta.get("name", ""),
            planner_meta=planner_meta,
        )
        written = write_report(report, run_dir)
        _report_paths(written)

    if args.json and report is not None:
        print(json.dumps(report.model_dump(mode="json"), indent=2, ensure_ascii=False, default=str))

    counts = report.severity_counts
    print()
    print(f"findings: {counts.total} total "
          f"({counts.critical} critical, {counts.high} high, {counts.medium} medium, "
          f"{counts.low} low, {counts.info} info)")
    print(f"report:   {run_dir / 'report.json'}")
    if counts.critical or counts.high:
        return EXIT_FINDINGS
    return EXIT_OK


def _build_config(args: argparse.Namespace) -> ScanConfig:
    return ScanConfig(
        max_steps=max(1, args.max_steps),
        max_tool_calls=max(1, args.max_tool_calls),
        max_pages=max(1, args.max_pages),
        max_requests=max(1, args.max_requests),
        requests_per_second=max(0.1, args.rate),
        request_timeout_s=max(1.0, args.request_timeout),
        tool_timeout_s=max(1.0, args.tool_timeout),
        scan_timeout_s=max(5.0, args.scan_timeout),
        allow_active_tools=bool(args.active or args.injection or args.injection_only or getattr(args, "openapi", False)),
        require_confirmation=not args.yes,
        user_agent=f"ai-dast-core/{__version__} (+authorized-security-testing)",
    )


def _build_planner(args: argparse.Namespace, registry):
    if args.planner == "scripted":
        return ScriptedPlanner(max_pages=min(6, args.max_pages)), {"name": "scripted-recon-v1"}

    api_key = (
        os.environ.get("DAST_API_KEY")
        or os.environ.get("OPENAI_API_KEY")
        or os.environ.get("LLM_API_KEY")
    )
    if not api_key:
        print(
            "error: --planner llm needs an API key in DAST_API_KEY, OPENAI_API_KEY or "
            "LLM_API_KEY. Use --planner scripted to run without one.",
            file=sys.stderr,
        )
        raise SystemExit(EXIT_USAGE)

    planner = LlmPlanner(
        registry,
        model=args.model,
        api_key=api_key,
        base_url=args.base_url or None,
    )
    meta = {
        "name": f"llm:{args.model}",
        "base_url": args.base_url or "(provider default)",
        "temperature": 0.0,
        "tool_choice": "auto",
    }
    return planner, meta


def _print_banner(scope, config: ScanConfig, registry, planner_meta, args) -> None:
    if args.quiet:
        return
    rule = "=" * 72
    print(rule)
    print("ai-dast-core - scope-restricted AI-assisted web DAST scanner")
    print(rule)
    print("Authorised testing only. You are responsible for having permission.")
    print()
    print("Scope (enforced by the harness before every request):")
    print(scope.as_prompt_block())
    if scope.authorized_by:
        print(f"- authorised by: {scope.authorized_by}")
    print()
    print("Budgets:")
    print(
        f"- {config.max_steps} planning steps, {config.max_tool_calls} tool calls, "
        f"{config.max_pages} pages, {config.max_requests} HTTP requests"
    )
    print(
        f"- {config.requests_per_second:g} requests/second, {config.request_timeout_s:g}s per "
        f"request, {config.scan_timeout_s:g}s for the whole scan"
    )
    print()
    print(f"Planner: {planner_meta.get('name', 'unknown')}")
    print("Tools offered to the planner:")
    for name in sorted(tool.name for tool in registry.callable_tools()):
        print(f"- {name}")
    print("Tools that exist but will not run:")
    for tool in registry:
        if not tool.meta.implemented:
            print(f"- {tool.name} (not implemented)")
    print(rule)
    print()


def _confirm_scope(scope) -> bool:
    print("Type 'yes' to confirm you are authorised to test the scope above:")
    try:
        answer = input("> ").strip().lower()
    except EOFError:
        return False
    return answer in {"y", "yes"}


def _run_directory(args: argparse.Namespace) -> Path:
    stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    name = args.run_name.strip() or stamp
    safe = "".join(ch if ch.isalnum() or ch in "-_." else "-" for ch in name)
    return Path(args.output_dir) / safe


def _write_run_metadata(run_dir: Path, session, planner_meta, registry) -> None:
    """Persist what was authorised and what was offered, before the scan runs."""
    metadata = {
        "scan_id": session.scan_id,
        "created_at": session.started_at,
        "version": __version__,
        "scope": session.scope.model_dump(mode="json"),
        "config": session.config.model_dump(mode="json"),
        "planner": planner_meta,
        "tools_offered": sorted(tool.name for tool in registry.callable_tools()),
        "tools_declared_not_implemented": sorted(
            tool.name for tool in registry if not tool.meta.implemented
        ),
    }
    try:
        (run_dir / "run.json").write_text(
            json.dumps(metadata, indent=2, ensure_ascii=False, default=str), encoding="utf-8"
        )
    except OSError:
        pass


def _report_paths(written: dict[str, Path]) -> None:
    for kind, path in written.items():
        print(f"wrote {kind}: {path}")


# --------------------------------------------------------------------------- #
# tools
# --------------------------------------------------------------------------- #


def _cmd_tools(args: argparse.Namespace) -> int:
    registry = build_default_registry()
    if args.category:
        selected = registry.by_category(args.category)
    else:
        selected = list(registry)

    if args.json:
        payload = [
            {
                **tool.to_dict(),
                **({"schema": tool.json_schema()} if args.schema else {}),
            }
            for tool in selected
        ]
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return EXIT_OK

    grouped = tool_categories(registry)
    print(f"ai-dast-core {__version__} - tool catalogue")
    print()
    for category, names in grouped.items():
        if args.category and category != args.category:
            continue
        print(f"{category.upper()} ({len(names)})")
        for name in names:
            tool = registry.get(name)
            marker = "" if tool.meta.implemented else "  [not implemented]"
            print(f"  {name}{marker}")
            print(f"      {tool.meta.summary}")
            if tool.meta.capabilities:
                print(f"      capabilities: {', '.join(tool.meta.capabilities)}")
            if tool.meta.requires_confirmation:
                print("      requires confirmation: yes")
            if args.schema:
                print("      schema:")
                for line in json.dumps(tool.json_schema(), indent=2).splitlines():
                    print(f"        {line}")
        print()
    print("DISCOVERY and PASSIVE tools run by default. ACTIVE tools require explicit opt-in (--active, --injection).")
    return EXIT_OK


# --------------------------------------------------------------------------- #
# serve
# --------------------------------------------------------------------------- #


def _cmd_serve(args: argparse.Namespace) -> int:
    """Start the HTTP API and web UI."""
    from app.service.api import build_app_from_args
    from app.service.config import ScopeRefused  # noqa: F401 - re-exported for callers
    from app.service.config import authorise_request  # noqa: F401

    if not args.api_allowed_host:
        print(
            "error: at least one --api-allowed-host is required. A service that may scan "
            "anything is an open proxy, not a deployment.",
            file=sys.stderr,
        )
        return EXIT_USAGE

    exposed = args.host not in {"127.0.0.1", "localhost", "::1"}
    if exposed and not args.api_key:
        print(
            f"error: binding to {args.host!r} requires --api-key (or $DAST_SERVICE_KEY). "
            "An unauthenticated scanner on a network interface is an open relay for "
            "attacks. Use --host 127.0.0.1 for local use.",
            file=sys.stderr,
        )
        return EXIT_USAGE

    try:
        app = build_app_from_args(
            allowed_hosts=args.api_allowed_host,
            denied_hosts=args.api_denied_host,
            allowed_ports=args.api_allowed_port or None,
            allow_private=args.api_allow_private,
            allow_active=args.api_allow_active,
            allow_injection=args.api_allow_injection,
            api_key=args.api_key,
            bind_host=args.host,
            runs_dir=args.runs_dir,
            max_concurrent_scans=max(1, args.max_concurrent_scans),
            max_steps=max(1, args.api_max_steps),
            max_tool_calls=max(1, args.api_max_tool_calls),
            max_pages=max(1, args.api_max_pages),
            max_requests=max(1, args.api_max_requests),
            max_rate=args.api_max_rate,
            scan_timeout_s=args.api_scan_timeout,
            planner_enabled=args.api_planner_llm,
            llm_model=args.api_model,
            llm_base_url=args.api_model_base_url,
            authorized_by_service="http-api",
            # uvicorn drives the FastAPI lifespan, and the lifespan starts the scan
            # workers. Disabling them here would leave every submitted job queued forever.
            start_workers=True,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    deployment = app.state.service.deployment
    rule = "=" * 72
    print(rule)
    print("ai-dast-core service - HTTP API and web UI")
    print(rule)
    print("Authorised testing only. Every host you authorise below becomes reachable by")
    print("anyone holding the API key.")
    print()
    print(f"Listening on   : http://{args.host}:{args.port}")
    print(f"Web UI         : http://{args.host}:{args.port}/")
    print(f"OpenAPI docs   : http://{args.host}:{args.port}/docs")
    print(f"Deploy profile : {deployment.profile}")
    print(f"Authentication : {'required' if app.state.service.auth_required else 'not required (loopback)'}")
    print()
    print("Scan authorisation (a request can only narrow this):")
    print(f"- allowed hosts : {', '.join(deployment.allowed_hosts)}")
    if deployment.denied_hosts:
        print(f"- denied hosts  : {', '.join(deployment.denied_hosts)}")
    print(f"- allowed ports : {', '.join(str(port) for port in deployment.allowed_ports)}")
    print(f"- private targets: {'ALLOWED' if deployment.allow_private_addresses else 'denied'}")
    print(f"- concurrent    : {deployment.max_concurrent_scans} scan(s) at a time")
    print(f"- reports       : {deployment.runs_dir}")
    print()
    print("Budget ceilings per scan:")
    for key, value in deployment.describe_ceilings().items():
        print(f"- {key}: {value}")
    print()
    print(f"Planners offered: {', '.join(deployment.planners())}")
    if args.api_planner_llm and not deployment.llm_configured():
        print(
            f"  warning: --api-planner-llm was requested but no credential was found in "
            f"{deployment.api_key_ref}; requests for the AI planner will be refused."
        )
    print(rule)
    print()

    try:
        import uvicorn
    except ImportError:
        print(
            "error: uvicorn is not installed. Run: pip install 'uvicorn[standard]'",
            file=sys.stderr,
        )
        return EXIT_ERROR

    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info",
    )
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
