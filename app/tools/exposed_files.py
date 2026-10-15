"""``analyze_exposed_files``: probe a fixed path catalogue for exposed files.

This is the first tool with a **path list**, so it needs more guardrails than the others,
and the guards are the interesting part:

1. **The paths are harness constants.** The AI chooses an origin and, optionally, which
   *categories* to probe. It cannot name a path. That is what stops this becoming an
   arbitrary content-discovery scanner.
2. **Its own budget.** ``max_exposed_file_checks`` is separate from ``max_requests``, so a
   planner cannot spend the whole request budget on path guessing and starve the passive
   checks that actually produce findings.
3. **Soft-404 calibration.** Many servers answer ``200`` for every path. Before trusting any
   status code, the tool probes a control path that cannot exist. If that also returns
   ``200``, status codes are treated as meaningless and every hit must additionally pass a
   **content signature** check.
4. **Never stores file content.** A hit is recorded as path, status, content type, length
   and severity. The excerpt is a *redacted* signature match — for a ``.env`` that is
   ``KEY=VALUE pattern present``, never the secret.

A hit is a factual observation ("this path returned a dotenv-shaped body"). Whether it
matters depends on what is in the file, which this tool deliberately does not read out.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

from app.models.finding import Confidence, Evidence, Finding, FindingCategory, Severity
from app.models.tools import (
    AnalyzeExposedFilesData,
    AnalyzeExposedFilesRequest,
    ExposedFileCheck,
)
from app.policy.limits import LimitExceeded
from app.tools.base import ToolOutcome, ok
from app.tools.findings import make_finding
from app.tools.http_client import EgressDenied, HttpExchange
from app.tools.shared import require_in_scope

# A path that must not exist. Probing it reveals whether the server lies about 200s.
CONTROL_PATH = "/.well-known/ai-dast-core-nonexistent-control-path-9f3a2b"

MAX_BODY_BYTES = 20_000
MAX_EXCERPT = 400

# How many extra GET requests are allowed to confirm HEAD candidates. Confirmation is what
# actually prevents false positives on a soft-404 server, so this is generous: it should not
# be the binding constraint. The shared request budget is the real limit, and it is what
# stops the sweep from running away.
MAX_EXTRA_GETS = 60


@dataclass(frozen=True)
class PathSpec:
    """One catalogue entry."""

    path: str
    category: str
    severity: str
    description: str
    recommendation: str
    # Content signatures that prove the path is really serving the thing it claims to.
    # A hit is only believed once one of these matches, except on a server that correctly
    # returns 404 for unknown paths.
    signatures: tuple[re.Pattern[str], ...] = ()
    # Signatures that prove the response is a *generic error page*, which means "not
    # exposed" even though the status code looked promising.
    negative_signatures: tuple[re.Pattern[str], ...] = ()
    # Content types that confirm the file type. Needed for binary formats such as archives,
    # where there is no reliable text signature in the decoded body.
    content_types: tuple[str, ...] = ()
    # Max acceptable body size for a believable hit. A 2 MB HTML page is not a .env.
    max_bytes: int = MAX_BODY_BYTES

    @property
    def confirmable(self) -> bool:
        """Whether this entry has any way to confirm the file type beyond a status code."""
        return bool(self.signatures or self.content_types)


def _rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


_GENERIC_ERROR = (
    _rx(r"<(?:!doctype\s+)?html"),
    _rx(r"\b(?:404|403)\b.{0,40}\b(?:not found|forbidden|error)\b"),
    _rx(r"\b(?:page|file)\s+not\s+found\b"),
    _rx(r"\bnginx\b.{0,80}\b(?:404|error)\b"),
    _rx(r"\bapache\b.{0,120}\b(?:not found|error)\b"),
)

# The catalogue. Severity reflects the impact of the file being publicly readable, not the
# probability that it is.
PATH_CATALOGUE: tuple[PathSpec, ...] = (
    # --- version control ------------------------------------------------- #
    PathSpec(
        path="/.git/HEAD",
        category="vcs",
        severity="high",
        description=(
            "The Git repository metadata is reachable from the web root. `/.git/HEAD` is the "
            "cheapest way to confirm it, and the object store it points at usually allows "
            "the entire source history to be reconstructed."
        ),
        recommendation=(
            "Block `/.git/` at the web server or reverse proxy, and deploy by exporting an "
            "artefact rather than leaving a working copy in the document root."
        ),
        signatures=(_rx(r"^ref:\s+refs/"), _rx(r"^[0-9a-f]{40}\s*$")),
    ),
    PathSpec(
        path="/.git/config",
        category="vcs",
        severity="high",
        description=(
            "The Git configuration is readable. It often contains remote URLs, and "
            "occasionally credentials embedded in those URLs."
        ),
        recommendation="Block `/.git/` at the web server.",
        signatures=(_rx(r"\[core\]"), _rx(r"\[remote\b"), _rx(r"repositoryformatversion")),
    ),
    PathSpec(
        path="/.svn/entries",
        category="vcs",
        severity="medium",
        description="Subversion working-copy metadata is reachable.",
        recommendation="Block `/.svn/` at the web server and deploy from an export.",
        signatures=(_rx(r"^\d+\s*$", ), _rx(r"dir\s*\n"), _rx(r"<wc-entries")),
    ),
    PathSpec(
        path="/.hg/requires",
        category="vcs",
        severity="medium",
        description="Mercurial repository metadata is reachable.",
        recommendation="Block `/.hg/` at the web server.",
        signatures=(_rx(r"revlog"), _rx(r"store")),
    ),
    # --- configuration ---------------------------------------------------- #
    PathSpec(
        path="/.env",
        category="config",
        severity="critical",
        description=(
            "A dotenv file is publicly readable. These conventionally hold database "
            "credentials, API keys and application secrets, so this is usually a direct "
            "path to full compromise."
        ),
        recommendation=(
            "Remove the file from the web root immediately, rotate every secret it "
            "contained, and add a deny rule so it cannot be served again."
        ),
        signatures=(
            _rx(r"^[A-Z][A-Z0-9_]{2,}\s*="),
            _rx(r"APP_KEY\s*="),
            _rx(r"DB_PASSWORD\s*="),
            _rx(r"SECRET\s*="),
        ),
        max_bytes=20_000,
    ),
    PathSpec(
        path="/.env.local",
        category="config",
        severity="critical",
        description="A local dotenv override is publicly readable.",
        recommendation="Remove it from the web root and rotate every secret it contained.",
        signatures=(_rx(r"^[A-Z][A-Z0-9_]{2,}\s*="),),
        max_bytes=20_000,
    ),
    PathSpec(
        path="/config.php.bak",
        category="config",
        severity="high",
        description="A backup copy of a PHP configuration file is readable as plain text.",
        recommendation="Delete the backup and add a rule denying `*.bak` at the web server.",
        signatures=(_rx(r"<\?php"), _rx(r"\$config"), _rx(r"password")),
    ),
    PathSpec(
        path="/wp-config.php.bak",
        category="config",
        severity="critical",
        description=(
            "A backup of the WordPress configuration is readable. It normally contains the "
            "database name, user and password in plain text."
        ),
        recommendation="Delete the backup, rotate the database credentials, and deny `*.bak`.",
        signatures=(_rx(r"DB_PASSWORD"), _rx(r"define\s*\(")),
    ),
    PathSpec(
        path="/.aws/credentials",
        category="config",
        severity="critical",
        description="An AWS credentials file is publicly readable.",
        recommendation=(
            "Remove the file, rotate the exposed access key immediately, and review CloudTrail "
            "for use of it."
        ),
        signatures=(_rx(r"\[default\]"), _rx(r"aws_access_key_id")),
        max_bytes=10_000,
    ),
    PathSpec(
        path="/.docker/config.json",
        category="config",
        severity="high",
        description="A Docker client configuration is readable, and may contain registry auth tokens.",
        recommendation="Remove the file and rotate any registry credentials it held.",
        signatures=(_rx(r"auths"), _rx(r"credsStore")),
    ),
    # --- backups ---------------------------------------------------------- #
    PathSpec(
        path="/backup.zip",
        category="backup",
        severity="high",
        description="A backup archive is downloadable from the web root.",
        recommendation=(
            "Remove it from the web root, store backups outside the served tree, and require "
            "authentication for any restore interface."
        ),
        # An archive is binary, so there is no text signature to match. The content type is
        # the only evidence available without downloading it, and downloading an unknown
        # archive to inspect it is not something this harness does.
        content_types=("application/zip", "application/x-zip", "application/x-zip-compressed"),
        negative_signatures=_GENERIC_ERROR,
    ),
    PathSpec(
        path="/backup.tar.gz",
        category="backup",
        severity="high",
        description="A backup archive is downloadable from the web root.",
        recommendation="Remove it from the web root and store backups outside the served tree.",
        content_types=("application/gzip", "application/x-gzip", "application/x-tar"),
        negative_signatures=_GENERIC_ERROR,
    ),
    PathSpec(
        path="/database.sql",
        category="backup",
        severity="critical",
        description="A database dump is downloadable from the web root.",
        recommendation=(
            "Remove the dump, treat all data it contained as disclosed, and store dumps "
            "outside the served tree."
        ),
        signatures=(_rx(r"CREATE\s+TABLE"), _rx(r"INSERT\s+INTO"), _rx(r"mysqldump")),
    ),
    PathSpec(
        path="/dump.sql",
        category="backup",
        severity="critical",
        description="A database dump is downloadable from the web root.",
        recommendation="Remove the dump and store dumps outside the served tree.",
        signatures=(_rx(r"CREATE\s+TABLE"), _rx(r"INSERT\s+INTO")),
    ),
    # --- server information ----------------------------------------------- #
    PathSpec(
        path="/server-status",
        category="server-info",
        severity="medium",
        description=(
            "The Apache mod_status page is exposed. It lists current requests, client IPs "
            "and internal URLs."
        ),
        recommendation=(
            "Restrict `/server-status` to localhost, or disable mod_status where it is not "
            "needed."
        ),
        signatures=(_rx(r"Apache Server Status"), _rx(r"Server Version")),
    ),
    PathSpec(
        path="/phpinfo.php",
        category="server-info",
        severity="high",
        description=(
            "A phpinfo() page is exposed. It discloses PHP version, loaded modules, "
            "environment variables and often credentials in `$_SERVER`."
        ),
        recommendation="Delete the file. Never ship phpinfo() to production.",
        signatures=(_rx(r"phpinfo\(\)"), _rx(r"PHP Version"), _rx(r"<title>phpinfo")),
    ),
    PathSpec(
        path="/actuator/env",
        category="server-info",
        severity="high",
        description=(
            "A Spring Boot actuator environment endpoint is exposed. It returns resolved "
            "configuration properties, frequently including datasource credentials."
        ),
        recommendation=(
            "Disable or authenticate the actuator endpoints, and never expose `/actuator/env` "
            "publicly."
        ),
        signatures=(_rx(r"propertySources"), _rx(r"activeProfiles")),
    ),
    PathSpec(
        path="/actuator/health",
        category="server-info",
        severity="low",
        description="A Spring Boot actuator health endpoint is exposed.",
        recommendation=(
            "Expose only the health details you need, and keep the rest of the actuator "
            "surface off the public internet."
        ),
        signatures=(_rx(r'"status"\s*:'), _rx(r'"components"')),
    ),
    PathSpec(
        path="/debug/vars",
        category="server-info",
        severity="medium",
        description="A Go expvar debug endpoint is exposed, disclosing runtime counters.",
        recommendation="Register expvar handlers on an internal listener only.",
        signatures=(_rx(r'"cmdline"'), _rx(r'"memstats"')),
    ),
    PathSpec(
        path="/metrics",
        category="server-info",
        severity="low",
        description=(
            "A Prometheus metrics endpoint is publicly readable. It discloses internal "
            "service names, route shapes and traffic volumes."
        ),
        recommendation="Restrict `/metrics` to the monitoring network.",
        signatures=(_rx(r"^#\s+HELP\s+"), _rx(r"^#\s+TYPE\s+")),
    ),
    # --- editor and IDE leftovers ----------------------------------------- #
    PathSpec(
        path="/.DS_Store",
        category="editor",
        severity="low",
        description=(
            "A macOS .DS_Store file is readable. It leaks the names of files and directories "
            "in the folder, which helps an attacker enumerate the deployment."
        ),
        recommendation="Delete it, add it to the deploy exclusion list, and deny the filename.",
        # A real .DS_Store is a binary plist beginning with the Bud1 magic. Servers that
        # return HTML or JSON here are answering from a catch-all rule, not serving the file.
        signatures=(
            _rx(r"Bud1"),
            _rx(r"\x00\x00\x00\x01Bud1"),
            _rx(r"bplist00"),
        ),
        max_bytes=100_000,
    ),
    PathSpec(
        path="/.vscode/settings.json",
        category="editor",
        severity="low",
        description="An editor settings file is readable and may disclose local paths or secrets.",
        recommendation="Exclude editor directories from deployment.",
        signatures=(_rx(r"\{"), _rx(r"settings")),
    ),
    PathSpec(
        path="/.idea/workspace.xml",
        category="editor",
        severity="low",
        description="A JetBrains workspace file is readable and may disclose local paths.",
        recommendation="Exclude IDE directories from deployment.",
        signatures=(_rx(r"<project"), _rx(r"workspace")),
    ),
    # --- CI ---------------------------------------------------------------- #
    PathSpec(
        path="/.gitlab-ci.yml",
        category="ci",
        severity="low",
        description=(
            "The CI pipeline definition is readable. It discloses build steps, registry "
            "hosts and sometimes variable names."
        ),
        recommendation="Serve the repository root from a static host only where intended.",
        signatures=(_rx(r"^stages\s*:"), _rx(r"^[a-z0-9_-]+\s*:\s*$", ), _rx(r"script\s*:")),
    ),
    PathSpec(
        path="/.github/workflows",
        category="ci",
        severity="info",
        description="The GitHub Actions workflow directory is listed.",
        recommendation="Confirm this is intentional; workflow files can disclose deployment topology.",
        negative_signatures=_GENERIC_ERROR,
    ),
    # --- documentation ----------------------------------------------------- #
    PathSpec(
        path="/README.md",
        category="docs",
        severity="info",
        description=(
            "The project README is served from the web root. Usually harmless, but it can "
            "disclose internal setup details or default credentials."
        ),
        recommendation="Serve documentation from somewhere other than the deploy root.",
        # Markdown served as markdown. A catch-all HTML page will not match this.
        signatures=(
            _rx(r"^#\s+\S"),
            _rx(r"^##\s+\S", ),
            _rx(r"```"),
        ),
    ),
    PathSpec(
        path="/CHANGELOG.md",
        category="docs",
        severity="info",
        description="The changelog is served, disclosing the version history of the application.",
        recommendation="Serve documentation from somewhere other than the deploy root.",
        signatures=(_rx(r"^#\s+\S"), _rx(r"(?im)^##\s*\[?[\d.]+\]?")),
    ),
)

CATALOGUE_BY_PATH: dict[str, PathSpec] = {spec.path: spec for spec in PATH_CATALOGUE}
ALL_CATEGORIES: tuple[str, ...] = (
    "vcs",
    "config",
    "backup",
    "server-info",
    "editor",
    "ci",
    "docs",
)

# Used when the caller names no categories: the highest-signal subset, kept small so the
# default sweep stays cheap.
DEFAULT_CATEGORIES: tuple[str, ...] = ("vcs", "config", "server-info")


def analyze_exposed_files(ctx, request: AnalyzeExposedFilesRequest) -> ToolOutcome:
    """Probe the catalogue for exposed files and raise findings for real hits."""
    decision = require_in_scope(ctx, request.url)
    origin = _origin_of(decision.url)

    categories = tuple(request.categories) or DEFAULT_CATEGORIES
    specs = [spec for spec in PATH_CATALOGUE if spec.category in categories]
    if not specs:
        return ok(
            f"No catalogue paths match the requested categories "
            f"({', '.join(categories)}); nothing was probed.",
            AnalyzeExposedFilesData(origin=origin, categories_probed=list(categories)),
        )
    specs = specs[: request.max_paths]

    checks: list[ExposedFileCheck] = []
    notes: list[str] = []

    # Step 1: calibrate. A server that answers 200 to a path that cannot exist tells us
    # nothing with status codes alone.
    baseline_status, soft_404 = _calibrate(ctx, origin, notes)

    budget_exhausted = False
    skipped = 0
    extra_gets = 0

    for spec in specs:
        url = urljoin(origin + "/", spec.path.lstrip("/"))
        if not ctx.scope.check_url(url, resolve=False).allowed:
            skipped += 1
            continue

        try:
            ctx.limits.reserve("exposed_file_checks")
        except LimitExceeded:
            budget_exhausted = True
            skipped += len(specs) - len(checks) - skipped
            break

        try:
            exchange = ctx.http.request(url, method="HEAD", follow_redirects=False, read_body=False)
        except EgressDenied as exc:
            notes.append(f"{spec.path} refused by the scope guard: {exc.reason}")
            skipped += 1
            continue

        check = _assess(spec, url, exchange, soft_404=soft_404)

        # A candidate needs the body inspected whenever the status code alone cannot be
        # trusted: on a soft-404 server, or when we have signatures that should confirm the
        # file type but have not been given a chance to match yet.
        needs_body = (
            check.status_code == 200
            and not check.verified
            and (soft_404 or bool(spec.signatures))
            and extra_gets < MAX_EXTRA_GETS
        )
        if needs_body:
            extra_gets += 1
            try:
                # The request budget is charged by SafeHttpClient, not here.
                body_exchange = ctx.http.request(
                    url, method="GET", follow_redirects=False, read_body=True
                )
            except (LimitExceeded, EgressDenied):
                body_exchange = None
            if body_exchange is not None:
                check = _assess(
                    spec, url, body_exchange, method="GET", prior=check, soft_404=soft_404
                )

        checks.append(check)

    exposed = [check for check in checks if check.exposed]
    findings = [_finding_for(check, origin) for check in exposed]

    if budget_exhausted:
        notes.append(
            "The exposed-file probe budget for this scan ran out; the sweep is partial. "
            "Raise --max-exposed-file-checks to cover the whole catalogue."
        )

    # Order the detail list most-important-first so that a payload-budget truncation drops
    # the uninteresting "not found" rows rather than the exposures themselves.
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    ordered_checks = sorted(
        checks, key=lambda check: (not check.exposed, severity_rank.get(check.severity, 5))
    )

    data = AnalyzeExposedFilesData(
        origin=origin,
        probed=len(checks),
        skipped=skipped,
        exposed_count=len(exposed),
        baseline_status=baseline_status,
        soft_404_detected=soft_404,
        categories_probed=list(categories),
        checks=ordered_checks,
        notes=notes,
    )

    if soft_404:
        notes_summary = (
            " The server answers 200 for nonexistent paths, so every hit was verified by "
            "content signature rather than by status code."
        )
    else:
        notes_summary = ""

    if not exposed:
        summary = (
            f"Probed {len(checks)} well-known path(s) on {origin} across "
            f"{', '.join(categories)}; none returned real content. "
            f"This is not evidence that the deployment is clean - only that these "
            f"{len(checks)} paths are not publicly readable.{notes_summary}"
        )
    else:
        by_severity: dict[str, int] = {}
        for check in exposed:
            by_severity[check.severity] = by_severity.get(check.severity, 0) + 1
        rendered = ", ".join(f"{count} {name}" for name, count in sorted(by_severity.items()))
        summary = (
            f"Probed {len(checks)} well-known path(s) on {origin}; {len(exposed)} returned real "
            f"content ({rendered}): "
            + ", ".join(check.path for check in exposed[:8])
            + "."
            + notes_summary
        )
    return ok(
        summary,
        data,
        findings=findings,
        notes=notes,
        priority_fields=("checks",),
        # Prose that can be dropped from an item before any item is dropped entirely. The
        # recommendation also travels on the finding, so nothing actionable is lost.
        droppable_fields=("notes", "description", "recommendation"),
    )


# --------------------------------------------------------------------------- #
# Probing
# --------------------------------------------------------------------------- #


def _calibrate(ctx, origin: str, notes: list[str]) -> tuple[int | None, bool]:
    """Probe a path that cannot exist, to learn whether 200 means anything here."""
    control_url = urljoin(origin + "/", CONTROL_PATH.lstrip("/"))
    if not ctx.scope.check_url(control_url, resolve=False).allowed:
        return None, False
    try:
        # The request budget is charged by SafeHttpClient, not here.
        exchange = ctx.http.request(
            control_url, method="HEAD", follow_redirects=False, read_body=False
        )
    except (LimitExceeded, EgressDenied):
        return None, False

    status = exchange.status_code
    if status == 200:
        notes.append(
            f"The server returned 200 for a path that cannot exist ({CONTROL_PATH}), so "
            "status codes alone are not trustworthy here. Hits were confirmed by content "
            "signature instead."
        )
        return status, True
    return status, False


def _assess(
    spec: PathSpec,
    url: str,
    exchange: HttpExchange,
    *,
    method: str = "HEAD",
    prior: ExposedFileCheck | None = None,
    soft_404: bool = False,
) -> ExposedFileCheck:
    """Decide whether one response represents a real exposure.

    The decision rule is deliberately asymmetric, because a false "your .env is public" is
    far more damaging than a missed path:

    * A status code alone is **never** sufficient when the server answers 200 for paths that
      do not exist (``soft_404``), or when we have signatures that could confirm the file
      type. In that case the body must be inspected and must match.
    * A body that matches a *generic error page* means "not exposed", whatever the status.
    * A body that does not match any signature for the declared file type means "not
      exposed", even on a 200.
    """
    status = exchange.status_code
    headers = exchange.headers or {}
    content_type = str(headers.get("content-type", ""))[:200]
    raw_length = headers.get("content-length")
    try:
        content_length = int(raw_length) if raw_length is not None else None
    except (TypeError, ValueError):
        content_length = None

    notes: list[str] = list(prior.notes) if prior else []
    body = exchange.body_prefix if method == "GET" else ""

    exposed = False
    verified = False
    confidence = "low"
    excerpt = ""

    if status not in {200, 206}:
        notes.append(f"HTTP {status} - not served")
    elif content_length is not None and content_length > spec.max_bytes:
        notes.append(
            f"HTTP {status} but {content_length} bytes, far larger than {spec.path} should be; "
            "treated as a catch-all response rather than the file"
        )
    elif spec.negative_signatures and body and _matches_any(spec.negative_signatures, body):
        notes.append(
            "HTTP 200 but the body is a generic error or index page, not the file"
        )
    elif body:
        # We have content. A signature or an archive content type decides.
        positive = _matches_any(spec.signatures, body) if spec.signatures else False
        type_confirms = _content_type_matches(spec, content_type)
        if spec.signatures and not positive and not type_confirms:
            notes.append(
                "HTTP 200 but the body did not match any signature for this file type, so it "
                "is a catch-all response rather than the file"
            )
        elif soft_404 and not positive and not type_confirms:
            # Nothing confirms the file type and the server lies about 200s.
            notes.append(
                "HTTP 200 on a server that returns 200 for nonexistent paths, and nothing in "
                "the response confirms this file type; not reported as exposed"
            )
        else:
            exposed = True
            verified = True
            confidence = "high"
            if positive:
                for pattern in spec.signatures:
                    match = pattern.search(body)
                    if match:
                        excerpt = _redact(match.group(0), spec)
                        break
            elif type_confirms:
                excerpt = f"content-type: {content_type}"
            notes.append("Body inspected and matched the expected shape for this file type")
    else:
        # No body was returned by HEAD. Only trust the status when the server does not
        # answer 200 for everything.
        if method == "HEAD" and not soft_404:
            exposed = True
            verified = False
            confidence = "low"
            notes.append(
                f"HTTP {status} on HEAD, and the server correctly returns 404 for paths that "
                "do not exist; content not inspected, so this is a candidate rather than a "
                "confirmed exposure"
            )
        else:
            notes.append(
                "No body was available to inspect, and a 200 on this server does not by "
                "itself indicate the file exists"
            )

    return ExposedFileCheck(
        path=spec.path,
        url=url,
        method=method,
        status_code=status,
        content_type=content_type,
        content_length=content_length,
        exposed=exposed,
        verified=verified,
        severity=spec.severity,  # type: ignore[arg-type]
        confidence=confidence,  # type: ignore[arg-type]
        description=spec.description,
        recommendation=spec.recommendation,
        evidence_excerpt=excerpt[:MAX_EXCERPT],
        notes=notes,
    )


def _matches_any(patterns: tuple[re.Pattern[str], ...], body: str) -> bool:
    return any(pattern.search(body) for pattern in patterns)


def _content_type_matches(spec: PathSpec, content_type: str) -> bool:
    """Whether the response declares one of the content types this entry expects."""
    if not spec.content_types:
        return False
    declared = content_type.split(";", 1)[0].strip().lower()
    return declared in spec.content_types


def _redact(matched: str, spec: PathSpec) -> str:
    """Never echo a secret: report the *shape* of the match, not its value.

    A dotenv hit becomes ``KEY=VALUE pattern present (length 42)`` rather than the
    credential itself. The report needs to prove the file is a dotenv, not to leak it.
    """
    cleaned = " ".join(matched.split())
    if spec.category == "config" and "=" in cleaned:
        key = cleaned.split("=", 1)[0]
        return f"{key}=<redacted> (matched a credential-shaped assignment)"
    if len(cleaned) > 80:
        return cleaned[:77] + "..."
    return cleaned


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #


def _finding_for(check: ExposedFileCheck, origin: str) -> Finding:
    """Turn a confirmed exposure into a finding with traceable evidence."""
    from app.models.finding import Finding as FindingModel

    host = FindingModel.host_of(origin)
    confidence = (
        Confidence.HIGH
        if check.confidence == "high"
        else Confidence.MEDIUM
        if check.confidence == "medium"
        else Confidence.LOW
    )

    title = f"Publicly readable file: {check.path}"
    location = f"file:{check.path}"

    return make_finding(
        title=title,
        category=FindingCategory.INFORMATION_DISCLOSURE,
        severity=Severity(check.severity),
        confidence=confidence,
        description=check.description,
        impact=_impact_for(check),
        recommendation=check.recommendation,
        url=check.url,
        location=location,
        owasp="A05:2021 - Security Misconfiguration",
        cwe=_cwe_for(check.path),
        evidence=[
            Evidence(
                tool="analyze_exposed_files",
                url=check.url,
                location=location,
                observed=(
                    f"HTTP {check.status_code}, content-type={check.content_type or 'unknown'}, "
                    f"{check.content_length if check.content_length is not None else 'unknown'} bytes"
                    + (f", signature: {check.evidence_excerpt}" if check.evidence_excerpt else "")
                ),
                expected="HTTP 404, or an authentication challenge",
                raw={
                    "path": check.path,
                    "status_code": check.status_code,
                    "confidence": check.confidence,
                    "notes": check.notes,
                },
            )
        ],
        references=[
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/"
        ],
        source_tools=["analyze_exposed_files"],
        tags=["configuration", "disclosure", check.path.split("/")[1].replace(".", "") or "root"],
    )


def _impact_for(check: ExposedFileCheck) -> str:
    if check.path.startswith("/.git"):
        return (
            "The full source history is usually reconstructable from this, including "
            "credentials that were removed from the current revision."
        )
    if check.path in {"/.env", "/.env.local", "/.aws/credentials", "/wp-config.php.bak"}:
        return (
            "The file is designed to hold secrets. Treat every credential it could contain as "
            "disclosed until proven otherwise, and rotate them."
        )
    if check.path in {"/database.sql", "/dump.sql"}:
        return "The entire database contents are downloadable by anyone."
    if check.path in {"/backup.zip", "/backup.tar.gz"}:
        return "A complete copy of the application - source, and often configuration - is downloadable."
    if check.path in {"/server-status", "/actuator/env", "/phpinfo.php", "/debug/vars"}:
        return (
            "Internal configuration, paths and possibly credentials are disclosed, which "
            "shortens an attacker's reconnaissance considerably."
        )
    return (
        "The file discloses information about the deployment that was not meant to be public."
    )


def _cwe_for(path: str) -> str:
    if path.startswith("/.git") or path.startswith("/.svn") or path.startswith("/.hg"):
        return "CWE-527"
    if path in {"/.env", "/.env.local", "/.aws/credentials"}:
        return "CWE-538"
    if path in {"/backup.zip", "/backup.tar.gz", "/database.sql", "/dump.sql"}:
        return "CWE-530"
    return "CWE-538"


def _origin_of(url: str) -> str:
    parts = urlsplit(url)
    port = f":{parts.port}" if parts.port else ""
    return f"{parts.scheme.lower()}://{(parts.hostname or '').lower()}{port}"


__all__ = [
    "ALL_CATEGORIES",
    "CATALOGUE_BY_PATH",
    "CONTROL_PATH",
    "DEFAULT_CATEGORIES",
    "PATH_CATALOGUE",
    "PathSpec",
    "analyze_exposed_files",
]
