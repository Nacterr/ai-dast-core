"""Discovery tools: open a page and inventory what it exposes.

These four tools are the reconnaissance half of the MVP. All of them are read-only
against the target: ``browser_open`` performs a single navigation, and the three
``extract_*`` tools read a page that has already been captured.

The AI chooses *which* URL to open and which page to inspect. It cannot choose how
the request is made, and it cannot reach a URL the scope guard has not approved.
"""

from __future__ import annotations

from collections import Counter
from urllib.parse import parse_qs, urljoin, urlsplit

from app.models.scan import FormRecord, LinkRecord, ScriptRecord
from app.models.tools import (
    BrowserOpenData,
    BrowserOpenRequest,
    ExtractedForm,
    ExtractedLink,
    ExtractedScript,
    ExtractFormsData,
    ExtractFormsRequest,
    ExtractLinksData,
    ExtractLinksRequest,
    ExtractScriptsData,
    ExtractScriptsRequest,
    FormField,
)
from app.tools.base import ToolOutcome, ok
from app.tools.html_fallback import (
    base_url_of,
    extract_forms_from_html,
    extract_links_from_html,
    extract_scripts_from_html,
)
from app.tools.js_snippets import (
    API_ENDPOINT_PATTERNS,
    ATTRIBUTE_ENDPOINT_PATTERNS,
    EXTRACT_FORMS_JS,
    EXTRACT_LINKS_JS,
    EXTRACT_SCRIPTS_JS,
    SECRET_PATTERNS,
)
from app.tools.shared import clean_text, require_in_scope, require_page, scope_annotate

import re

_MAX_API_ENDPOINTS = 60
_MAX_SECRET_HINTS = 10
_SKIP_SCHEMES = ("mailto:", "tel:", "javascript:", "data:", "blob:", "about:")


# --------------------------------------------------------------------------- #
# browser_open
# --------------------------------------------------------------------------- #


def browser_open(ctx, request: BrowserOpenRequest) -> ToolOutcome:
    """Open one in-scope URL in the controlled browser and capture the page."""
    decision = require_in_scope(ctx, request.url)

    ctx.limits.check_scan_deadline()
    ctx.limits.reserve("pages")

    handle = ctx.browser.open(
        decision.url,
        decision=decision,
        wait_until=request.wait_until,
        wait_ms=request.wait_ms,
        screenshot=request.screenshot,
        full_page=request.full_page,
        disable_javascript=request.disable_javascript,
    )

    effective_final = (
        handle.final_url
        if handle.final_url and handle.final_url.startswith(("http://", "https://"))
        else handle.url
    )
    handle.final_url = effective_final

    # Record the page in the harness's own structured memory, not just the payload:
    # the report must not depend on the LLM having remembered anything.
    ctx.session.surface.pages[handle.page_id] = {
        "url": handle.url,
        "final_url": effective_final,
        "status_code": handle.status_code,
        "title": handle.title,
        "content_type": handle.content_type,
        "html_bytes": handle.html_bytes,
        "html_sha256": handle.html_sha256,
        "redirect_chain": list(handle.redirect_chain),
        "blocked_request_count": len(handle.blocked_requests),
        "javascript_enabled": handle.javascript_enabled,
    }
    ctx.session.surface.target = ctx.session.surface.target or decision.url

    # Seed the attack surface with the URL that was just opened. Without this, the URL the
    # operator actually named never enters the known-URL list unless some other page happens
    # to link to it - so a planner choosing "a discovered URL with parameters" could miss the
    # very endpoint it was pointed at.
    ctx.session.surface.add_link(
        LinkRecord(
            url=effective_final,
            first_seen_page=handle.url,
            in_scope=True,
            scope_reason="the URL this scan opened directly",
            has_query=bool(parse_qs(urlsplit(effective_final).query, keep_blank_values=True)),
            query_keys=sorted(
                parse_qs(urlsplit(effective_final).query, keep_blank_values=True)
            )[:25],
        )
    )

    blocked_counts = Counter(
        _blocked_reason(blocked.reason) for blocked in handle.blocked_requests
    )

    data = BrowserOpenData(
        url=handle.url,
        final_url=effective_final,
        status_code=handle.status_code,
        title=handle.title,
        content_type=handle.content_type,
        html_bytes=handle.html_bytes,
        html_sha256=handle.html_sha256,
        redirect_chain=handle.redirect_chain,
        out_of_scope_redirect=handle.out_of_scope_redirect,
        page_id=handle.page_id,
        screenshot_path=handle.screenshot_path,
        console_errors=handle.console_errors,
        notes=_browser_notes(handle, blocked_counts),
    )

    summary = _browser_summary(data)
    artifacts = [handle.screenshot_path] if handle.screenshot_path else []
    return ok(summary, data, artifacts=artifacts)


def _blocked_reason(reason: str) -> str:
    if reason.startswith("off-scope navigation"):
        return "off-scope navigations blocked"
    if reason.startswith("off-scope fetch") or reason.startswith("off-scope xhr"):
        return "off-scope script requests blocked"
    if reason.startswith("off-scope websocket"):
        return "off-scope websockets blocked"
    if reason.startswith("allowed third-party subresource"):
        return "third-party subresources allowed (disclosed)"
    return "other requests handled"


def _browser_notes(handle, blocked_counts: Counter) -> list[str]:
    notes = list(handle.notes)
    if not handle.javascript_enabled:
        notes.append("page captured with JavaScript disabled; scripts did not execute")
    for reason, count in sorted(blocked_counts.items()):
        notes.append(f"{count} {reason}")
    if handle.out_of_scope_redirect:
        notes.append(
            "the page attempted to navigate outside the authorised scope; "
            "the navigation was blocked"
        )
    return notes


def _browser_summary(data: BrowserOpenData) -> str:
    parts = [f"Opened {data.final_url}"]
    if data.status_code is not None:
        parts.append(f"HTTP {data.status_code}")
    if data.title:
        parts.append(f"title={data.title!r}")
    parts.append(f"{data.html_bytes} bytes of HTML")
    if data.redirect_chain and len(data.redirect_chain) > 1:
        parts.append(f"{len(data.redirect_chain) - 1} redirect(s) followed")
    if data.out_of_scope_redirect:
        parts.append("an out-of-scope redirect was blocked")
    parts.append(f"page_id={data.page_id}")
    return "; ".join(parts) + "."


# --------------------------------------------------------------------------- #
# extract_links
# --------------------------------------------------------------------------- #


def extract_links(ctx, request: ExtractLinksRequest) -> ToolOutcome:
    """Inventory the links reachable from an already-opened page."""
    handle = require_page(ctx, request.page_id)

    base = handle.final_url or handle.url
    raw_links: list[dict[str, str]] = []
    dom_result = ctx.browser.evaluate(handle.page_id, EXTRACT_LINKS_JS)
    used_dom = isinstance(dom_result, dict)

    if used_dom:
        base = _base_from(dom_result, base)
        raw_links = [item for item in dom_result.get("links", []) if isinstance(item, dict)]
    else:
        base = base_url_of(handle.html, base)
        raw_links = [
            {
                "url": item["url"],
                "text": item.get("text", ""),
                "rel": item.get("rel", ""),
                "kind": item.get("kind", "other"),
            }
            for item in extract_links_from_html(handle.html, base)
        ]

    page_origin = _origin(base)
    seen: set[tuple[str, str]] = set()
    links: list[ExtractedLink] = []
    in_scope_count = 0
    total_found = 0

    for item in raw_links:
        url = str(item.get("url") or "").strip()
        if not url or url.lower().startswith(_SKIP_SCHEMES):
            continue
        kind = str(item.get("kind") or "other")
        key = (url, kind)
        if key in seen:
            continue
        seen.add(key)
        total_found += 1

        in_scope, reason = scope_annotate(ctx, url)
        if in_scope:
            in_scope_count += 1
        elif request.same_origin_only:
            # Out of scope *and* the caller wants same-origin only: drop it.
            continue
        elif not request.include_out_of_scope:
            continue

        if request.same_origin_only and _origin(url) != page_origin:
            # Same-origin filtering is about the page origin, not the scan scope.
            continue

        query = parse_qs(urlsplit(url).query, keep_blank_values=True)
        link = ExtractedLink(
            url=url,
            text=clean_text(item.get("text"), 200),
            rel=clean_text(item.get("rel"), 100),
            kind=kind if kind in {"anchor", "form_action", "script_src", "stylesheet", "iframe", "image", "other"} else "other",
            in_scope=in_scope,
            scope_reason=reason,
            has_query=bool(query),
            query_keys=sorted(query)[:25],
        )
        links.append(link)

        # Feed the aggregated attack surface model.
        ctx.session.surface.add_link(
            LinkRecord(
                url=link.url,
                first_seen_page=handle.final_url,
                in_scope=link.in_scope,
                scope_reason=link.scope_reason,
                has_query=link.has_query,
                query_keys=link.query_keys,
            )
        )

    links = links[: request.max_links]
    data = ExtractLinksData(
        page_url=handle.final_url or handle.url,
        total_found=total_found,
        returned=len(links),
        in_scope_count=sum(1 for link in links if link.in_scope),
        links=links,
    )
    summary = (
        f"Found {total_found} unique links on {data.page_url}; "
        f"{data.in_scope_count} of the {data.returned} returned are in scope. "
        f"Extraction used the {'live DOM' if used_dom else 'saved HTML (JavaScript was disabled)'}."
    )
    return ok(summary, data)


# --------------------------------------------------------------------------- #
# extract_forms
# --------------------------------------------------------------------------- #


def extract_forms(ctx, request: ExtractFormsRequest) -> ToolOutcome:
    """Inventory the HTML forms on an already-opened page."""
    handle = require_page(ctx, request.page_id)

    base = handle.final_url or handle.url
    raw_forms: list[dict] = []
    dom_result = ctx.browser.evaluate(handle.page_id, EXTRACT_FORMS_JS)
    used_dom = isinstance(dom_result, dict)

    if used_dom:
        base = _base_from(dom_result, base)
        raw_forms = [item for item in dom_result.get("forms", []) if isinstance(item, dict)]
    else:
        base = base_url_of(handle.html, base)
        raw_forms = list(extract_forms_from_html(handle.html, base))

    forms: list[ExtractedForm] = []
    for raw in raw_forms[: request.max_forms]:
        action = str(raw.get("action") or base)
        in_scope, reason = scope_annotate(ctx, action)

        fields: list[FormField] = []
        for field in raw.get("fields") or []:
            if not isinstance(field, dict):
                continue
            field_type = str(field.get("field_type") or "text")
            if field_type == "hidden" and not request.include_hidden:
                continue
            fields.append(
                FormField(
                    name=clean_text(field.get("name"), 200),
                    field_type=clean_text(field_type, 50),
                    value=clean_text(field.get("value"), 300),
                    required=bool(field.get("required")),
                    placeholder=clean_text(field.get("placeholder"), 200),
                    autocomplete=clean_text(field.get("autocomplete"), 100),
                    options=[clean_text(option, 200) for option in (field.get("options") or [])][:50],
                )
            )

        method = str(raw.get("method") or "get").lower()
        if method not in {"get", "post", "put", "patch", "delete"}:
            method = "other"

        is_login = bool(raw.get("is_login_form"))
        is_upload = bool(raw.get("is_upload_form"))
        has_token = bool(raw.get("has_csrf_token"))

        notes: list[str] = []
        if is_login:
            notes.append("login form: credential handling and lockout policy are untested by this harness")
        if is_upload:
            notes.append("file upload form: upload handling is not exercised by this harness")
        if method in {"post", "put", "patch", "delete"} and not has_token:
            notes.append("state-changing form with no CSRF token field detected")
        if not in_scope:
            notes.append(f"action URL is out of scope: {reason}")

        form = ExtractedForm(
            action=action,
            method=method,
            form_id=clean_text(raw.get("form_id"), 200),
            name=clean_text(raw.get("name"), 200),
            enctype=clean_text(raw.get("enctype"), 200),
            in_scope=in_scope,
            scope_reason=reason if not in_scope else "",
            is_login_form=is_login,
            is_upload_form=is_upload,
            has_csrf_token=has_token,
            fields=fields,
            notes=notes,
        )
        forms.append(form)

        ctx.session.surface.forms.append(
            FormRecord(
                action=form.action,
                method=form.method,
                page_url=handle.final_url,
                in_scope=form.in_scope,
                is_login_form=form.is_login_form,
                is_upload_form=form.is_upload_form,
                has_csrf_token=form.has_csrf_token,
                field_names=[field.name for field in form.fields if field.name][:25],
                hints=notes,
            )
        )

    data = ExtractFormsData(
        page_url=handle.final_url or handle.url,
        total_found=len(raw_forms),
        returned=len(forms),
        forms=forms,
        ready_for_submit=False,
    )
    summary = (
        f"Found {len(raw_forms)} forms on {data.page_url}; returned {len(forms)}. "
        f"{sum(1 for form in forms if form.is_login_form)} look like login forms and "
        f"{sum(1 for form in forms if not form.has_csrf_token and form.method != 'get')} "
        "are state-changing without a detected CSRF token. "
        "This harness never submits forms."
    )
    return ok(summary, data)


# --------------------------------------------------------------------------- #
# extract_scripts
# --------------------------------------------------------------------------- #


def extract_scripts(ctx, request: ExtractScriptsRequest) -> ToolOutcome:
    """Inventory scripts and harvest endpoint-like strings from them."""
    handle = require_page(ctx, request.page_id)

    base = handle.final_url or handle.url
    raw_scripts: list[dict] = []
    attribute_values: list[str] = []
    html_for_scan = handle.html
    dom_result = ctx.browser.evaluate(handle.page_id, EXTRACT_SCRIPTS_JS)
    used_dom = isinstance(dom_result, dict)

    if used_dom:
        base = _base_from(dom_result, base)
        raw_scripts = [item for item in dom_result.get("scripts", []) if isinstance(item, dict)]
        attribute_values = [str(value) for value in dom_result.get("attrs", []) if value]
        html_for_scan = str(dom_result.get("html") or handle.html)
    else:
        base = base_url_of(handle.html, base)
        raw_scripts = list(
            extract_scripts_from_html(
                handle.html, base, max_inline_chars=max(request.max_inline_chars, 500)
            )
        )

    scripts: list[ExtractedScript] = []
    inline_bodies: list[str] = []
    for raw in raw_scripts[: request.max_scripts]:
        kind = str(raw.get("kind") or "inline")
        src = str(raw.get("src") or "").strip()
        body = str(raw.get("text") or "")
        length = int(raw.get("length") or len(body))

        if kind == "inline":
            if not request.include_inline:
                continue
            inline_bodies.append(body)
            digest = _sha256(body)
            scripts.append(
                ExtractedScript(
                    kind="inline",
                    url="",
                    in_scope=True,
                    sha256=digest,
                    length=length,
                    excerpt=body[: request.max_inline_chars],
                )
            )
            # Inline scripts are tracked too, so the surface total reflects reality.
            ctx.session.surface.add_script(
                ScriptRecord(
                    url="",
                    kind="inline",
                    in_scope=True,
                    sha256=digest,
                    length=length,
                    first_seen_page=handle.final_url,
                )
            )
            continue

        absolute = urljoin(base, src)
        in_scope, reason = scope_annotate(ctx, absolute)
        scripts.append(
            ExtractedScript(
                kind="module" if raw.get("is_module") else "external",
                url=absolute,
                in_scope=in_scope,
                scope_reason="" if in_scope else reason,
                sha256="",
                length=0,
                excerpt="",
            )
        )
        ctx.session.surface.add_script(
            ScriptRecord(
                url=absolute,
                kind="external",
                in_scope=in_scope,
                first_seen_page=handle.final_url,
            )
        )

    api_endpoints = _harvest_endpoints(base, inline_bodies, attribute_values, html_for_scan)
    secrets_hints = _harvest_secret_hints(inline_bodies)

    in_scope_endpoints = [url for url in api_endpoints if ctx.scope.check_url(url, resolve=False).allowed]

    surface = ctx.session.surface
    for endpoint in in_scope_endpoints:
        if endpoint not in surface.api_endpoints:
            surface.api_endpoints.append(endpoint)
    surface.api_endpoints = surface.api_endpoints[:200]

    data = ExtractScriptsData(
        page_url=handle.final_url or handle.url,
        total_found=len(raw_scripts),
        returned=len(scripts),
        inline_count=sum(1 for script in scripts if script.kind == "inline"),
        external_count=sum(1 for script in scripts if script.kind != "inline"),
        scripts=scripts,
        api_endpoints=api_endpoints,
        secrets_hints=secrets_hints,
    )
    summary = (
        f"Found {len(raw_scripts)} scripts on {data.page_url} "
        f"({data.inline_count} inline, {data.external_count} external) and "
        f"{len(api_endpoints)} API-looking endpoints "
        f"({len(in_scope_endpoints)} of them in scope). "
        "Excerpts are truncated; endpoint strings are candidates, not confirmed routes."
    )
    if secrets_hints:
        summary += f" {len(secrets_hints)} possible hard-coded credential hint(s) were redacted."
    return ok(summary, data)


def _base_from(dom_result: dict, fallback: str) -> str:
    """Take the document base URI reported by a DOM extraction snippet."""
    candidate = str(dom_result.get("base") or "").strip()
    if not candidate:
        return fallback
    parts = urlsplit(candidate)
    if parts.scheme in {"http", "https"} and parts.netloc:
        return candidate
    return fallback


def _sha256(value: str) -> str:
    import hashlib

    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def _harvest_endpoints(
    base: str, inline_bodies: list[str], attribute_values: list[str], html: str
) -> list[str]:
    """Extract and normalise endpoint candidates from script and markup text."""
    corpus = "\n".join(inline_bodies)
    candidates: list[str] = []

    for pattern in API_ENDPOINT_PATTERNS:
        for match in re.finditer(pattern, corpus, re.IGNORECASE):
            candidates.append(match.group(1))

    for pattern in ATTRIBUTE_ENDPOINT_PATTERNS:
        for match in re.finditer(pattern, html, re.IGNORECASE):
            candidates.append(match.group(1))
    candidates.extend(attribute_values)

    normalized: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        value = candidate.strip().strip("\"'`")
        if not value or len(value) > 300:
            continue
        if value.startswith(_SKIP_SCHEMES) or value.startswith("#"):
            continue
        if value.startswith("//"):
            value = f"https:{value}"
        absolute = urljoin(base, value)
        parts = urlsplit(absolute)
        if parts.scheme not in {"http", "https"} or not parts.netloc:
            continue
        if parts.path in {"", "/"} and not parts.query:
            continue
        if absolute in seen:
            continue
        seen.add(absolute)
        normalized.append(absolute)
        if len(normalized) >= _MAX_API_ENDPOINTS:
            break
    return normalized


def _harvest_secret_hints(inline_bodies: list[str]) -> list[str]:
    """Report *that* a credential-looking literal exists, never the value."""
    hints: list[str] = []
    corpus = "\n".join(inline_bodies)
    for pattern, description in SECRET_PATTERNS:
        if re.search(pattern, corpus):
            hints.append(description)
            if len(hints) >= _MAX_SECRET_HINTS:
                break
    return hints


def _origin(url: str) -> str:
    try:
        parts = urlsplit(url)
    except ValueError:
        return ""
    if not parts.scheme or not parts.hostname:
        return ""
    port = f":{parts.port}" if parts.port else ""
    return f"{parts.scheme.lower()}://{parts.hostname.lower()}{port}"
