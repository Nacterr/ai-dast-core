"""Regex/HTML-parser fallbacks for pages captured without a live DOM.

When a page is opened with JavaScript disabled its live Playwright page is closed
immediately, so the extractors must work from the saved HTML string. These helpers
use the standard library only, which keeps them fast and free of parsing surprises
from malformed real-world markup.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from app.tools.js_snippets import _LINK_PATTERNS

_ANCHOR_RE = re.compile(_LINK_PATTERNS[0][0], re.IGNORECASE | re.DOTALL)
_HTML_TAG_RE = re.compile(r"<[^>]+>")


def strip_tags(value: str) -> str:
    return _HTML_TAG_RE.sub("", value)


def extract_links_from_html(html: str, base_url: str) -> list[dict[str, str]]:
    """Return ``[{url, text, rel, kind}]`` resolved against ``base_url``."""
    found: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    for pattern, kind in _LINK_PATTERNS:
        for match in re.finditer(pattern, html, re.IGNORECASE | re.DOTALL):
            raw = (match.group(1) or "").strip()
            if not raw or raw.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
                continue
            absolute = urljoin(base_url, raw)
            if not absolute.lower().startswith(("http://", "https://")):
                continue
            text = ""
            if kind == "anchor" and match.lastindex and match.lastindex >= 2:
                text = strip_tags(match.group(2) or "")
            key = (absolute, kind)
            if key in seen:
                continue
            seen.add(key)
            found.append({"url": absolute, "text": text, "rel": "", "kind": kind})
    return found


class _FormParser(HTMLParser):
    """Minimal form/field collector for the no-JavaScript path."""

    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.forms: list[dict[str, object]] = []
        self._current: dict[str, object] | None = None
        self._seen_ids: set[int] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {key.lower(): (value or "") for key, value in attrs}

        if tag == "form":
            if id(self) in self._seen_ids:  # pragma: no cover - defensive
                return
            self._current = {
                "action": urljoin(self.base_url, attributes.get("action") or self.base_url),
                "method": (attributes.get("method") or "get").lower(),
                "form_id": attributes.get("id", "")[:200],
                "name": attributes.get("name", "")[:200],
                "enctype": (attributes.get("enctype") or "").lower(),
                "is_login_form": False,
                "is_upload_form": "multipart/form-data" in (attributes.get("enctype") or "").lower(),
                "has_csrf_token": False,
                "fields": [],
            }
            return

        if tag == "input" and self._current is not None:
            field_type = (attributes.get("type") or "text").lower()
            if field_type in {"submit", "button", "reset", "image"}:
                return
            name = attributes.get("name", "")
            if field_type == "password":
                self._current["is_login_form"] = True
            if field_type == "file":
                self._current["is_upload_form"] = True
            if field_type == "hidden" and re.search(
                r"(csrf|xsrf|authenticity|nonce|token)", name, re.IGNORECASE
            ):
                self._current["has_csrf_token"] = True
            self._append_field(
                {
                    "name": name[:200],
                    "field_type": field_type,
                    "value": attributes.get("value", "")[:300],
                    "required": "required" in attributes,
                    "placeholder": attributes.get("placeholder", "")[:200],
                    "autocomplete": attributes.get("autocomplete", "")[:100],
                    "options": [],
                }
            )
            return

        if tag in {"textarea", "select"} and self._current is not None:
            self._append_field(
                {
                    "name": attributes.get("name", "")[:200],
                    "field_type": tag,
                    "value": "",
                    "required": "required" in attributes,
                    "placeholder": attributes.get("placeholder", "")[:200],
                    "autocomplete": attributes.get("autocomplete", "")[:100],
                    "options": [],
                }
            )
            return

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current is not None:
            self.forms.append(self._current)
            self._current = None

    def close(self) -> None:  # noqa: D102 - ensure an unclosed form is captured
        super().close()
        if self._current is not None:
            self.forms.append(self._current)
            self._current = None

    def _append_field(self, field: dict[str, object]) -> None:
        assert self._current is not None
        fields = self._current.setdefault("fields", [])
        assert isinstance(fields, list)
        fields.append(field)


def extract_forms_from_html(html: str, base_url: str) -> list[dict[str, object]]:
    """Return a list of form dicts shaped like the browser extraction result."""
    parser = _FormParser(base_url)
    try:
        parser.feed(html)
        parser.close()
    except Exception:  # noqa: BLE001 - malformed markup must not fail the scan
        pass
    return parser.forms


def extract_scripts_from_html(
    html: str, base_url: str, *, max_inline_chars: int = 1500
) -> list[dict[str, object]]:
    """Return ``[{kind, src, is_module, text, length}]`` for every script tag."""
    scripts: list[dict[str, object]] = []
    for match in re.finditer(
        r"<script\b([^>]*)>(.*?)</script\s*>", html, re.IGNORECASE | re.DOTALL
    ):
        raw_attrs, body = match.group(1) or "", match.group(2) or ""
        src_match = re.search(r"""src\s*=\s*["']([^"']+)["']""", raw_attrs, re.IGNORECASE)
        is_module = bool(re.search(r"""type\s*=\s*["']module["']""", raw_attrs, re.IGNORECASE))
        if src_match:
            scripts.append(
                {
                    "kind": "module" if is_module else "external",
                    "src": src_match.group(1).strip(),
                    "is_module": is_module,
                    "text": "",
                    "length": 0,
                }
            )
        else:
            scripts.append(
                {
                    "kind": "inline",
                    "src": "",
                    "is_module": is_module,
                    "text": body[:max_inline_chars],
                    "length": len(body),
                }
            )
    return scripts


def base_url_of(html: str, fallback: str) -> str:
    """Honour a ``<base href>`` element, which changes every relative URL."""
    match = re.search(
        r"""<base\b[^>]*?href\s*=\s*["']([^"']+)["']""", html, re.IGNORECASE
    )
    if match:
        candidate = urljoin(fallback, match.group(1).strip())
        if urlsplit(candidate).scheme in {"http", "https"}:
            return candidate
    return fallback


__all__ = [
    "base_url_of",
    "extract_forms_from_html",
    "extract_links_from_html",
    "extract_scripts_from_html",
    "strip_tags",
]
