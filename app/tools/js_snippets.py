"""Client-side extraction snippets.

These strings are the *only* JavaScript the harness executes in a target page. They
are static constants - never assembled from AI-supplied data - and they only read
from the DOM. No snippet writes to the page, calls ``fetch``, or touches storage.

Using the live DOM rather than regex over raw HTML matters for correctness: it
resolves relative URLs, respects the document base, and sees markup that only
exists after client-side rendering.

The regex fallbacks exist for pages captured with JavaScript disabled, whose live
page handle is already closed.
"""

from __future__ import annotations

EXTRACT_LINKS_JS = r"""
() => {
  const out = [];
  const push = (url, text, rel, kind) => {
    if (!url) return;
    out.push({ url, text: (text || '').slice(0, 200), rel: (rel || '').slice(0, 100), kind });
  };
  for (const a of document.querySelectorAll('a[href]')) {
    push(a.href, (a.textContent || '').trim(), a.getAttribute('rel'), 'anchor');
  }
  for (const area of document.querySelectorAll('area[href]')) {
    push(area.href, area.getAttribute('alt') || '', area.getAttribute('rel'), 'anchor');
  }
  for (const form of document.querySelectorAll('form[action]')) {
    push(form.action, form.getAttribute('name') || form.id || '', null, 'form_action');
  }
  for (const script of document.querySelectorAll('script[src]')) {
    push(script.src, '', null, 'script_src');
  }
  for (const link of document.querySelectorAll('link[href]')) {
    const rel = (link.getAttribute('rel') || '').toLowerCase();
    push(link.href, '', rel, rel.includes('stylesheet') ? 'stylesheet' : 'other');
  }
  for (const frame of document.querySelectorAll('iframe[src]')) {
    push(frame.src, frame.getAttribute('title') || '', null, 'iframe');
  }
  for (const img of document.querySelectorAll('img[src]')) {
    push(img.src, img.getAttribute('alt') || '', null, 'image');
  }
  const base = document.baseURI;
  return { base, links: out };
}
"""

EXTRACT_FORMS_JS = r"""
() => {
  const forms = [];
  for (const form of document.querySelectorAll('form')) {
    const fields = [];
    let hasPassword = false;
    let hasFile = false;
    let hasToken = false;
    const tokenPattern = /(csrf|xsrf|authenticity|__requestverification|nonce|token)/i;

    for (const el of form.querySelectorAll('input, textarea, select, button')) {
      const tag = el.tagName.toLowerCase();
      const type = tag === 'input' ? (el.getAttribute('type') || 'text').toLowerCase() : tag;
      if (type === 'submit' || type === 'button' || type === 'reset' || type === 'image') continue;

      let options = [];
      if (tag === 'select') {
        options = Array.from(el.options || []).slice(0, 50).map(o => o.value);
      }

      const name = el.getAttribute('name') || '';
      if (type === 'password') hasPassword = true;
      if (type === 'file') hasFile = true;
      if (type === 'hidden' && tokenPattern.test(name)) hasToken = true;

      fields.push({
        name,
        field_type: type,
        value: (el.value === undefined || el.value === null) ? '' : String(el.value).slice(0, 300),
        required: el.hasAttribute('required') || el.getAttribute('aria-required') === 'true',
        placeholder: el.getAttribute('placeholder') || '',
        autocomplete: el.getAttribute('autocomplete') || '',
        options,
      });
    }

    const enctype = (form.getAttribute('enctype') || '').toLowerCase();
    forms.push({
      action: form.action || location.href,
      method: (form.getAttribute('method') || 'get').toLowerCase(),
      form_id: (form.id || '').slice(0, 200),
      name: (form.getAttribute('name') || '').slice(0, 200),
      enctype,
      is_login_form: hasPassword,
      is_upload_form: hasFile || enctype.includes('multipart/form-data'),
      has_csrf_token: hasToken,
      fields,
    });
  }
  return { base: document.baseURI, forms };
}
"""

EXTRACT_SCRIPTS_JS = r"""
() => {
  const scripts = [];
  for (const el of document.querySelectorAll('script')) {
    const src = el.getAttribute('src');
    const body = el.textContent || '';
    scripts.push({
      kind: src ? (el.getAttribute('type') === 'module' ? 'module' : 'external') : 'inline',
      src: src || '',
      is_module: el.getAttribute('type') === 'module',
      text: body.slice(0, 20000),
      length: body.length,
    });
  }
  const attrs = [];
  for (const el of document.querySelectorAll('[data-url],[data-api],[data-endpoint],[hx-get],[hx-post],[data-href]')) {
    for (const name of ['data-url','data-api','data-endpoint','hx-get','hx-post','data-href']) {
      const value = el.getAttribute(name);
      if (value) attrs.push(value);
    }
  }
  const html = document.documentElement ? document.documentElement.outerHTML.slice(0, 400000) : '';
  return { base: document.baseURI, scripts, attrs, html };
}
"""

# Regex fallbacks for raw HTML captured without a live DOM.
_LINK_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"""<a\b[^>]*?href\s*=\s*["']([^"']+)["'][^>]*>(.*?)</a>""", "anchor"),
    (r"""<area\b[^>]*?href\s*=\s*["']([^"']+)["']""", "anchor"),
    (r"""<form\b[^>]*?action\s*=\s*["']([^"']+)["']""", "form_action"),
    (r"""<script\b[^>]*?src\s*=\s*["']([^"']+)["']""", "script_src"),
    (r"""<link\b[^>]*?href\s*=\s*["']([^"']+)["']""", "stylesheet"),
    (r"""<iframe\b[^>]*?src\s*=\s*["']([^"']+)["']""", "iframe"),
    (r"""<img\b[^>]*?src\s*=\s*["']([^"']+)["']""", "image"),
)

# Endpoint candidates: absolute paths in JS, quoted API routes, and fetch/axios
# targets. Deliberately conservative - a noisy list wastes the AI's context.
API_ENDPOINT_PATTERNS: tuple[str, ...] = (
    r"""(?:fetch|axios\.\w+|\.open|url)\s*\(\s*["'`]([^"'`\s]{2,300})["'`]""",
    r"""["'`](/api/[A-Za-z0-9_\-./{}$:]{1,200})["'`]""",
    r"""["'`](/v\d+/[A-Za-z0-9_\-./{}$:]{1,200})["'`]""",
    r"""["'`](https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{4,300})["'`]""",
    r"""(?:baseURL|baseUrl|API_BASE|apiBase)\s*[:=]\s*["'`]([^"'`\s]{2,300})["'`]""",
)

# Attribute-based endpoint declarations present in HTMX, Alpine and similar stacks.
ATTRIBUTE_ENDPOINT_PATTERNS: tuple[str, ...] = (
    r"""data-(?:url|api|endpoint|href)\s*=\s*["']([^"']{2,300})["']""",
    r"""hx-(?:get|post|put|delete|patch)\s*=\s*["']([^"']{2,300})["']""",
)

# Notices only. Values are never returned: a match produces a redacted hint.
SECRET_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"""(?i)(?:api[_-]?key|apikey)\s*[:=]\s*["'][A-Za-z0-9_\-]{16,}["']""", "possible API key in inline JavaScript"),
    (r"""(?i)(?:secret|client[_-]?secret)\s*[:=]\s*["'][A-Za-z0-9_\-]{12,}["']""", "possible client secret in inline JavaScript"),
    (r"""(?i)aws(?:.{0,20})?(?:access[_-]?key|secret)\s*[:=]\s*["'][A-Za-z0-9/+=]{16,}["']""", "possible AWS credential in inline JavaScript"),
    (r"""eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}""", "possible JWT literal in inline JavaScript"),
    (r"""(?i)bearer\s+[A-Za-z0-9_\-.]{20,}""", "possible bearer token in inline JavaScript"),
    (r"""-----BEGIN [A-Z ]*PRIVATE KEY-----""", "possible private key material in inline JavaScript"),
    (r"""(?i)(?:firebase|supabase)[^\n]{0,40}(?:key|url)\s*[:=]\s*["'][^"']{10,}["']""", "possible backend service config in inline JavaScript"),
)

__all__ = [
    "API_ENDPOINT_PATTERNS",
    "ATTRIBUTE_ENDPOINT_PATTERNS",
    "EXTRACT_FORMS_JS",
    "EXTRACT_LINKS_JS",
    "EXTRACT_SCRIPTS_JS",
    "SECRET_PATTERNS",
]
