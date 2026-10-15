"""A deliberately insecure local target used by the demo and the test suite.

This exists so the harness can be exercised end to end without touching any system the
operator does not control. It serves a single-page application shell with everything the
MVP tools are meant to notice:

* links, including one with query parameters and one that points off-site;
* a login form, a search form and a state-changing form with no CSRF token;
* external and inline JavaScript, including a fetch call to an API route and a
  credential-looking literal that must be reported only as a redacted hint;
* security headers that are mostly absent, plus ``Server`` and ``X-Powered-By`` banners;
* cookies missing ``Secure``, ``HttpOnly`` and ``SameSite``.
* intentionally vulnerable training routes: reflected XSS, open redirect, IDOR,
  path-traversal simulation, SSRF simulation, and unauthenticated debug/API data.

Everything is bound to 127.0.0.1 on an ephemeral port. Run it with::

    python -m tools.demo_target
"""

from __future__ import annotations

import argparse
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Demo Shop - Home</title>
  <base href="/">
  <link rel="stylesheet" href="/static/app.css">
  <link rel="stylesheet" href="https://cdn.example-cdn.test/vendor.css">
  <script src="/static/app.js"></script>
  <script>
    const API_BASE = "/api/v1";
    window.CONFIG = { apiKey: "AKIAIOSFODNN7EXAMPLE1234", env: "demo" };
    async function loadUser(id) {
      const response = await fetch("/api/v1/users/" + id + "/profile?expand=roles");
      return response.json();
    }
    fetch("https://telemetry.example-metrics.test/collect", { method: "POST", body: "x" });
  </script>
</head>
<body>
  <nav>
    <a href="/">Home</a>
    <a href="/products?q=shoes">Products</a>
    <a href="/search?q=shoes&page=1">Search</a>
    <a href="/products/42?ref=nav">Product 42</a>
    <a href="/admin">Admin</a>
    <a href="/redirect?next=https://example.test">Redirect</a>
    <a href="/api/v1/users/1001/profile">User profile</a>
    <a href="/download?file=reports/quarterly.txt">Download</a>
    <a href="https://partner.example-external.test/promo">Partner site</a>
    <a href="mailto:sales@example.com">Email us</a>
  </nav>

  <main>
    <h1>Demo Shop</h1>

    <form id="login" name="login" action="/login" method="post">
      <input type="hidden" name="csrf_token" value="tok-abc123">
      <input type="text" name="username" placeholder="Username" required autocomplete="username">
      <input type="password" name="password" placeholder="Password" required autocomplete="current-password">
      <button type="submit">Sign in</button>
    </form>

    <form id="search-form" action="/search" method="get">
      <input type="search" name="q" placeholder="Search products">
      <select name="sort"><option value="relevance">Relevance</option><option value="price">Price</option></select>
      <button type="submit">Search</button>
    </form>

    <form id="checkout" action="/api/v1/orders" method="post">
      <input type="text" name="sku" placeholder="SKU">
      <input type="number" name="quantity" value="1">
      <input type="file" name="attachment">
      <button type="submit">Place order</button>
    </form>

    <div data-api="/api/v1/cart/items" hx-post="/api/v1/cart/add"></div>
    <iframe src="/widget" title="Widget"></iframe>
    <img src="/static/logo.png" alt="Logo">
  </main>
</body>
</html>
"""

APP_JS = """
// Demo bundle
const routes = { cart: "/api/v2/cart", invoices: "/api/v2/invoices/{id}" };
axios.get("/api/v2/session/me");
fetch("/graphql", { method: "POST" });
fetch("/api/v1/users/1001/profile");
document.addEventListener("DOMContentLoaded", () => console.log("ready"));
"""

ROBOTS_TXT = """# Demo Shop crawler policy
User-agent: *
Disallow: /admin
Disallow: /api/v1/orders
Disallow: /internal/metrics
Allow: /

User-agent: BadBot
Disallow: /

Sitemap: /sitemap.xml

Crawl-delay: 1
"""

SITEMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>/</loc></url>
  <url><loc>/search?q=shoes</loc></url>
  <url><loc>/products/42</loc></url>
  <url><loc>/about</loc></url>
</urlset>
"""

SECURITY_TXT = """Contact: mailto:security@example.com
Expires: 2027-12-31T23:59:00.000Z
Preferred-Languages: en, vi
Canonical: /.well-known/security.txt
Policy: /security-policy
"""

# Deliberately exposed files. Values are fake, but shaped like the real thing so the
# signature checks in analyze_exposed_files have something honest to match on.
GIT_HEAD = "ref: refs/heads/main\n"

GIT_CONFIG = """[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
[remote "origin"]
\turl = https://git.example.com/demoshop/app.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
"""

DOT_ENV = """# Demo Shop environment - DO NOT COMMIT
APP_NAME=DemoShop
APP_ENV=production
APP_KEY=base64:ZGVtb2tleW5vdGFyZWFsa2V5Zm9ydGVzdGluZzE=
DB_CONNECTION=mysql
DB_HOST=db.internal.example.com
DB_DATABASE=demoshop
DB_USERNAME=demoshop_app
DB_PASSWORD=not-a-real-password-12345
REDIS_HOST=cache.internal.example.com
MAIL_PASSWORD=smtp-not-real-67890
"""

SERVER_STATUS = """<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html><head><title>Apache Server Status for localhost</title></head>
<body>
<h1>Apache Server Status for localhost (via 127.0.0.1)</h1>
<dl><dt>Server Version: Apache/2.4.58 (Debian)</dt>
<dt>Server MPM: prefork</dt>
<dt>Current Time: Wednesday, 01-Jan-2026 00:00:00 UTC</dt></dl>
</body></html>
"""

DS_STORE = b"\x00\x00\x00\x01Bud1\x00\x00\x00\x00\x00\x00\x00\x00"

# A deliberately injectable search endpoint. This is what a naive query builder produces:
# the parameter is concatenated into SQL, so a single quote breaks the statement and the
# driver's error is echoed to the client. The harness's error-based probe must find this.
INJECTABLE_QUERY = "SELECT id, name FROM products WHERE name LIKE '%{q}%' ORDER BY name"

SQL_ERROR_TEMPLATE = (
    "<html><head><title>Database error</title></head><body>"
    "<h1>Query failed</h1>"
    "<p>You have an error in your SQL syntax; check the manual that corresponds to your "
    "MySQL server version for the right syntax to use near "
    "<code>'%{q}%' ORDER BY name' at line 1</code></p>"
    "<p>Query was: <code>{query}</code></p>"
    "</body></html>"
)

SEARCH_OK_TEMPLATE = (
    "<html><head><title>Product search</title></head><body>"
    "<h1>Products matching {q}</h1>"
    "<ul><li>Shoe</li><li>Shirt</li><li>Shelf</li></ul>"
    "</body></html>"
)

README_MD = """# Demo Shop

Internal staging deployment for the Demo Shop storefront.

## Local setup

    cp .env.example .env
    docker compose up -d

## Default credentials

    admin / changeme
"""

SEARCH_HTML = """<!doctype html>
<html><head><title>Search results</title></head>
<body>
  <p>Results for <span id="q">{query}</span></p>
  <form action="/search" method="get">
    <input type="search" name="q" value="{query}">
    <button type="submit">Search again</button>
  </form>
</body></html>
"""

# These values are synthetic. The routes below model common mistakes without making
# outbound requests or reading the host filesystem.
DEBUG_VARS = {
    "app": "DemoShop",
    "environment": "production",
    "database_host": "db.internal.example.com",
    "feature_flags": {"new_checkout": True, "debug": True},
}

FAKE_DOCUMENTS = {
    "reports/quarterly.txt": "Quarterly demo report: revenue=100000; owner=demo@example.test",
    "etc/passwd": "root:x:0:0:root:/root:/bin/sh\ndemo:x:1000:1000:demo:/home/demo:/bin/sh",
}


class DemoHandler(BaseHTTPRequestHandler):
    """Serves the demo content with realistically poor security headers.

    ``strict_404`` controls how unknown paths are answered:

    * ``True`` (default) - a real 404 with an error page, like a normal server.
    * ``False`` - a 200 with the error page, the "soft 404" pattern that breaks naive
      content-discovery tools. Run with ``--soft-404`` to exercise that path, which is what
      ``analyze_exposed_files`` has to defend against.
    """

    server_version = "DemoShop/1.4.2"
    protocol_version = "HTTP/1.1"
    strict_404 = True

    NOT_FOUND_HTML = (
        "<!doctype html><html><head><title>Not found</title></head>"
        "<body><h1>404 Not found</h1><p>The page you requested does not exist.</p>"
        "</body></html>"
    )

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A002 - stdlib signature
        """Silence the default stderr access log."""
        return

    _head_only = False

    # -- routing ----------------------------------------------------------- #

    def do_GET(self) -> None:  # noqa: N802 - stdlib signature
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            self._send(200, INDEX_HTML, "text/html; charset=utf-8", with_cookies=True)
        elif path == "/static/app.js":
            self._send(200, APP_JS, "application/javascript")
        elif path == "/static/app.css":
            self._send(200, "body{font-family:sans-serif}", "text/css")
        elif path == "/robots.txt":
            self._send(200, ROBOTS_TXT, "text/plain; charset=utf-8")
        elif path == "/sitemap.xml":
            self._send(200, SITEMAP_XML, "application/xml")
        elif path == "/.well-known/security.txt":
            self._send(200, SECURITY_TXT, "text/plain; charset=utf-8")
        # Deliberately exposed files, for analyze_exposed_files to find.
        elif path == "/.git/HEAD":
            self._send(200, GIT_HEAD, "text/plain")
        elif path == "/.git/config":
            self._send(200, GIT_CONFIG, "text/plain")
        elif path in ("/.env", "/.env.local"):
            self._send(200, DOT_ENV, "text/plain")
        elif path == "/server-status":
            self._send(200, SERVER_STATUS, "text/html")
        elif path == "/.DS_Store":
            self._send_bytes(200, DS_STORE, "application/octet-stream")
        elif path == "/README.md":
            self._send(200, README_MD, "text/markdown; charset=utf-8")
        elif path == "/search":
            query = self.path.split("q=", 1)[-1].split("&", 1)[0] if "q=" in self.path else ""
            self._send(200, SEARCH_HTML.format(query=query), "text/html; charset=utf-8")
        elif path == "/redirect":
            self._open_redirect()
        elif path == "/download":
            self._serve_download()
        elif path == "/fetch":
            self._serve_ssrf_simulation()
        elif path == "/debug/vars":
            self._send(200, json.dumps(DEBUG_VARS), "application/json")
        elif path == "/products":
            self._serve_product_search()
        elif path.startswith("/products/"):
            pid = path.removeprefix("/products/")
            self._send(
                200,
                f"<html><head><title>Product {pid}</title></head><body><h1>Product #{pid}</h1></body></html>",
                "text/html; charset=utf-8",
            )
        elif path.startswith("/api/v1/users/") and path.endswith("/profile"):
            self._serve_user_profile(path)
        elif path.startswith("/api/"):
            payload = json.dumps({"path": path, "status": "ok"})
            self._send(200, payload, "application/json")
        elif path == "/admin":
            self._send(200, "<html><title>Admin</title><body>Admin area</body></html>", "text/html")
        elif path == "/widget":
            self._send(200, "<html><body>widget</body></html>", "text/html")
        else:
            self._send_not_found()

    def do_OPTIONS(self) -> None:  # noqa: N802 - stdlib signature
        """Answer a CORS preflight.

        Two behaviours, separated on purpose so the active checks have something honest to
        find:

        * ``/api/reflect`` and ``/api/null-origin`` reflect the requested method and allow
          credentials, which is a cross-origin *write* primitive. ``cors_preflight`` must
          report this at high severity.
        * everything else advertises only read methods, which must **not** be reported.
        """
        path = self.path.split("?", 1)[0]
        requested_method = self.headers.get("Access-Control-Request-Method", "GET")

        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.send_header(
            "Access-Control-Allow-Headers",
            self.headers.get("Access-Control-Request-Headers", "*"),
        )
        self.send_header("Access-Control-Max-Age", "86400")

        if path in ("/api/reflect", "/api/null-origin"):
            # Echoes whatever method the caller asks for, including writes.
            self.send_header("Access-Control-Allow-Methods", f"GET, POST, PUT, DELETE, {requested_method}")
            self.send_header("Allow", "GET, POST, PUT, DELETE, OPTIONS")
        else:
            self.send_header("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
            self.send_header("Allow", "GET, HEAD, OPTIONS")

        self._send_cors_headers()
        self.end_headers()

    def do_TRACE(self) -> None:  # noqa: N802 - stdlib signature
        """TRACE is deliberately disabled, as it should be on a real server."""
        self.send_response(405)
        self.send_header("Content-Length", "0")
        self.send_header("Allow", "GET, HEAD, OPTIONS")
        self.end_headers()

    def _send_not_found(self) -> None:
        """Answer an unknown path, honouring the soft-404 mode."""
        status = 404 if self.strict_404 else 200
        self._send(status, self.NOT_FOUND_HTML, "text/html; charset=utf-8")

    def _serve_product_search(self) -> None:
        """Serve an endpoint that concatenates its parameter into SQL.

        The flaw is modelled, not simulated: a value containing a quote character makes the
        statement syntactically invalid, and the driver's error is returned to the client,
        which is exactly the pair of mistakes error-based detection looks for.
        """
        from urllib.parse import parse_qs, urlsplit

        query_params = parse_qs(urlsplit(self.path).query, keep_blank_values=True)
        raw_q = (query_params.get("q") or [""])[0]
        # Strip the encoding so a percent-encoded quote behaves like a literal quote, which is
        # what a real server does after parsing the query string.
        from urllib.parse import unquote

        q = unquote(raw_q)

        if "'" in q or '"' in q:
            statement = INJECTABLE_QUERY.format(q=q)
            self._send(
                500,
                SQL_ERROR_TEMPLATE.format(q=q, query=statement),
                "text/html; charset=utf-8",
            )
            return
        self._send(200, SEARCH_OK_TEMPLATE.format(q=q or "everything"), "text/html; charset=utf-8")

    def _open_redirect(self) -> None:
        """Redirect to an arbitrary caller-provided URL without validation."""
        from urllib.parse import parse_qs, urlsplit

        target = (parse_qs(urlsplit(self.path).query).get("next") or ["/"])[0]
        self.send_response(302)
        self.send_header("Location", target)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _serve_user_profile(self, path: str) -> None:
        """Return any user's profile without checking the caller's identity (IDOR)."""
        user_id = path.removeprefix("/api/v1/users/").removesuffix("/profile")
        profile = {
            "id": user_id,
            "email": f"user-{user_id}@example.test",
            "plan": "enterprise",
            "internal_notes": "synthetic profile; no authentication is enforced",
        }
        self._send(200, json.dumps(profile), "application/json")

    def _serve_download(self) -> None:
        """Resolve a file name by string concatenation; traversal is simulated with fake data."""
        from urllib.parse import parse_qs, urlsplit, unquote

        requested = unquote((parse_qs(urlsplit(self.path).query).get("file") or [""])[0])
        normalized = requested.replace("\\", "/")
        if ".." in normalized:
            # Never read a real file. This stands in for a leaked /etc/passwd response.
            self._send(200, FAKE_DOCUMENTS["etc/passwd"], "text/plain")
            return
        body = FAKE_DOCUMENTS.get(normalized, "file not found")
        self._send(200 if normalized in FAKE_DOCUMENTS else 404, body, "text/plain")

    def _serve_ssrf_simulation(self) -> None:
        """Echo an arbitrary URL and return canned metadata; no network request is made."""
        from urllib.parse import parse_qs, urlsplit

        target = (parse_qs(urlsplit(self.path).query).get("url") or [""])[0]
        self._send(
            200,
            json.dumps({
                "requested_url": target,
                "status": "fetched",
                "body": "synthetic internal metadata",
            }),
            "application/json",
        )

    def do_HEAD(self) -> None:  # noqa: N802 - stdlib signature
        """Answer HEAD with the real status and headers, but no body.

        A stub that returns 200 for every path would make the demo target look like a
        soft-404 server, which is a far less useful teaching example.
        """
        self._head_only = True
        try:
            self.do_GET()
        finally:
            self._head_only = False

    def _path_exists(self, path: str) -> bool:
        if path in ("/", "/index.html", "/robots.txt", "/sitemap.xml", "/.well-known/security.txt"):
            return True
        if path.startswith("/static/") or path.startswith("/api/"):
            return True
        return path in {
            "/search",
            "/products",
            "/admin",
            "/widget",
            "/redirect",
            "/download",
            "/fetch",
            "/debug/vars",
            "/api/v1/users/profile",
            "/.git/HEAD",
            "/.git/config",
            "/.env",
            "/.env.local",
            "/server-status",
            "/.DS_Store",
            "/README.md",
        }

    def do_POST(self) -> None:  # noqa: N802 - stdlib signature
        length = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(min(length, 1_000_000)) if length else b""
        path = self.path.split("?", 1)[0]
        if path == "/api/v1/users/profile":
            # Mass-assignment training route: accepts caller-supplied role/is_admin fields.
            self._send(200, json.dumps({"updated": True, "accepted_fields": body.decode("utf-8", "replace")}), "application/json")
            return
        self._send(200, json.dumps({"accepted": True}), "application/json")

    # -- response helpers -------------------------------------------------- #

    def _send(
        self,
        status: int,
        payload: str,
        content_type: str,
        *,
        include_body: bool = True,
        with_cookies: bool = False,
    ) -> None:
        self._send_bytes(
            status, payload.encode("utf-8"), content_type,
            include_body=include_body, with_cookies=with_cookies,
        )

    def _send_bytes(
        self,
        status: int,
        payload: bytes,
        content_type: str,
        *,
        include_body: bool = True,
        with_cookies: bool = False,
        head_only: bool = False,
    ) -> None:
        encoded = payload
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        # Deliberately weak header posture: no HSTS, CSP, Referrer-Policy, COOP, CORP,
        # Permissions-Policy or X-Permitted-Cross-Domain-Policies, and banners present.
        self.send_header("X-Powered-By", "Express/4.18.2")
        self._send_cors_headers()
        if with_cookies:
            # No Secure, no HttpOnly, no SameSite; one over-broad Domain cookie.
            self.send_header(
                "Set-Cookie",
                "sessionid=abc123def456ghi789; Path=/; Expires=Wed, 21 Oct 2099 07:28:00 GMT",
            )
            self.send_header("Set-Cookie", "theme=dark; Path=/; Domain=.127.0.0.1")
            self.send_header("Set-Cookie", "csrftoken=tok-abc123; Path=/; SameSite=Strict")
        self.end_headers()
        if include_body and not (head_only or self._head_only):
            self.wfile.write(encoded)

    def _send_cors_headers(self) -> None:
        """Emit a CORS policy, honestly vulnerable on the endpoints that model one.

        The demo target is meant to teach, so the two behaviours are separated rather than
        mixed:

        * ``/api/reflect``  - echoes whatever Origin it is given **and** allows credentials.
          This is the account-takeover shape, and ``analyze_cors`` must catch it.
        * everything else   - the common ``*`` policy. Safe without credentials, so
          ``analyze_cors`` must *not* report it.
        """
        path = self.path.split("?", 1)[0]
        request_origin = self.headers.get("Origin", "")

        if path == "/api/reflect":
            if request_origin:
                self.send_header("Access-Control-Allow-Origin", request_origin)
                self.send_header("Access-Control-Allow-Credentials", "true")
            else:
                self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Vary", "Origin")
            return

        if path == "/api/null-origin":
            self.send_header("Access-Control-Allow-Origin", "null")
            self.send_header("Access-Control-Allow-Credentials", "true")
            return

        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Credentials", "true")


def make_server(
    host: str = "127.0.0.1", port: int = 0, *, strict_404: bool = True
) -> ThreadingHTTPServer:
    """Create the demo server bound to an ephemeral port.

    ``strict_404=False`` makes every unknown path answer 200, which is the soft-404
    behaviour that content-discovery tools must defend against.
    """

    class _Handler(DemoHandler):
        pass

    _Handler.strict_404 = strict_404
    return ThreadingHTTPServer((host, port), _Handler)


def serve_forever(host: str = "127.0.0.1", port: int = 0, *, strict_404: bool = True) -> None:
    server = make_server(host, port, strict_404=strict_404)
    actual_port = server.server_address[1]
    print(f"demo target listening on http://{host}:{actual_port}")
    print("press Ctrl+C to stop")
    server.serve_forever()


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the local deliberately-insecure demo target.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0, help="0 selects an ephemeral port.")
    parser.add_argument(
        "--soft-404",
        action="store_true",
        help=(
            "answer 200 for unknown paths instead of 404. Simulates the catch-all behaviour "
            "that produces false positives in naive content-discovery tools."
        ),
    )
    parser.add_argument(
        "--background",
        action="store_true",
        help="start in a daemon thread and keep the process alive (for scripted demos).",
    )
    args = parser.parse_args()

    server = make_server(args.host, args.port, strict_404=not args.soft_404)
    port = server.server_address[1]
    print(f"demo target listening on http://{args.host}:{port}")
    if args.soft_404:
        print("mode: SOFT 404 - unknown paths answer 200 (catch-all)")

    if args.background:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            thread.join()
        except KeyboardInterrupt:
            server.shutdown()
        return 0

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
