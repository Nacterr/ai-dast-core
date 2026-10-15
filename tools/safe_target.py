"""A hardened counterpart to :mod:`tools.demo_target` for scan comparisons.

This target intentionally keeps several route names from the vulnerable demo, but applies
basic fixes: output encoding, parameterised-query behaviour, redirect allowlisting, auth
checks, no file/URL resolution, restrictive CORS, security headers and secure cookies.
It is still a toy app with synthetic data and is intended for loopback testing only.
"""

from __future__ import annotations

import argparse
import html
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, quote, urlsplit


class SafeHandler(BaseHTTPRequestHandler):
    server_version = "DemoShopSafe"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    _head_only = False

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A002
        return

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        query = parse_qs(urlsplit(self.path).query, keep_blank_values=True)
        if path in {"/", "/index.html"}:
            body = (
                '<!doctype html><html><head><title>Safe Demo Shop</title></head><body>'
                '<h1>Safe Demo Shop</h1>'
                '<a href="/search?q=shoes">Search</a> '
                '<a href="/products?q=shoes">Products</a> '
                '<a href="/api/v1/users/1001/profile">Profile</a>'
                '</body></html>'
            )
            self._send(200, body, "text/html; charset=utf-8", with_cookie=True)
        elif path == "/search":
            value = html.escape(query.get("q", [""])[0], quote=True)
            self._send(200, f"<html><body><h1>Results for {value}</h1></body></html>", "text/html")
        elif path == "/products":
            # Simulates a parameterised query: quotes are ordinary data, never SQL syntax.
            value = html.escape(query.get("q", [""])[0], quote=True)
            self._send(200, f"<html><body><h1>Products matching {value}</h1></body></html>", "text/html")
        elif path == "/redirect":
            target = query.get("next", ["/"])[0]
            if not target.startswith("/") or target.startswith("//"):
                self._send(400, "invalid redirect target", "text/plain")
            else:
                self.send_response(302)
                self.send_header("Location", target)
                self.send_header("Content-Length", "0")
                self._security_headers()
                self.end_headers()
        elif path == "/download":
            requested = query.get("file", [""])[0].replace("\\", "/")
            if ".." in requested or requested.startswith("/"):
                self._send(400, "invalid file name", "text/plain")
            elif requested == "reports/quarterly.txt":
                self._send(200, "Quarterly report for the safe demo", "text/plain")
            else:
                self._send(404, "not found", "text/plain")
        elif path == "/fetch":
            self._send(400, "server-side fetching is disabled", "text/plain")
        elif path in {"/.env", "/.env.local", "/.git/config", "/debug/vars", "/server-status"}:
            self._send(404, "not found", "text/plain")
        elif path == "/api/v1/users/" or (path.startswith("/api/v1/users/") and path.endswith("/profile")):
            self._send(401, json.dumps({"error": "authentication required"}), "application/json")
        elif path.startswith("/api/"):
            self._send(200, json.dumps({"status": "ok"}), "application/json")
        else:
            self._send(404, "not found", "text/plain")

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("content-length") or 0)
        if length:
            self.rfile.read(min(length, 1_000_000))
        if self.path.split("?", 1)[0] == "/api/v1/users/profile":
            self._send(401, json.dumps({"error": "authentication required"}), "application/json")
            return
        self._send(403, json.dumps({"error": "write not permitted in demo"}), "application/json")

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(204)
        self.send_header("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Content-Length", "0")
        self._security_headers()
        self.end_headers()

    def do_TRACE(self) -> None:  # noqa: N802
        self._send(405, "method not allowed", "text/plain")

    def do_HEAD(self) -> None:  # noqa: N802
        self._head_only = True
        try:
            self.do_GET()
        finally:
            self._head_only = False

    def _send(self, status: int, body: str, content_type: str, *, with_cookie: bool = False) -> None:
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self._security_headers()
        if with_cookie:
            self.send_header("Set-Cookie", "sessionid=safe-demo; Path=/; Secure; HttpOnly; SameSite=Lax")
        self.end_headers()
        if not self._head_only:
            self.wfile.write(encoded)

    def _security_headers(self) -> None:
        self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        self.send_header("Content-Security-Policy", "default-src 'self'; object-src 'none'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        origin = self.headers.get("Origin")
        if origin == "https://app.example.test":
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")


def make_server(host: str = "127.0.0.1", port: int = 0) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), SafeHandler)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the hardened local comparison target.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args()
    server = make_server(args.host, args.port)
    print(f"safe target listening on http://{args.host}:{server.server_address[1]}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
