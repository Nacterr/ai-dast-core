"""The comparison target should not reproduce the demo target's obvious weaknesses."""

from __future__ import annotations

from http.client import HTTPConnection
from urllib.parse import urlsplit


def _request(base: str, method: str, path: str, body: bytes | None = None):
    parts = urlsplit(base)
    connection = HTTPConnection(parts.hostname, parts.port, timeout=3)
    connection.request(method, path, body=body, headers={"Content-Type": "application/json"})
    return connection.getresponse()


def test_safe_target_rejects_the_vulnerable_shapes(demo_safe_server: str) -> None:
    search = _request(demo_safe_server, "GET", "/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
    assert search.status == 200
    assert "&lt;script&gt;" in search.read().decode()

    redirect = _request(demo_safe_server, "GET", "/redirect?next=https%3A%2F%2Fevil.test")
    assert redirect.status == 400
    redirect.read()

    profile = _request(demo_safe_server, "GET", "/api/v1/users/4242/profile")
    assert profile.status == 401
    profile.read()

    traversal = _request(demo_safe_server, "GET", "/download?file=..%2F..%2Fetc%2Fpasswd")
    assert traversal.status == 400
    traversal.read()

    fetch = _request(demo_safe_server, "GET", "/fetch?url=http%3A%2F%2F169.254.169.254")
    assert fetch.status == 400
    fetch.read()


def test_safe_target_sets_security_headers_and_secure_cookie(demo_safe_server: str) -> None:
    response = _request(demo_safe_server, "GET", "/")
    assert response.status == 200
    assert response.headers["Strict-Transport-Security"]
    assert response.headers["Content-Security-Policy"]
    assert "Secure" in response.headers["Set-Cookie"]
    assert "HttpOnly" in response.headers["Set-Cookie"]
    assert "SameSite=Lax" in response.headers["Set-Cookie"]
    response.read()


def test_safe_target_does_not_accept_mass_assignment_without_auth(demo_safe_server: str) -> None:
    response = _request(
        demo_safe_server,
        "POST",
        "/api/v1/users/profile",
        b'{"role":"admin","is_admin":true}',
    )
    assert response.status == 401
    response.read()
