"""Direct checks for the intentionally vulnerable local demo target."""

from __future__ import annotations

import json
from http.client import HTTPConnection
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


def _get(base: str, path: str):
    parts = urlsplit(base)
    connection = HTTPConnection(parts.hostname, parts.port, timeout=3)
    connection.request("GET", path)
    # HTTPConnection does not follow Location, which is important for the open-redirect test.
    return connection.getresponse()


def _body(response) -> str:
    return response.read().decode("utf-8")


def test_training_routes_expose_the_documented_weaknesses(demo_server: str) -> None:
    redirect = _get(demo_server, "/redirect?next=https%3A%2F%2Fevil.test%2Flanding")
    assert redirect.status == 302
    assert redirect.headers["Location"] == "https://evil.test/landing"

    profile = json.loads(_body(_get(demo_server, "/api/v1/users/4242/profile")))
    assert profile["id"] == "4242"
    assert profile["email"] == "user-4242@example.test"

    traversal = _get(demo_server, "/download?file=..%2F..%2Fetc%2Fpasswd")
    assert "root:x:0:0" in _body(traversal)

    ssrf = json.loads(_body(_get(demo_server, "/fetch?url=http%3A%2F%2F169.254.169.254%2Flatest")))
    assert ssrf["requested_url"] == "http://169.254.169.254/latest"
    assert ssrf["status"] == "fetched"

    debug = json.loads(_body(_get(demo_server, "/debug/vars")))
    assert debug["environment"] == "production"


def test_mass_assignment_training_route_accepts_role_field(demo_server: str) -> None:
    request = Request(
        demo_server + "/api/v1/users/profile",
        data=b'{"display_name":"demo","role":"admin","is_admin":true}',
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(request, timeout=3) as response:
        payload = json.loads(response.read().decode("utf-8"))
    assert payload["updated"] is True
    assert "role" in payload["accepted_fields"]
