"""Scope guard tests.

The scope guard is the security boundary of the whole application, so it gets the most
adversarial tests in the suite. Every case here is a real bypass technique against naive
scope checks.
"""

from __future__ import annotations

import pytest

from app.policy.scope import (
    ScopeGuard,
    build_scope_policy,
    host_matches_pattern,
)
from app.policy.scope import _is_blocked_address  # noqa: PLC2701 - testing internals on purpose

import ipaddress


# --------------------------------------------------------------------------- #
# Host pattern matching
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("host", "pattern", "expected"),
    [
        ("example.com", "example.com", True),
        ("EXAMPLE.COM", "example.com", True),
        ("example.com.", "example.com", True),
        ("www.example.com", "example.com", False),
        ("a.example.com", "*.example.com", True),
        ("a.b.example.com", "*.example.com", True),
        ("example.com", "*.example.com", False),  # a wildcard never matches the apex
        ("notexample.com", "*.example.com", False),
        ("example.com.evil.test", "*.example.com", False),
        ("example.com", ".example.com", True),
        ("sub.example.com", ".example.com", True),
        ("", "example.com", False),
        ("example.com", "", False),
    ],
)
def test_host_matches_pattern(host: str, pattern: str, expected: bool) -> None:
    assert host_matches_pattern(host, pattern) is expected


# --------------------------------------------------------------------------- #
# Policy construction
# --------------------------------------------------------------------------- #


def test_build_scope_policy_includes_target_and_www_variant() -> None:
    policy = build_scope_policy("https://example.com/app")
    assert "example.com" in policy.allowed_hosts
    assert "www.example.com" in policy.allowed_hosts
    assert policy.allowed_ports == [80, 443]


def test_build_scope_policy_keeps_non_standard_port() -> None:
    policy = build_scope_policy("https://example.com:8443/")
    assert 8443 in policy.allowed_ports
    assert 80 in policy.allowed_ports and 443 in policy.allowed_ports


def test_build_scope_policy_does_not_wildcard_subdomains_of_an_apex() -> None:
    policy = build_scope_policy("https://example.com")
    guard = ScopeGuard(policy)
    assert guard.check_url("https://api.example.com/", resolve=False).allowed is False


def test_build_scope_policy_rejects_a_target_without_a_host() -> None:
    with pytest.raises(ValueError):
        build_scope_policy("https:///nopath")


def test_explicit_extra_host_is_allowed() -> None:
    policy = build_scope_policy("https://example.com", extra_hosts=["api.example.com"])
    guard = ScopeGuard(policy)
    assert guard.check_url("https://api.example.com/v1", resolve=False).allowed


def test_wildcard_extra_host() -> None:
    policy = build_scope_policy("https://example.com", extra_hosts=["*.example.com"])
    guard = ScopeGuard(policy)
    assert guard.check_url("https://a.example.com/", resolve=False).allowed
    assert guard.check_url("https://a.b.example.com/", resolve=False).allowed


def test_excluded_host_beats_inclusion() -> None:
    policy = build_scope_policy(
        "https://example.com", extra_hosts=["*.example.com"], excluded_hosts=["legacy.example.com"]
    )
    guard = ScopeGuard(policy)
    assert guard.check_url("https://legacy.example.com/", resolve=False).allowed is False
    assert guard.check_url("https://app.example.com/", resolve=False).allowed


# --------------------------------------------------------------------------- #
# Scheme, port and shape checks
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "gopher://example.com/",
        "ftp://example.com/",
        "data:text/html,<script>alert(1)</script>",
        "javascript:alert(1)",
        "dict://example.com:11211/",
    ],
)
def test_non_http_schemes_are_refused(url: str) -> None:
    guard = ScopeGuard(build_scope_policy("https://example.com"))
    decision = guard.check_url(url, resolve=False)
    assert decision.allowed is False
    assert decision.verdict.value == "denied_scheme"


@pytest.mark.parametrize("url", ["https://example.com:22/", "https://example.com:6379/", "http://example.com:8080/"])
def test_disallowed_ports_are_refused(url: str) -> None:
    guard = ScopeGuard(build_scope_policy("https://example.com"))
    decision = guard.check_url(url, resolve=False)
    assert decision.allowed is False
    assert decision.verdict.value == "denied_port"


@pytest.mark.parametrize(
    "url",
    [
        "https://user:pass@example.com/",
        "https://example.com@evil.test/",
        "https://example.com\\@evil.test/",
    ],
)
def test_embedded_credentials_are_refused(url: str) -> None:
    """``https://allowed.com@evil.com`` must not be treated as ``allowed.com``."""
    guard = ScopeGuard(build_scope_policy("https://example.com", extra_hosts=["evil.test"]))
    decision = guard.check_url(url, resolve=False)
    assert decision.allowed is False


def test_unknown_host_is_refused() -> None:
    guard = ScopeGuard(build_scope_policy("https://example.com"))
    decision = guard.check_url("https://evil.test/", resolve=False)
    assert decision.allowed is False
    assert decision.verdict.value == "denied_host"


def test_empty_and_oversized_urls_are_refused() -> None:
    guard = ScopeGuard(build_scope_policy("https://example.com"))
    assert guard.check_url("", resolve=False).allowed is False
    assert guard.check_url("https://example.com/" + "a" * 4096, resolve=False).allowed is False


def test_case_and_dot_normalisation() -> None:
    guard = ScopeGuard(build_scope_policy("https://example.com"))
    assert guard.check_url("HTTPS://EXAMPLE.COM./path", resolve=False).allowed


def test_path_prefix_restriction() -> None:
    policy = build_scope_policy("https://example.com")
    policy.path_prefixes = ["/api/"]
    guard = ScopeGuard(policy)
    assert guard.check_url("https://example.com/api/v1/users", resolve=False).allowed
    assert guard.check_url("https://example.com/admin", resolve=False).allowed is False
    assert guard.check_url("https://example.com/admin", resolve=False).verdict.value == "denied_path"


# --------------------------------------------------------------------------- #
# Address checks
# --------------------------------------------------------------------------- #


def test_loopback_is_refused_by_default() -> None:
    guard = ScopeGuard(build_scope_policy("http://127.0.0.1:8000", extra_hosts=["127.0.0.1"]))
    decision = guard.check_url("http://127.0.0.1:8000/", resolve=False)
    assert decision.allowed is False
    assert decision.verdict.value == "denied_private_address"


def test_loopback_is_allowed_with_explicit_opt_in() -> None:
    guard = ScopeGuard(
        build_scope_policy("http://127.0.0.1:8000", extra_hosts=["127.0.0.1"], allow_private=True)
    )
    assert guard.check_url("http://127.0.0.1:8000/", resolve=False).allowed


def test_localhost_hostname_is_always_refused() -> None:
    guard = ScopeGuard(
        build_scope_policy("http://localhost:8000", extra_hosts=["localhost"], allow_private=True)
    )
    decision = guard.check_url("http://localhost:8000/", resolve=False)
    assert decision.allowed is False


@pytest.mark.parametrize(
    "host",
    [
        "2130706433",  # decimal encoding of 127.0.0.1
        "0x7f000001",  # hex encoding
        "017700000001",  # octal encoding
        "127.1",  # short form
        "0",
        "[::1]",
        "[::ffff:127.0.0.1]",
        "169.254.169.254",  # cloud metadata
        "10.0.0.1",
        "192.168.1.1",
        "172.16.0.1",
        "100.64.0.1",  # CGNAT
        "metadata.google.internal",
    ],
)
def test_obfuscated_and_internal_hosts_are_refused(host: str) -> None:
    """Every one of these must be refused even when explicitly listed in scope."""
    policy = build_scope_policy("https://example.com", extra_hosts=[host])
    guard = ScopeGuard(policy)
    decision = guard.check_url(f"https://{host}/", resolve=False)
    assert decision.allowed is False, f"{host} was allowed"


@pytest.mark.parametrize(
    ("address", "blocked"),
    [
        ("127.0.0.1", True),
        ("10.1.2.3", True),
        ("169.254.169.254", True),
        ("100.64.0.1", True),
        ("::1", True),
        ("fe80::1", True),
        ("224.0.0.1", True),
        ("93.184.216.34", False),
        ("2606:2800:220:1:248:1893:25c8:1946", False),
    ],
)
def test_address_classification(address: str, blocked: bool) -> None:
    is_blocked, _reason = _is_blocked_address(ipaddress.ip_address(address))
    assert is_blocked is blocked


def test_dns_rebinding_to_loopback_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """A public hostname resolving to a private address must be refused."""
    guard = ScopeGuard(build_scope_policy("https://rebind.example.com"))

    def fake_getaddrinfo(host, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        if host == "rebind.example.com":
            return [(2, 1, 6, "", ("127.0.0.1", 0))]
        raise OSError("unexpected host")

    monkeypatch.setattr("app.policy.scope.socket.getaddrinfo", fake_getaddrinfo)
    decision = guard.check_url("https://rebind.example.com/", resolve=True)
    assert decision.allowed is False
    assert decision.verdict.value == "denied_private_address"


def test_unresolvable_host_is_refused_without_spending_a_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import socket as socket_module

    guard = ScopeGuard(build_scope_policy("https://nx.example.com"))

    def failing_getaddrinfo(*args, **kwargs):  # noqa: ANN002, ANN003
        raise socket_module.gaierror("name or service not known")

    monkeypatch.setattr("app.policy.scope.socket.getaddrinfo", failing_getaddrinfo)
    decision = guard.check_url("https://nx.example.com/", resolve=True)
    assert decision.allowed is False
    assert decision.verdict.value == "denied_unresolved"


def test_resolution_can_be_skipped_for_annotation() -> None:
    """``resolve=False`` must not perform a lookup, so link annotation stays cheap."""
    guard = ScopeGuard(build_scope_policy("https://example.com"))
    assert guard.check_url("https://example.com/anything", resolve=False).allowed


def test_guard_describe_is_reportable() -> None:
    guard = ScopeGuard(build_scope_policy("https://example.com", allow_private=False))
    described = guard.describe()
    assert described["target"] == "https://example.com"
    assert "example.com" in described["allowed_hosts"]
    assert described["allow_private_addresses"] is False
