"""Scope guard: the single authority on what the harness may contact.

Threat model
------------
The AI planner is untrusted input. It may hallucinate a host, be socially
engineered via page content (prompt injection inside the target's HTML), or
simply be wrong. Therefore *no* outbound action happens without passing through
this module. It defends against:

1. **Out-of-scope hosts** - allowlist with wildcard support.
2. **DNS rebinding / SSRF pivot** - hostnames are resolved and every resolved
   address is checked, so ``evil.example.com -> 127.0.0.1`` is refused.
3. **Obfuscated literals** - decimal/octal/hex IPv4, IPv6 with zone ids, and
   userinfo tricks (``https://allowed.com@evil.com``) are normalised before the
   check, and the *hostname* is what is matched, never the raw string.
4. **Scheme abuse** - only ``http``/``https``; ``file:``, ``gopher:``, ``data:``
   and friends are refused.
5. **Port scanning** - only explicitly allowed ports.
6. **Redirect escapes** - redirect chains are followed manually so every hop is
   re-validated; a hop that leaves scope stops the chain.

The guard is intentionally side-effect free apart from a DNS cache, so it can be
unit tested exhaustively.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field
from enum import StrEnum
from urllib.parse import unquote, urlsplit

from app.models.tools import MAX_URL_LEN
from app.models.scan import ScopePolicy


class ScopeVerdict(StrEnum):
    """Outcome of a scope check."""

    ALLOWED = "allowed"
    DENIED_SCHEME = "denied_scheme"
    DENIED_HOST = "denied_host"
    DENIED_PORT = "denied_port"
    DENIED_PATH = "denied_path"
    DENIED_PRIVATE_ADDRESS = "denied_private_address"
    DENIED_MALFORMED = "denied_malformed"
    DENIED_UNRESOLVED = "denied_unresolved"


@dataclass(frozen=True)
class ScopeDecision:
    """Immutable result of a scope check."""

    allowed: bool
    verdict: ScopeVerdict
    reason: str = ""
    url: str = ""
    host: str = ""
    port: int | None = None
    scheme: str = ""
    resolved_ips: tuple[str, ...] = ()

    def __bool__(self) -> bool:  # allows ``if decision:``
        return self.allowed


@dataclass
class _DnsCache:
    """Small positive/negative DNS cache with a TTL.

    Both successful and failed lookups are cached: a hostile planner cannot use
    repeated lookups as a timing oracle, and a flaky resolver cannot stall the scan.
    """

    ttl_s: float = 300.0
    _cache: dict[str, tuple[float, tuple[str, ...], str]] = field(default_factory=dict)

    def resolve(self, host: str, now: float) -> tuple[tuple[str, ...], str]:
        """Return ``(addresses, error)``. ``addresses`` is empty on failure."""
        cached = self._cache.get(host)
        if cached and now - cached[0] < self.ttl_s:
            return cached[1], cached[2]

        addresses: tuple[str, ...] = ()
        error = ""
        try:
            infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
            addresses = tuple(sorted({info[4][0] for info in infos}))
        except (socket.gaierror, UnicodeError, OSError) as exc:
            error = f"DNS resolution failed: {type(exc).__name__}"
        self._cache[host] = (now, addresses, error)
        return addresses, error

    def clear(self) -> None:
        self._cache.clear()


# Suffixes that must never be reachable, matched on the literal hostname before DNS.
_BLOCKED_HOST_SUFFIXES: tuple[str, ...] = (
    ".localhost",
    ".local",
    ".internal",
    ".intranet",
    ".corp",
    ".home.arpa",
    ".in-addr.arpa",
    ".ip6.arpa",
    ".onion",
)

_BLOCKED_HOST_EXACT: frozenset[str] = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "metadata",
        "metadata.google.internal",
        "instance-data",
    }
)


def _normalize_host(raw_host: str) -> str:
    """Lowercase, strip brackets/trailing dot, and decode percent-escapes.

    ``https://example.com%2Eevil.com`` and ``[::1]`` are normalised here so later
    comparisons never operate on an ambiguous string.
    """
    host = unquote(raw_host).strip().lower()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if host.endswith(".") and len(host) > 1:
        host = host[:-1]
    # Strip an IPv6 zone id such as fe80::1%eth0 - it is not part of the address.
    if "%" in host:
        host = host.split("%", 1)[0]
    return host


_IPV4_CHARS = re.compile(r"\A[0-9a-fx.]+\Z", re.IGNORECASE)


def _parse_ip_literal(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Parse a host as an IP literal, including non-dotted IPv4 notations.

    ``socket.inet_aton`` accepts ``2130706433``, ``0177.0.0.1``, ``0x7f000001`` and
    ``127.1`` - all of which mean 127.0.0.1 and all of which are used to slip past naive
    scope checks that only test for the dotted-quad form. Any hostname built only from
    digits, hex digits, ``x`` and dots is therefore treated as a potential literal and
    handed to ``inet_aton``. Genuine domain names contain other letters, so they never
    reach that call and no DNS lookup is triggered from here.
    """
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass

    if not _IPV4_CHARS.match(host):
        return None

    try:
        packed = socket.inet_aton(host)
    except (OSError, ValueError):
        return None
    try:
        return ipaddress.IPv4Address(packed)
    except ValueError:
        return None


def _is_blocked_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> tuple[bool, str]:
    """Return ``(blocked, reason)`` for an IP address.

    Anything that is not globally routable is refused by default: this covers
    loopback, RFC1918, link-local (including the cloud metadata address
    169.254.169.254), CGNAT, multicast, reserved and unspecified ranges.
    """
    checks: tuple[tuple[bool, str], ...] = (
        (address.is_loopback, "loopback address"),
        (address.is_private, "private/non-routable address"),
        (address.is_link_local, "link-local address (often cloud metadata)"),
        (address.is_multicast, "multicast address"),
        (address.is_reserved, "reserved address"),
        (address.is_unspecified, "unspecified address"),
    )
    for is_bad, reason in checks:
        if is_bad:
            return True, reason
    # CGNAT 100.64.0.0/10 is not flagged by is_private on all Python versions.
    if isinstance(address, ipaddress.IPv4Address) and address in ipaddress.ip_network(
        "100.64.0.0/10"
    ):
        return True, "carrier-grade NAT address"
    # 6to4 / Teredo can tunnel to private space.
    if isinstance(address, ipaddress.IPv6Address) and address.sixtofour is not None:
        if address.sixtofour.is_private or address.sixtofour.is_loopback:
            return True, "6to4 address embedding a private IPv4 address"
    return False, ""


def host_matches_pattern(host: str, pattern: str) -> bool:
    """Match ``host`` against an exact host or a ``*.example.com`` wildcard.

    A wildcard matches sub-domains only, never the apex: ``*.example.com`` matches
    ``a.example.com`` but not ``example.com``. Include both entries when the apex
    should be in scope - being explicit here is what keeps scope auditable.
    """
    host = _normalize_host(host)
    pattern = _normalize_host(pattern)
    if not pattern or not host:
        return False
    if pattern.startswith("*."):
        suffix = pattern[2:]
        if not suffix:
            return False
        return host.endswith("." + suffix) and host != suffix
    if pattern.startswith("."):
        suffix = pattern[1:]
        return bool(suffix) and (host == suffix or host.endswith("." + suffix))
    return host == pattern


class ScopeGuard:
    """Validates every outbound action against a resolved :class:`ScopePolicy`.

    Usage::

        guard = ScopeGuard(policy)
        decision = guard.check_url(user_url)
        if not decision:
            return denied(decision.reason)
    """

    def __init__(self, policy: ScopePolicy, *, clock=None, dns: _DnsCache | None = None) -> None:
        self.policy = policy
        self._clock = clock or __import__("time").monotonic
        self._dns = dns or _DnsCache()
        self._allowed_schemes = {s.lower() for s in policy.allowed_schemes}
        self._allowed_ports = set(policy.allowed_ports)
        self._path_prefixes = tuple(policy.path_prefixes or ["/"])

    # -- public API -------------------------------------------------------- #

    @property
    def target_host(self) -> str:
        return _normalize_host(urlsplit(self.policy.target).hostname or "")

    def check_url(self, url: str, *, resolve: bool = True) -> ScopeDecision:
        """Full check of a URL: shape, scheme, host allowlist, port, path, addresses.

        Set ``resolve=False`` for purely syntactic checks (for example when
        annotating a link in a report without performing a lookup).
        """
        if not isinstance(url, str) or not url or len(url) > MAX_URL_LEN:
            return self._deny(ScopeVerdict.DENIED_MALFORMED, "URL is empty, not a string, or too long", url)

        try:
            parts = urlsplit(url)
        except ValueError as exc:
            return self._deny(ScopeVerdict.DENIED_MALFORMED, f"URL could not be parsed: {exc}", url)

        scheme = (parts.scheme or "").lower()
        if scheme not in self._allowed_schemes:
            return self._deny(
                ScopeVerdict.DENIED_SCHEME,
                f"scheme '{scheme or '(none)'}' is not allowed; allowed: "
                f"{', '.join(sorted(self._allowed_schemes))}",
                url,
            )

        if not parts.netloc:
            return self._deny(ScopeVerdict.DENIED_MALFORMED, "URL has no host component", url)

        host = _normalize_host(parts.hostname or "")
        if not host:
            return self._deny(ScopeVerdict.DENIED_MALFORMED, "URL has no usable hostname", url)

        # Reject embedded credentials: they are a classic host-confusion vector and
        # the harness never needs them at the URL level.
        if parts.username or parts.password:
            return self._deny(
                ScopeVerdict.DENIED_MALFORMED,
                "URL contains embedded credentials, which the harness refuses to use",
                url,
                host=host,
                scheme=scheme,
            )

        try:
            port = parts.port
        except ValueError:
            return self._deny(
                ScopeVerdict.DENIED_MALFORMED, "URL contains an invalid port", url, host=host
            )
        effective_port = port if port is not None else (443 if scheme == "https" else 80)

        if effective_port not in self._allowed_ports:
            return self._deny(
                ScopeVerdict.DENIED_PORT,
                f"port {effective_port} is not in the allowed set "
                f"{{{', '.join(str(p) for p in sorted(self._allowed_ports))}}}",
                url,
                host=host,
                port=effective_port,
                scheme=scheme,
            )

        if not self._path_allowed(parts.path or "/"):
            return self._deny(
                ScopeVerdict.DENIED_PATH,
                f"path '{parts.path}' is outside the allowed prefixes "
                f"{{{', '.join(self._path_prefixes)}}}",
                url,
                host=host,
                port=effective_port,
                scheme=scheme,
            )

        if self._host_is_denied(host):
            return self._deny(
                ScopeVerdict.DENIED_HOST,
                f"host '{host}' matches the explicit exclusion list",
                url,
                host=host,
                port=effective_port,
                scheme=scheme,
            )

        if not self._host_is_allowed(host):
            return self._deny(
                ScopeVerdict.DENIED_HOST,
                f"host '{host}' is not in scope; in-scope: "
                f"{', '.join(self.policy.allowed_hosts) or '(none)'}",
                url,
                host=host,
                port=effective_port,
                scheme=scheme,
            )

        addresses, error = self._resolve(host) if resolve else ((), "")
        if resolve:
            if error:
                return self._deny(
                    ScopeVerdict.DENIED_UNRESOLVED,
                    f"host '{host}' could not be resolved ({error}); refusing to spend a request",
                    url,
                    host=host,
                    port=effective_port,
                    scheme=scheme,
                )
            if not addresses:
                return self._deny(
                    ScopeVerdict.DENIED_UNRESOLVED,
                    f"host '{host}' resolved to no addresses",
                    url,
                    host=host,
                    port=effective_port,
                    scheme=scheme,
                )

        literal = _parse_ip_literal(host)
        if literal is not None:
            literal_denial = self._assert_address_usable(literal, url, host, effective_port, scheme)
            if literal_denial is not None:
                return literal_denial

        if not self.policy.allow_private_addresses:
            for raw_address in addresses:
                try:
                    address = ipaddress.ip_address(raw_address)
                except ValueError:
                    continue
                blocked, reason = _is_blocked_address(address)
                if blocked:
                    return self._deny(
                        ScopeVerdict.DENIED_PRIVATE_ADDRESS,
                        (
                            f"host '{host}' resolves to {raw_address}, a {reason}; "
                            "private ranges require --allow-private"
                        ),
                        url,
                        host=host,
                        port=effective_port,
                        scheme=scheme,
                        resolved_ips=addresses,
                    )

        return ScopeDecision(
            allowed=True,
            verdict=ScopeVerdict.ALLOWED,
            reason="in scope",
            url=url,
            host=host,
            port=effective_port,
            scheme=scheme,
            resolved_ips=tuple(addresses),
        )

    def check_redirect(self, url: str) -> ScopeDecision:
        """Check a redirect target. Always block out-of-scope hops in the MVP."""
        decision = self.check_url(url)
        if not decision.allowed:
            return decision
        if self.policy.follow_redirects_out_of_scope:
            # Kept for completeness; the MVP never configures this.
            return decision
        return decision

    def describe(self) -> dict[str, object]:
        """Machine-readable summary of the active scope, for reports."""
        return {
            "target": self.policy.target,
            "allowed_hosts": list(self.policy.allowed_hosts),
            "excluded_hosts": list(self.policy.excluded_hosts),
            "allowed_ports": list(self.policy.allowed_ports),
            "allowed_schemes": list(self.policy.allowed_schemes),
            "path_prefixes": list(self._path_prefixes),
            "allow_private_addresses": self.policy.allow_private_addresses,
            "max_redirects": self.policy.max_redirects,
        }

    # -- internals --------------------------------------------------------- #

    def _resolve(self, host: str) -> tuple[tuple[str, ...], str]:
        literal = _parse_ip_literal(host)
        if literal is not None:
            return (str(literal),), ""
        return self._dns.resolve(host, self._clock())

    def _assert_address_usable(
        self, literal, url: str, host: str, port: int, scheme: str
    ) -> ScopeDecision | None:
        if self.policy.allow_private_addresses:
            return None
        blocked, reason = _is_blocked_address(literal)
        if blocked:
            return self._deny(
                ScopeVerdict.DENIED_PRIVATE_ADDRESS,
                f"host '{host}' is a literal {reason}; private ranges require --allow-private",
                url,
                host=host,
                port=port,
                scheme=scheme,
            )
        return None

    def _host_is_allowed(self, host: str) -> bool:
        if not self.policy.allowed_hosts:
            return False
        # A literal IP is allowed only if it is explicitly listed.
        return any(host_matches_pattern(host, pattern) for pattern in self.policy.allowed_hosts)

    def _host_is_denied(self, host: str) -> bool:
        if any(host_matches_pattern(host, pattern) for pattern in self.policy.excluded_hosts):
            return True
        if host in _BLOCKED_HOST_EXACT:
            return True
        return any(host.endswith(suffix) for suffix in _BLOCKED_HOST_SUFFIXES)

    def _path_allowed(self, path: str) -> bool:
        if not self._path_prefixes or self._path_prefixes == ("/",):
            return True
        normalized = path if path.startswith("/") else "/" + path
        return any(
            normalized == prefix.rstrip("/") or normalized.startswith(prefix)
            for prefix in self._path_prefixes
        )

    @staticmethod
    def _deny(
        verdict: ScopeVerdict,
        reason: str,
        url: str = "",
        *,
        host: str = "",
        port: int | None = None,
        scheme: str = "",
        resolved_ips: tuple[str, ...] = (),
    ) -> ScopeDecision:
        return ScopeDecision(
            allowed=False,
            verdict=verdict,
            reason=reason,
            url=url,
            host=host,
            port=port,
            scheme=scheme,
            resolved_ips=resolved_ips,
        )


def build_scope_policy(
    target: str,
    *,
    extra_hosts: list[str] | None = None,
    excluded_hosts: list[str] | None = None,
    allow_private: bool = False,
    authorized_by: str = "",
    authorization_note: str = "",
    max_redirects: int = 5,
) -> ScopePolicy:
    """Derive a :class:`ScopePolicy` from a target URL plus operator additions.

    The target host is always in scope. When the target host is an apex domain the
    ``www.`` variant is added, because that is the overwhelmingly common redirect
    and refusing it would silently cripple the scan. Everything else must be
    requested explicitly.
    """
    parts = urlsplit(target if "://" in target else f"https://{target}")
    host = _normalize_host(parts.hostname or "")
    if not host:
        raise ValueError(f"could not determine a hostname from target: {target!r}")

    scheme = (parts.scheme or "https").lower()
    port = parts.port or (443 if scheme == "https" else 80)

    allowed: list[str] = [host]
    labels = host.split(".")
    if len(labels) == 2 and not host.startswith("www."):
        allowed.append(f"www.{host}")
    for extra in extra_hosts or []:
        # Preserve an explicit wildcard: '*.example.com' must keep its '*.' prefix so
        # sub-domains match, rather than collapsing to the apex.
        raw = extra.strip().lower()
        if raw.startswith("*."):
            cleaned = "*." + _normalize_host(raw[2:])
        else:
            cleaned = _normalize_host(raw)
        if cleaned and cleaned not in allowed:
            allowed.append(cleaned)

    ports: list[int] = [80, 443]
    if port not in ports:
        ports.append(port)

    return ScopePolicy(
        target=target,
        allowed_hosts=allowed,
        excluded_hosts=[_normalize_host(h) for h in (excluded_hosts or [])],
        allowed_ports=sorted(ports),
        allowed_schemes=["http", "https"],
        path_prefixes=["/"],
        allow_private_addresses=allow_private,
        max_redirects=max_redirects,
        authorized_by=authorized_by,
        authorization_note=authorization_note,
    )
