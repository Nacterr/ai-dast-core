"""Controlled HTTP client for passive checks.

All outbound HTTP in the harness goes through :class:`SafeHttpClient`. It exists so
that scope, rate limiting and request accounting are applied in exactly one place -
including on every redirect hop, which is the case most implementations get wrong.

Redirects are followed manually with ``follow_redirects=False`` because letting
httpx follow them would perform the hop *before* the scope guard could inspect the
target. Each hop is therefore validated, counted and rate limited individually.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import urljoin

from app.policy.limits import LimitExceeded, LimitTracker
from app.policy.scope import ScopeGuard

# Called once per completed exchange. The scan loop uses it to maintain the harness's
# transaction log, which the result tools read. Keeping it a callback means the HTTP client
# stays unaware of sessions and findings.
ExchangeSink = Callable[["HttpExchange"], None]


class EgressDenied(RuntimeError):
    """Raised when the scope guard refuses a request, or a redirect leaves scope."""

    def __init__(self, reason: str, url: str = "") -> None:
        super().__init__(reason)
        self.reason = reason
        self.url = url


@dataclass
class HttpHop:
    """One request/response pair in a (possibly redirected) exchange."""

    url: str
    method: str
    status_code: int
    headers: dict[str, str] = field(default_factory=dict)
    location: str | None = None
    body_prefix: str = ""
    body_bytes: int = 0
    elapsed_ms: int = 0


@dataclass
class HttpExchange:
    """The complete result of one logical request, including its redirect chain."""

    requested_url: str
    final_url: str
    status_code: int | None
    headers: dict[str, str] = field(default_factory=dict)
    hops: list[HttpHop] = field(default_factory=list)
    body_prefix: str = ""
    body_bytes: int = 0
    error: str = ""
    tls: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.status_code is not None and not self.error

    def header(self, name: str, default: str = "") -> str:
        """Case-insensitive header lookup."""
        return self.headers.get(name.lower(), default)

    def all_set_cookie(self) -> list[str]:
        """Every ``Set-Cookie`` value across every hop, in order."""
        values: list[str] = []
        for hop in self.hops:
            raw = hop.headers.get("set-cookie")
            if not raw:
                continue
            values.extend(_split_set_cookie_header(raw))
        return values


def _split_set_cookie_header(raw: str) -> list[str]:
    """Split a combined ``Set-Cookie`` header value into individual cookies.

    ``httpx`` collapses repeated headers into one comma-joined string for some
    transports, and ``Expires=Wed, 21 Oct 2026 07:28:00 GMT`` contains a comma.
    This splits on commas that are followed by a ``name=`` token while tracking the
    ``Expires`` attribute so its date is not mistaken for a separator.
    """
    cookies: list[str] = []
    current: list[str] = []
    index = 0
    length = len(raw)
    while index < length:
        char = raw[index]
        if char == ",":
            rest = raw[index + 1 :].lstrip()
            # A new cookie starts with `name=`, but not with a known attribute.
            head = rest.split("=", 1)[0].strip().lower()
            is_attribute = head in {
                "expires",
                "max-age",
                "domain",
                "path",
                "secure",
                "httponly",
                "samesite",
                "priority",
                "partitioned",
            }
            if rest and not is_attribute and "=" in rest.split(";", 1)[0]:
                cookies.append("".join(current).strip())
                current = []
                index += 1
                continue
        current.append(char)
        index += 1
    tail = "".join(current).strip()
    if tail:
        cookies.append(tail)
    return [cookie for cookie in cookies if cookie]


class SafeHttpClient:
    """Scope-aware, rate-limited HTTP client."""

    def __init__(
        self,
        scope: ScopeGuard,
        limits: LimitTracker,
        *,
        user_agent: str = "ai-dast-core/0.1",
        body_limit_bytes: int = 2_000_000,
        timeout_s: float = 15.0,
        exchange_sink: ExchangeSink | None = None,
    ) -> None:
        self._scope = scope
        self._limits = limits
        self._user_agent = user_agent
        self._body_limit = body_limit_bytes
        self._timeout_s = timeout_s
        self._exchange_sink = exchange_sink
        self._client: Any = None
        self._closed = False

    # -- lifecycle --------------------------------------------------------- #

    def _ensure_client(self) -> Any:
        if self._client is not None:
            return self._client
        try:
            import httpx
        except ImportError as exc:  # pragma: no cover - dependency error path
            raise RuntimeError(
                "the 'httpx' package is not installed; run: pip install httpx"
            ) from exc
        self._client = httpx.Client(
            follow_redirects=False,
            verify=True,
            timeout=httpx.Timeout(self._timeout_s),
            headers={
                "User-Agent": self._user_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Connection": "close",
            },
        )
        return self._client

    def close(self) -> None:
        if self._client is not None and not self._closed:
            try:
                self._client.close()
            except Exception:  # noqa: BLE001
                pass
        self._closed = True
        self._client = None

    def __enter__(self) -> SafeHttpClient:
        self._ensure_client()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # -- requests ---------------------------------------------------------- #

    def request(
        self,
        url: str,
        *,
        method: str = "GET",
        follow_redirects: bool = True,
        max_redirects: int | None = None,
        read_body: bool = True,
        extra_headers: dict[str, str] | None = None,
    ) -> HttpExchange:
        """Perform a scope-checked request, following redirects hop by hop.

        ``extra_headers`` exists so a tool can send harness-chosen request headers - for
        example the fixed ``Origin`` that :mod:`app.tools.cors` needs. They are never derived
        from AI input; a tool that took a caller-supplied header would be handing the model a
        raw-request primitive.
        """
        method = method.upper()
        decision = self._scope.check_url(url)
        if not decision.allowed:
            raise EgressDenied(decision.reason, url)

        hop_cap = self._scope.policy.max_redirects if max_redirects is None else max_redirects
        client = self._ensure_client()

        exchange = HttpExchange(requested_url=url, final_url=url, status_code=None)
        try:
            self._walk(
                exchange,
                client=client,
                method=method,
                hop_cap=hop_cap,
                follow_redirects=follow_redirects,
                read_body=read_body,
                extra_headers=extra_headers,
            )
        finally:
            # Recorded even when the walk raised: a refused first hop is exactly the kind of
            # event the transaction log should show.
            exchange.tls = self._tls_summary(client, exchange.final_url)
            self._emit(exchange)
        return exchange

    def _walk(
        self,
        exchange: HttpExchange,
        *,
        client: Any,
        method: str,
        hop_cap: int,
        follow_redirects: bool,
        read_body: bool,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        """Follow the redirect chain, validating and accounting for every hop."""
        current_url = exchange.requested_url
        current_method = method
        visited: set[str] = set()

        for _hop_index in range(hop_cap + 1):
            if current_url in visited:
                exchange.error = f"redirect loop detected at {current_url}"
                return
            visited.add(current_url)

            hop_decision = self._scope.check_url(current_url)
            if not hop_decision.allowed:
                if not exchange.hops:
                    raise EgressDenied(hop_decision.reason, current_url)
                # A redirect left scope: stop here and report it as data.
                exchange.error = (
                    f"redirect blocked: {hop_decision.reason} (stopped at {current_url})"
                )
                return

            self._limits.before_request()

            started = time.monotonic()
            try:
                response = client.request(
                    current_method, current_url, headers=extra_headers or None
                )
            except Exception as exc:  # noqa: BLE001 - network errors are data
                exchange.error = f"{type(exc).__name__}: {str(exc)[:300]}"
                break
            elapsed_ms = int((time.monotonic() - started) * 1000)

            headers = {key.lower(): value for key, value in response.headers.items()}
            location = headers.get("location")

            body_prefix = ""
            body_bytes = 0
            if read_body and current_method != "HEAD":
                try:
                    raw = response.content[: self._body_limit]
                    body_bytes = len(response.content)
                    body_prefix = raw.decode(response.encoding or "utf-8", errors="replace")
                except Exception:  # noqa: BLE001
                    body_prefix = ""

            hop = HttpHop(
                url=current_url,
                method=current_method,
                status_code=response.status_code,
                headers=headers,
                location=location,
                body_prefix=body_prefix[:4000],
                body_bytes=body_bytes,
                elapsed_ms=elapsed_ms,
            )
            exchange.hops.append(hop)
            exchange.final_url = current_url
            exchange.status_code = response.status_code
            exchange.headers = headers
            exchange.body_prefix = hop.body_prefix
            exchange.body_bytes = body_bytes

            if not follow_redirects or response.status_code not in (301, 302, 303, 307, 308):
                return
            if not location:
                return

            next_url = urljoin(current_url, location)
            next_decision = self._scope.check_url(next_url)
            if not next_decision.allowed:
                exchange.error = f"redirect to {next_url} refused: {next_decision.reason}"
                return
            # 303 always becomes GET; 301/302 historically do too for non-GET.
            if response.status_code == 303 or (
                response.status_code in (301, 302) and current_method not in ("GET", "HEAD")
            ):
                current_method = "GET"
            current_url = next_url
        else:
            exchange.error = f"exceeded {hop_cap} redirects"

    def _emit(self, exchange: HttpExchange) -> None:
        """Hand a completed exchange to the sink, if one is attached.

        A sink failure must never break a scan: the transaction log is a convenience, not a
        correctness requirement.
        """
        if self._exchange_sink is None:
            return
        try:
            self._exchange_sink(exchange)
        except Exception:  # noqa: BLE001
            pass

    def get(self, url: str, **kwargs: Any) -> HttpExchange:
        return self.request(url, method="GET", **kwargs)

    def head(self, url: str, **kwargs: Any) -> HttpExchange:
        return self.request(url, method="HEAD", read_body=False, **kwargs)

    # -- TLS --------------------------------------------------------------- #

    @staticmethod
    def _tls_summary(client: Any, url: str) -> dict[str, Any]:
        """Best-effort TLS facts for a completed HTTPS exchange.

        Reads the peer certificate through the transport extension when the
        installed HTTP stack exposes it; otherwise reports what it can prove and
        says so, rather than guessing.
        """
        summary: dict[str, Any] = {"scheme": "https" if url.startswith("https") else "http"}
        if summary["scheme"] != "https":
            return summary

        summary["certificate_verified"] = True
        transport = getattr(client, "_transport", None)
        pool = getattr(transport, "_pool", None)
        if pool is None:
            summary["note"] = "certificate details not exposed by this HTTP transport"
            return summary
        try:
            connections = getattr(pool, "connections", None)
            if not connections:
                summary["note"] = "no pooled connection available for inspection"
                return summary
            connection = next(iter(connections))
            stream = getattr(connection, "_network_stream", None)
            ssl_object = getattr(stream, "_ssl_object", None) if stream is not None else None
            if ssl_object is None:
                summary["note"] = "certificate details not exposed by this HTTP transport"
                return summary
        except Exception as exc:  # noqa: BLE001
            summary["note"] = f"certificate introspection failed: {type(exc).__name__}"
            return summary

        return summarize_tls(ssl_object)


def summarize_tls(ssl_object: Any) -> dict[str, Any]:
    """Extract TLS facts from an ``ssl.SSLObject``-shaped thing.

    Deliberately a module-level pure function taking the object, rather than a method that
    hunts for it through httpx internals: this is the part with logic worth testing, and it
    can be tested with a stand-in object instead of a real socket.

    Everything is defensive. The certificate mapping is populated by OpenSSL through the
    stdlib, but a transport can hand back an object with a partial API, and a security tool
    must degrade to "unknown" rather than crash or invent.
    """
    summary: dict[str, Any] = {"scheme": "https", "certificate_verified": True}

    try:
        summary["protocol"] = str(ssl_object.version() or "")
    except Exception:  # noqa: BLE001
        summary["protocol"] = ""

    try:
        cipher = ssl_object.cipher()
        summary["cipher"] = str(cipher[0]) if cipher else ""
    except Exception:  # noqa: BLE001
        summary["cipher"] = ""

    try:
        certificate = ssl_object.getpeercert() or {}
    except Exception:  # noqa: BLE001
        certificate = {}

    if not certificate:
        summary["note"] = "certificate details not exposed by this HTTP transport"
        return summary

    summary["subject"] = _flatten_name(certificate.get("subject", ()))
    summary["issuer"] = _flatten_name(certificate.get("issuer", ()))
    summary["not_before"] = str(certificate.get("notBefore", ""))
    summary["not_after"] = str(certificate.get("notAfter", ""))
    summary["subject_alt_names"] = [
        str(value) for key, value in certificate.get("subjectAltName", ()) if key == "DNS"
    ][:50]
    return summary


def _flatten_name(entries: Any) -> str:
    """Render an ``ssl`` distinguished-name structure as a readable string."""
    try:
        parts = [f"{key}={value}" for group in entries for key, value in group]
    except Exception:  # noqa: BLE001
        return ""
    return ", ".join(parts)


def describe_limits_exceeded(exc: LimitExceeded) -> str:
    return f"limit '{exc.kind}' reached: {exc.message}"


__all__ = [
    "EgressDenied",
    "ExchangeSink",
    "HttpExchange",
    "HttpHop",
    "LimitExceeded",
    "SafeHttpClient",
    "describe_limits_exceeded",
    "summarize_tls",
]
