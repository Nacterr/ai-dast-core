# Vulnerable demo target

`tools/demo_target.py` is a local-only training application for exercising this scanner.
It is intentionally insecure and uses synthetic data. It does not make outbound requests or
read files from the host, even on routes that model SSRF or path traversal.

## Run it

```powershell
.\.venv\Scripts\python.exe -m tools.demo_target --port 8099
```

Use `http://127.0.0.1:8099` as the scan target. Keep it bound to loopback. The default port
is ephemeral when `--port 0` is used. `--soft-404` is available for testing catch-all 404
handling.

## Deliberate weaknesses

| Route | Training weakness |
| --- | --- |
| `/products?q=...` | Error-based SQL injection; fake database errors are reflected |
| `/search?q=...` | Reflected output without HTML escaping |
| `/redirect?next=...` | Open redirect; `Location` is caller-controlled |
| `/api/v1/users/<id>/profile` | IDOR; arbitrary user IDs are returned without authentication |
| `/download?file=...` | Path traversal simulation using synthetic `/etc/passwd` content |
| `/fetch?url=...` | SSRF simulation; arbitrary URLs are accepted, but never fetched |
| `/debug/vars` | Unauthenticated debug/configuration disclosure |
| `/api/v1/users/profile` | POST mass-assignment training route |
| `/api/reflect` | Credentialed reflected CORS policy |
| `/.env`, `/.git/config`, `/server-status` | Exposed sensitive files and server information |
| `/` | Weak cookies, missing security headers, login/checkout forms without complete CSRF protection |

The demo deliberately does not execute commands, alter the host, contact external systems, or
contain real credentials. Do not expose it beyond a controlled local test environment.
