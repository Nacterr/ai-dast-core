# Safe comparison target

`tools/safe_target.py` is the hardened counterpart to `tools/demo_target.py`. It keeps a
similar URL shape so scanner results can be compared, but applies basic defenses.

Run it locally:

```powershell
.\.venv\Scripts\python.exe -m tools.safe_target --port 8100
```

Scan `http://127.0.0.1:8100` with the same scanner settings used for the vulnerable target.

Expected differences include escaped search output, rejected external redirects, no file or
URL fetching, authentication-required profiles, no exposed debug/config files, secure cookies,
security headers, and a restrictive CORS policy. It is a comparison fixture, not a production
application.
