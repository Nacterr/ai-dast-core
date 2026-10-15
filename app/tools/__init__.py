"""Tool layer: registry, controlled resources and the MVP tool set.

Layout follows one concern per module:

* :mod:`app.tools.registry`     - the allowlist and the dispatch pipeline
* :mod:`app.tools.base`         - the tool contract and result envelope
* :mod:`app.tools.context`      - the controlled resources a tool may use
* :mod:`app.tools.browser`      - Playwright session with request-time scope checks
* :mod:`app.tools.http_client`  - scope-aware, rate-limited HTTP client
* :mod:`app.tools.discovery`    - browser_open, extract_links/forms/scripts
* :mod:`app.tools.passive_checks` - check_headers, check_cookies
* :mod:`app.tools.catalog`      - the concrete registry the application uses
"""

from app.tools.base import Tool, ToolExecutionError, ToolOutcome, ToolUnavailableError
from app.tools.catalog import build_default_registry
from app.tools.context import ToolContext
from app.tools.registry import ToolNotFoundError, ToolRegistry

__all__ = [
    "Tool",
    "ToolContext",
    "ToolExecutionError",
    "ToolNotFoundError",
    "ToolOutcome",
    "ToolRegistry",
    "ToolUnavailableError",
    "build_default_registry",
]
