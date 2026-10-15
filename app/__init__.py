"""AI DAST core: a scope-restricted web DAST agent driven by an AI planner.

The architecture in one sentence: the AI decides *what to do next* by choosing from a
fixed, typed tool catalogue, and the harness decides *what is possible* - it owns
scope, permissions, budgets, the browser, HTTP egress and the report.

See ``docs/ARCHITECTURE.md`` for the full design and ``docs/SECURITY-MODEL.md`` for
the threat model and its honest limits.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
