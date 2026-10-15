"""Policy layer: scope, permissions and limits.

The policy layer is deliberately small and dependency-light so it can be audited and
unit tested without a network, a browser, or an LLM.
"""

from app.policy.limits import Budget, LimitExceeded, LimitTracker, RateLimiter
from app.policy.permissions import (
    ArgumentGuard,
    ArgumentVerdict,
    Capability,
    ConfirmationGate,
    ConfirmationRequest,
    ForbiddenCapability,
    PermissionSet,
    PreflightOutcome,
    RequestPolicy,
)
from app.policy.scope import (
    ScopeDecision,
    ScopeGuard,
    ScopeVerdict,
    build_scope_policy,
    host_matches_pattern,
)

__all__ = [
    "ArgumentGuard",
    "ArgumentVerdict",
    "Budget",
    "Capability",
    "ConfirmationGate",
    "ConfirmationRequest",
    "ForbiddenCapability",
    "LimitExceeded",
    "LimitTracker",
    "PermissionSet",
    "PreflightOutcome",
    "RateLimiter",
    "RequestPolicy",
    "ScopeDecision",
    "ScopeGuard",
    "ScopeVerdict",
    "build_scope_policy",
    "host_matches_pattern",
]
