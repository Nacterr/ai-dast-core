"""HTTP service layer: turns the scan engine into callable scan jobs.

The CLI trusts the human at the keyboard. This layer does not trust the caller, so it
re-derives everything from an operator-authored :class:`~app.service.config.DeploymentConfig`.
See :mod:`app.service.config` for the authorisation rules.
"""

from app.service.config import (
    AuthorisedScan,
    DeploymentConfig,
    ScopeRefused,
    authorise_request,
    build_deployment_config,
    capabilities,
)
from app.service.jobs import JobStore, ScanJob
from app.service.models import (
    ErrorResponse,
    JobAccepted,
    JobList,
    JobState,
    JobStatus,
    JobSummary,
    ReportEnvelope,
    ScanRequest,
    ServerCapabilities,
    TERMINAL_STATES,
    ToolListing,
)

__all__ = [
    "AuthorisedScan",
    "DeploymentConfig",
    "ErrorResponse",
    "JobAccepted",
    "JobList",
    "JobState",
    "JobStatus",
    "JobStore",
    "JobSummary",
    "ReportEnvelope",
    "ScanJob",
    "ScanRequest",
    "ScopeRefused",
    "ServerCapabilities",
    "TERMINAL_STATES",
    "ToolListing",
    "authorise_request",
    "build_deployment_config",
    "capabilities",
]
