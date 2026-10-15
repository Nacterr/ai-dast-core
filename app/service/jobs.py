"""Scan job store: background execution, persistence and cancellation.

A scan takes seconds to minutes and uses a real browser, so it cannot run inside an HTTP
request. The store turns a request into a durable *job*:

    submit()  -> queued, persisted, worker picks it up
    worker    -> runs ScanRunner in its own thread, streaming events to a log file
    caller    -> polls status, reads the report, or cancels

Design points that matter:

* **Bounded concurrency.** A semaphore limits how many scans run at once. Default is 1:
  a DAST tool that fans out is a denial-of-service tool, and the targets are usually
  production-adjacent.
* **Textbook two-phase locking.** The lock protects the job registry and the queue, never
  the scan itself. A long scan can never block a status request.
* **Persistence.** Each job writes ``job.json``, ``events.log`` and ``report.json`` into
  its own directory, so history survives a restart and reports are downloadable without
  re-running anything.
* **Cancellation is cooperative.** It is observed between steps, so a job stops at a safe
  point rather than leaving a browser process behind.
"""

from __future__ import annotations

import datetime as _dt
import json
import queue
import threading
import uuid
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app import __version__
from app.models.scan import ScanReport, ScanSession, ScanStatus
from app.orchestrator.loop import ScanRunner
from app.orchestrator.planner import LlmPlanner, ScriptedPlanner
from app.policy.permissions import Capability, ConfirmationGate, PermissionSet
from app.reports.json_report import build_report, write_report
from app.service.config import AuthorisedScan, DeploymentConfig
from app.service.models import JobState, JobStatus, JobSummary, TERMINAL_STATES
from app.tools.catalog import build_default_registry

# How many log lines are kept in memory for the progress view. The full log is always on
# disk; this is only what a polling client sees.
EVENT_TAIL_SIZE = 60
MAX_EVENTS_ON_DISK = 4000


def _now() -> str:
    return _dt.datetime.now(_dt.UTC).isoformat(timespec="seconds")


@dataclass
class ScanJob:
    """One scan, from submission to terminal state."""

    job_id: str
    request_target: str
    authorized_by: str
    authorization_note: str
    planner_name: str
    authorised: AuthorisedScan
    submitted_at: str = field(default_factory=_now)
    state: JobState = JobState.QUEUED
    started_at: str | None = None
    finished_at: str | None = None
    stop_reason: str = ""
    error: str | None = None
    events: deque[str] = field(default_factory=lambda: deque(maxlen=EVENT_TAIL_SIZE))
    session: ScanSession | None = None
    report: ScanReport | None = None
    runner: ScanRunner | None = None
    cancel_event: threading.Event = field(default_factory=threading.Event)

    # -- derived views ----------------------------------------------------- #

    @property
    def terminal(self) -> bool:
        return self.state in TERMINAL_STATES

    def severity_counts(self) -> dict[str, int]:
        if self.report is not None:
            counts = self.report.severity_counts
            return {
                "critical": counts.critical,
                "high": counts.high,
                "medium": counts.medium,
                "low": counts.low,
                "info": counts.info,
            }
        return {}

    def duration_s(self) -> float:
        if not self.started_at:
            return 0.0
        try:
            started = _dt.datetime.fromisoformat(self.started_at)
            finished = (
                _dt.datetime.fromisoformat(self.finished_at) if self.finished_at else _dt.datetime.now(_dt.UTC)
            )
        except ValueError:
            return 0.0
        return max(0.0, (finished - started).total_seconds())

    def status(self) -> JobStatus:
        session = self.session
        counters = dict(session.counters) if session else {}
        progress: dict[str, Any] = {}
        if session:
            progress = {
                "steps_used": counters.get("steps", 0),
                "steps_limit": counters.get("step_limit", 0),
                "tool_calls_used": counters.get("tool_calls", 0),
                "tool_calls_limit": counters.get("tool_call_limit", 0),
                "pages_used": counters.get("pages", 0),
                "pages_limit": counters.get("page_limit", 0),
                "requests_used": counters.get("requests", 0),
                "requests_limit": counters.get("request_limit", 0),
            }
        return JobStatus(
            job_id=self.job_id,
            state=self.state,
            target=self.authorised.target,
            authorized_by=self.authorized_by,
            planner=self.planner_name,
            submitted_at=self.submitted_at,
            started_at=self.started_at,
            finished_at=self.finished_at,
            duration_s=round(self.duration_s(), 2),
            progress=progress,
            counters=counters,
            severity_counts=self.severity_counts(),
            finding_count=len(self.report.findings) if self.report else 0,
            tool_call_count=len(self.report.tool_trace) if self.report else 0,
            stop_reason=self.stop_reason,
            error=self.error,
            recent_events=list(self.events)[-25:],
            scope=self.authorised.scope.model_dump(mode="json"),
        )

    def summary(self) -> JobSummary:
        return JobSummary(
            job_id=self.job_id,
            state=self.state,
            target=self.authorised.target,
            authorized_by=self.authorized_by,
            submitted_at=self.submitted_at,
            finished_at=self.finished_at,
            finding_count=len(self.report.findings) if self.report else 0,
            severity_counts=self.severity_counts(),
        )


class JobStore:
    """Owns the queue, the worker threads and on-disk job history."""

    def __init__(self, deployment: DeploymentConfig, *, registry=None) -> None:
        self.deployment = deployment
        self.registry = registry or build_default_registry()
        self.runs_dir = Path(deployment.runs_dir)
        self.runs_dir.mkdir(parents=True, exist_ok=True)

        self._lock = threading.RLock()
        self._jobs: dict[str, ScanJob] = {}
        self._queue: queue.Queue[str] = queue.Queue()
        self._workers: list[threading.Thread] = []
        self._slots = threading.Semaphore(deployment.max_concurrent_scans)
        self._shutdown = threading.Event()
        self._accepting = True

    # -- lifecycle --------------------------------------------------------- #

    def start(self) -> None:
        """Start the worker threads. Idempotent."""
        with self._lock:
            if self._workers:
                return
            for index in range(self.deployment.max_concurrent_scans):
                worker = threading.Thread(
                    target=self._worker_loop,
                    name=f"scan-worker-{index}",
                    daemon=True,
                )
                worker.start()
                self._workers.append(worker)

    def stop(self, *, timeout: float = 10.0) -> None:
        """Stop accepting work, cancel running scans and join the workers."""
        self._accepting = False
        self._shutdown.set()
        for job in self.list_jobs():
            if not job.terminal:
                self.cancel(job.job_id, reason="service shutting down")
        # Unblock workers parked on the queue.
        for _ in self._workers:
            self._queue.put("")
        for worker in list(self._workers):
            worker.join(timeout=timeout)
        with self._lock:
            self._workers.clear()

    # -- submission -------------------------------------------------------- #

    def submit(self, authorised: AuthorisedScan, *, authorization_note: str = "") -> ScanJob:
        """Queue an authorised scan. Raises RuntimeError when not accepting work."""
        if not self._accepting:
            raise RuntimeError("the service is shutting down and is not accepting new scans")

        job_id = f"job-{_dt.datetime.now(_dt.UTC).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
        job = ScanJob(
            job_id=job_id,
            request_target=authorised.target,
            authorized_by=authorised.scope.authorized_by,
            authorization_note=authorization_note,
            planner_name=(
                f"llm:{authorised.llm_model}" if authorised.planner == "llm" else "scripted-recon-v1"
            ),
            authorised=authorised,
        )

        job_dir = self.runs_dir / job_id
        job_dir.mkdir(parents=True, exist_ok=True)

        with self._lock:
            self._jobs[job_id] = job

        self._persist(job, job_dir)
        self._log(job, f"queued for {authorised.target} (planner={job.planner_name})")
        self._queue.put(job_id)
        return job

    def queue_position(self, job_id: str) -> int:
        """How many jobs are ahead of this one. 0 means it is next or already running."""
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None or job.state is not JobState.QUEUED:
                return 0
            pending = [
                other_id
                for other_id in list(self._queue.queue)
                if other_id and other_id in self._jobs
            ]
        try:
            return max(0, pending.index(job_id))
        except ValueError:
            return 0

    # -- reads ------------------------------------------------------------- #

    def get(self, job_id: str) -> ScanJob | None:
        with self._lock:
            job = self._jobs.get(job_id)
        if job is not None:
            return job
        return self._load_from_disk(job_id)

    def list_jobs(self, *, limit: int = 100) -> list[ScanJob]:
        """All known jobs, newest first, including ones loaded from disk."""
        with self._lock:
            jobs = list(self._jobs.values())
        known = {job.job_id for job in jobs}
        for directory in self._job_directories():
            if directory.name not in known:
                loaded = self._load_from_disk(directory.name)
                if loaded is not None:
                    jobs.append(loaded)
        jobs.sort(key=lambda job: job.submitted_at, reverse=True)
        return jobs[:limit]

    def counts(self) -> tuple[int, int]:
        with self._lock:
            queued = sum(1 for job in self._jobs.values() if job.state is JobState.QUEUED)
            running = sum(1 for job in self._jobs.values() if job.state is JobState.RUNNING)
        return queued, running

    # -- cancellation ------------------------------------------------------ #

    def cancel(self, job_id: str, *, reason: str = "cancelled by the caller") -> bool:
        """Request cancellation. Returns False when the job is unknown or already done."""
        job = self.get(job_id)
        if job is None or job.terminal:
            return False
        job.cancel_event.set()
        if job.state is JobState.QUEUED:
            job.state = JobState.CANCELLED
            job.stop_reason = reason
            job.finished_at = _now()
            self._log(job, f"cancelled while queued: {reason}")
            self._persist(job)
        else:
            job.stop_reason = reason
            self._log(job, f"cancellation requested: {reason}")
            if job.runner is not None:
                job.runner.cancel(reason)
        return True

    # -- worker ------------------------------------------------------------ #

    def _worker_loop(self) -> None:
        while not self._shutdown.is_set():
            try:
                job_id = self._queue.get(timeout=1.0)
            except queue.Empty:
                continue
            if not job_id or self._shutdown.is_set():
                continue
            job = self.get(job_id)
            if job is None or job.state is not JobState.QUEUED:
                continue
            self._run_job(job)

    def _run_job(self, job: ScanJob) -> None:
        acquired = self._slots.acquire(timeout=1.0)
        if not acquired:
            # Re-queue rather than drop it: the semaphore is only contended by our own
            # workers, so this is a transient scheduling artefact.
            self._queue.put(job.job_id)
            return

        try:
            if job.cancel_event.is_set():
                job.state = JobState.CANCELLED
                job.finished_at = _now()
                self._persist(job)
                return

            job.state = JobState.RUNNING
            job.started_at = _now()
            self._log(job, "scan started")
            self._persist(job)

            permissions = self._permissions_for(job)
            confirmation = ConfirmationGate(
                interactive=False,
                auto_approve=not job.authorised.config.require_confirmation,
            )
            job.runner = ScanRunner(
                self.registry,
                planner=self._planner_for(job),
                artifact_dir=self._job_dir(job) / "artifacts",
                permissions=permissions,
                confirmation=confirmation,
                event_sink=lambda message: self._log(job, message),
                quiet=True,
                cancel_event=job.cancel_event,
            )

            session = job.runner.create_session(job.authorised.scope, job.authorised.config)
            job.session = session
            job.runner.run(session)
            job.report = build_report(
                session,
                self.registry,
                planner_name=job.planner_name,
                planner_meta={"planner": job.authorised.planner, "via": "http_api"},
            )
            write_report(job.report, self._job_dir(job))

            job.stop_reason = session.stop_reason or job.stop_reason
            if job.cancel_event.is_set() and session.status is ScanStatus.COMPLETED:
                job.state = JobState.CANCELLED
            elif session.status is ScanStatus.FAILED:
                job.state = JobState.FAILED
                job.error = session.stop_reason
            else:
                job.state = JobState.COMPLETED
            self._log(
                job,
                f"scan finished: {len(job.report.findings)} finding(s), "
                f"state={job.state.value}",
            )
        except Exception as exc:  # noqa: BLE001 - a job must never kill its worker
            job.state = JobState.FAILED
            job.error = f"{type(exc).__name__}: {exc}"
            self._log(job, f"scan failed: {job.error}")
        finally:
            job.finished_at = job.finished_at or _now()
            self._persist(job)
            self._slots.release()

    def _permissions_for(self, job: ScanJob) -> PermissionSet:
        """Capabilities for one job.

        The service grants read-only discovery and HTTP egress. It never grants active
        scanning or private-network reach beyond what the operator authorised, and it
        cannot grant the never-allowed capabilities because those are not in the enum of
        grantable things.
        """
        permissions = PermissionSet()
        if self.deployment.allow_private_addresses:
            permissions.grant(Capability.PRIVATE_NETWORK)
        if getattr(job.authorised, "enable_active", False):
            permissions.grant(Capability.ACTIVE_SCAN)
        if getattr(job.authorised, "enable_injection", False):
            permissions.grant(Capability.INJECTION_PROBE)
        permissions.assert_forbidden_absent()
        return permissions

    def _planner_for(self, job: ScanJob):
        if job.authorised.planner == "llm":
            return LlmPlanner(
                self.registry,
                model=job.authorised.llm_model,
                api_key=getattr(job.authorised, "llm_api_key", "") or self.deployment.llm_api_key(),
                base_url=job.authorised.llm_base_url or None,
            )
        return ScriptedPlanner(
            max_pages=min(6, job.authorised.config.max_pages),
        )

    # -- persistence ------------------------------------------------------- #

    def _job_dir(self, job: ScanJob) -> Path:
        directory = self.runs_dir / job.job_id
        directory.mkdir(parents=True, exist_ok=True)
        return directory

    def _job_directories(self) -> list[Path]:
        try:
            return sorted(
                (entry for entry in self.runs_dir.iterdir() if entry.is_dir()),
                key=lambda entry: entry.name,
                reverse=True,
            )
        except OSError:
            return []

    def _persist(self, job: ScanJob, directory: Path | None = None) -> None:
        target = directory or self._job_dir(job)
        payload = {
            "job_id": job.job_id,
            "state": job.state.value,
            "target": job.authorised.target,
            "authorized_by": job.authorized_by,
            "authorization_note": job.authorization_note,
            "planner": job.planner_name,
            "submitted_at": job.submitted_at,
            "started_at": job.started_at,
            "finished_at": job.finished_at,
            "stop_reason": job.stop_reason,
            "error": job.error,
            "service_version": __version__,
            "scope": job.authorised.scope.model_dump(mode="json"),
            "config": job.authorised.config.model_dump(mode="json"),
            "progress": job.status().progress,
        }
        try:
            (target / "job.json").write_text(
                json.dumps(payload, indent=2, ensure_ascii=False, default=str), encoding="utf-8"
            )
        except OSError:
            pass

    def _log(self, job: ScanJob, message: str) -> None:
        """Append to the in-memory tail and the on-disk log."""
        line = f"{_dt.datetime.now(_dt.UTC).isoformat(timespec='seconds')} {message}"
        job.events.append(message)
        try:
            path = self._job_dir(job) / "events.log"
            with path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
        except OSError:
            pass

    def read_log(self, job: ScanJob, *, tail: int = 500) -> list[str]:
        """Read the job log from disk, newest last."""
        path = self._job_dir(job) / "events.log"
        if not path.exists():
            return list(job.events)
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                lines = handle.readlines()
        except OSError:
            return list(job.events)
        # Cap what is read back so a long scan cannot be used to exhaust memory.
        trimmed = lines[-min(max(0, tail), MAX_EVENTS_ON_DISK) :]
        return [line.rstrip("\n") for line in trimmed]

    def _load_from_disk(self, job_id: str) -> ScanJob | None:
        """Rehydrate a job's metadata from disk so history survives a restart."""
        directory = self.runs_dir / job_id
        metadata_path = directory / "job.json"
        if not metadata_path.exists():
            return None
        try:
            payload = json.loads(metadata_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

        from app.models.scan import ScanConfig, ScopePolicy

        try:
            authorised = AuthorisedScan(
                target=payload["target"],
                scope=ScopePolicy.model_validate(payload["scope"]),
                config=ScanConfig.model_validate(payload["config"]),
                planner="scripted",
            )
        except (KeyError, ValueError):
            return None

        job = ScanJob(
            job_id=payload.get("job_id", job_id),
            request_target=payload.get("target", ""),
            authorized_by=payload.get("authorized_by", ""),
            authorization_note=payload.get("authorization_note", ""),
            planner_name=payload.get("planner", ""),
            authorised=authorised,
            submitted_at=payload.get("submitted_at", _now()),
            state=JobState(payload.get("state", JobState.FAILED.value)),
            started_at=payload.get("started_at"),
            finished_at=payload.get("finished_at"),
            stop_reason=payload.get("stop_reason", ""),
            error=payload.get("error"),
        )

        report_path = directory / "report.json"
        if report_path.exists():
            try:
                job.report = ScanReport.model_validate_json(report_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                job.report = None

        with self._lock:
            self._jobs.setdefault(job.job_id, job)
            return self._jobs[job.job_id]


__all__ = ["EVENT_TAIL_SIZE", "JobStore", "ScanJob"]
