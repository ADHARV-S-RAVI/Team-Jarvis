"""24/7 durable SQLite-backed background worker with restart recovery."""

from __future__ import annotations

from datetime import datetime, timezone
import logging
import threading
import time

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from backend.app.config import get_settings
from backend.app.datalab.service import run_file_verification_pipeline
from backend.app.db.models import BackgroundJob
from backend.app.telemetry.bus import telemetry_bus

logger = logging.getLogger(__name__)


class DurableBackgroundWorker:
    """Polls background_jobs and recovers interrupted RUNNING jobs on startup."""

    def __init__(self) -> None:
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._started_at: float | None = None
        self._session_factory: sessionmaker | None = None

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    @property
    def uptime_seconds(self) -> float:
        if not self._started_at or not self.is_running:
            return 0.0
        return round(time.monotonic() - self._started_at, 2)

    def start(self, session_factory: sessionmaker) -> None:
        if self.is_running:
            return
        self._session_factory = session_factory
        self._stop_event.clear()
        self._started_at = time.monotonic()
        self._recover_interrupted_jobs()
        self._thread = threading.Thread(target=self._run_loop, name="qshield-worker", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 3.0) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)

    def _recover_interrupted_jobs(self) -> None:
        if not self._session_factory:
            return
        try:
            with self._session_factory() as db:
                stuck = list(
                    db.execute(select(BackgroundJob).where(BackgroundJob.status == "RUNNING")).scalars().all()
                )
                for job in stuck:
                    job.status = "QUEUED" if job.attempts < job.max_attempts else "FAILED"
                    job.error_message = "Recovered after worker restart"
                    job.updated_at = datetime.now(timezone.utc)
                if stuck:
                    db.commit()
        except Exception as exc:
            logger.debug("Worker startup recovery skipped: %s", type(exc).__name__)

    def _run_loop(self) -> None:
        poll_s = get_settings().worker_poll_seconds
        while not self._stop_event.is_set():
            did_work = False
            if self._session_factory:
                try:
                    with self._session_factory() as db:
                        did_work = self._process_next_job(db)
                except Exception as exc:
                    logger.debug("Worker loop error: %s", type(exc).__name__)
            if not did_work:
                self._stop_event.wait(poll_s)

    def _process_next_job(self, db: Session) -> bool:
        job = db.execute(
            select(BackgroundJob)
            .where(BackgroundJob.status.in_(("QUEUED", "RETRYING")))
            .order_by(BackgroundJob.created_at.asc())
            .limit(1)
        ).scalar_one_or_none()
        if job is None:
            return False

        try:
            if job.job_type == "VERIFY_FILE":
                run_file_verification_pipeline(db, file_id=job.target_id, job_id=job.id)
            else:
                job.status = "COMPLETED"
                job.progress_pct = 100
                job.completed_at = datetime.now(timezone.utc)
                db.commit()
        except Exception as exc:
            job.status = "RETRYING" if job.attempts < job.max_attempts else "FAILED"
            job.error_message = f"{type(exc).__name__}: {str(exc)[:200]}"
            job.updated_at = datetime.now(timezone.utc)
            db.commit()
            telemetry_bus.publish("job_failed", {"job_id": job.id, "status": job.status})
        return True


background_worker = DurableBackgroundWorker()
