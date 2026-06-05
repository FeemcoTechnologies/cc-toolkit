import logging
"""Background job queue with SSE (Server-Sent Events) support.

JobManager tracks async tasks (scans, reports, etc.) and pushes
progress updates to listening SSE clients in real time.
"""

import json
import queue
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Generator, Optional
logger = logging.getLogger(__name__)


class JobInfo:
    __slots__ = (
        "id", "type", "title", "status", "progress", "total_steps",
        "current_step", "message", "result", "error",
        "created_at", "completed_at", "cancelled",
    )

    def __init__(self, job_id: str, job_type: str, title: str, total_steps: int = 100):
        self.id = job_id
        self.type = job_type
        self.title = title
        self.status = "queued"
        self.progress = 0
        self.total_steps = total_steps
        self.current_step = 0
        self.message = ""
        self.result = None
        self.error = None
        self.created_at = datetime.now(timezone.utc).isoformat()
        self.completed_at = None
        self.cancelled = False

    def to_dict(self) -> dict:
        return {s: getattr(self, s) for s in self.__slots__}


class JobManager:
    """Thread-safe job manager with SSE listener support."""

    def __init__(self, max_history: int = 50):
        self._jobs: Dict[str, JobInfo] = {}
        self._listeners: Dict[str, set] = {}
        self._lock = threading.Lock()
        self._max_history = max_history

    # -- Job lifecycle -------------------------------------------------------

    def create(self, job_type: str, title: str, total_steps: int = 100) -> str:
        job_id = uuid.uuid4().hex[:8]
        job = JobInfo(job_id, job_type, title, total_steps)
        with self._lock:
            self._jobs[job_id] = job
            self._prune_old()
        return job_id

    def update(self, job_id: str, current_step: int = None, message: str = "",
               total_steps: int = None):
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            if current_step is not None:
                job.current_step = current_step
            if total_steps is not None:
                job.total_steps = total_steps
            if message:
                job.message = message
            if job.status == "queued":
                job.status = "running"
            job.progress = int(
                (job.current_step / job.total_steps) * 100
            ) if job.total_steps else 0
            self._broadcast(job)

    def complete(self, job_id: str, result: Any = None):
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            job.status = "completed"
            job.progress = 100
            job.result = result
            job.completed_at = datetime.now(timezone.utc).isoformat()
            self._broadcast(job)

    def fail(self, job_id: str, error: str):
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            job.status = "failed"
            job.error = str(error)[:2000]
            job.completed_at = datetime.now(timezone.utc).isoformat()
            self._broadcast(job)

    def cancel(self, job_id: str):
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            job.cancelled = True
            job.status = "cancelled"
            job.completed_at = datetime.now(timezone.utc).isoformat()
            self._broadcast(job)

    def get(self, job_id: str) -> Optional[dict]:
        with self._lock:
            job = self._jobs.get(job_id)
            return job.to_dict() if job else None

    def list_jobs(self, limit: int = 20) -> list:
        with self._lock:
            all_jobs = sorted(
                self._jobs.values(),
                key=lambda j: j.created_at,
                reverse=True,
            )
            return [j.to_dict() for j in all_jobs[:limit]]

    # -- SSE streaming -------------------------------------------------------

    def listen(self, job_ids: list[str] = None) -> Generator[str, None, None]:
        """SSE generator. Streams updates for given job IDs (or all)."""
        q: "queue.Queue" = queue.Queue()
        with self._lock:
            listener_set = set()
            if job_ids:
                for jid in job_ids:
                    if jid in self._jobs:
                        self._listeners.setdefault(jid, set()).add(q)
                        listener_set.add(jid)
                        q.put(("update", self._jobs[jid]))
            else:
                q.put(("snapshot", list(self._jobs.values())))

        try:
            while True:
                try:
                    kind, data = q.get(timeout=30)
                except queue.Empty:
                    yield ": heartbeat\n\n"
                    continue
                if kind == "snapshot":
                    yield f"event: snapshot\ndata: {json.dumps([j.to_dict() for j in data])}\n\n"
                elif kind == "update":
                    yield f"data: {json.dumps(data.to_dict())}\n\n"
                elif kind == "close":
                    break
        except GeneratorExit:
            pass
        finally:
            with self._lock:
                for jid in list(self._listeners):
                    self._listeners[jid].discard(q)
                    if not self._listeners[jid]:
                        del self._listeners[jid]

    def _broadcast(self, job: JobInfo):
        for q in list(self._listeners.get(job.id, set())):
            try:
                q.put(("update", job))
            except Exception:

                logger.debug("Exception in job_queue.py", exc_info=True)
        # Also notify global listeners (those without job_ids filter)
        for q in list(self._listeners.get("__all__", set())):
            try:
                q.put(("update", job))
            except Exception:

                logger.debug("Exception in job_queue.py", exc_info=True)

    def listen_all(self) -> Generator[str, None, None]:
        return self.listen(None)

    # -- Internal ------------------------------------------------------------

    def _prune_old(self):
        if len(self._jobs) <= self._max_history:
            return
        sorted_jobs = sorted(
            self._jobs.items(), key=lambda x: x[1].created_at
        )
        for k, _ in sorted_jobs[: -self._max_history]:
            self._jobs.pop(k, None)


# -- Wrapper for running callables as jobs ----------------------------------

def run_in_thread(job_manager: JobManager, job_id: str,
                  func: Callable, progress_callback=None,
                  *args, **kwargs) -> threading.Thread:
    """Execute `func` in a background thread, auto-updating job status."""
    def _wrapper():
        try:
            if progress_callback:
                kwargs["_progress"] = progress_callback
            result = func(*args, **kwargs)
            job_manager.complete(job_id, result)
        except Exception as e:
            job_manager.fail(job_id, str(e))
    t = threading.Thread(target=_wrapper, daemon=True)
    t.start()
    return t


# Singleton
_job_manager: Optional[JobManager] = None


def get_job_manager() -> JobManager:
    global _job_manager
    if _job_manager is None:
        _job_manager = JobManager()
    return _job_manager