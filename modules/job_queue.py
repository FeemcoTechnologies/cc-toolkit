import logging
"""Background job queue with SSE (Server-Sent Events) support.

JobManager tracks async tasks (scans, reports, etc.) and pushes
progress updates to listening SSE clients in real time.
"""

import json
import queue
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Generator, Optional
logger = logging.getLogger(__name__)


class JobInfo:
    __slots__ = (
        "id", "type", "title", "status", "progress", "total_steps",
        "current_step", "message", "result", "error",
        "created_at", "completed_at", "cancelled", "case_id",
    )

    def __init__(self, job_id: str, job_type: str, title: str,
                 total_steps: int = 100, case_id: str = ""):
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
        self.case_id = case_id

    def to_dict(self) -> dict:
        return {s: getattr(self, s) for s in self.__slots__}

    @classmethod
    def from_dict(cls, d: dict) -> "JobInfo":
        job = cls(str(d.get("id", "")), str(d.get("type", "")),
                  str(d.get("title", "")), 100)
        for s in cls.__slots__:
            if s in d:
                try:
                    setattr(job, s, d[s])
                except Exception:
                    pass
        # Re-coerce numeric fields after the raw overwrite: a corrupt persisted
        # value must not abort loading every other job or leave a broken total.
        try:
            job.total_steps = int(job.total_steps)
        except (ValueError, TypeError):
            job.total_steps = 100
        if job.total_steps <= 0:
            job.total_steps = 100
        return job


class JobManager:
    """Thread-safe job manager with SSE listener support.

    Optionally persists jobs to a JSON file on disk so completed/failed
    results survive dashboard restarts. Loaded from disk on init; jobs that
    were still running when the file was written are marked failed.
    """

    def __init__(self, max_history: int = 50, persist_path: str = ""):
        self._jobs: Dict[str, JobInfo] = {}
        self._listeners: Dict[str, set] = {}
        self._lock = threading.Lock()
        self._max_history = max_history
        self._persist_path = Path(persist_path) if persist_path else None
        if self._persist_path is None:
            default = Path.home() / ".config" / "kali-command-center" / "jobs.json"
            self._persist_path = default
        self._load()

    # -- Job lifecycle -------------------------------------------------------

    def create(self, job_type: str, title: str, total_steps: int = 100,
               case_id: str = "") -> str:
        job_id = uuid.uuid4().hex[:8]
        job = JobInfo(job_id, job_type, title, total_steps, case_id=case_id)
        with self._lock:
            self._jobs[job_id] = job
            self._prune_old()
        self._persist()
        return job_id

    def update(self, job_id: str, current_step: int = None, message: str = "",
               total_steps: int = None):
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            if job.status in ("completed", "failed", "cancelled"):
                # Terminal state — ignore late progress updates so a slow
                # worker thread can't regress progress or status after the
                # job already finished.
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
        self._persist()

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
        self._persist()
        self._attach_to_case(job)

    def fail(self, job_id: str, error: str):
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            job.status = "failed"
            job.error = str(error)[:2000]
            job.completed_at = datetime.now(timezone.utc).isoformat()
            self._broadcast(job)
        self._persist()
        self._attach_to_case(job)

    def cancel(self, job_id: str):
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            job.cancelled = True
            job.status = "cancelled"
            job.completed_at = datetime.now(timezone.utc).isoformat()
            self._broadcast(job)
        self._persist()
        self._attach_to_case(job)

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
                # No job_ids filter -> register a global "__all__" listener so
                # _broadcast keeps streaming updates (previously this branch
                # only sent one snapshot and never received further events).
                self._listeners.setdefault("__all__", set()).add(q)
                listener_set.add("__all__")
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

    def _attach_to_case(self, job: JobInfo):
        """Persist a terminal job's record into its case directory so any
        background job tied to a case always leaves a trace there (a
        `jobs/<job_id>.json` file plus an IR timeline entry). The case is
        auto-created when a job references one that doesn't exist yet, so a
        job never outlives its case."""
        case_id = getattr(job, "case_id", "") or ""
        if not case_id:
            return
        try:
            from modules.case_manager import CaseManager
            cm = CaseManager()
            if cm.info(case_id) is None:
                try:
                    cm.create(
                        case_id, case_type="pentest",
                        description=f"Auto-created by background job '{job.title}'",
                    )
                except Exception:
                    # Bad/missing case still fails -> nothing to attach to.
                    logger.debug("Failed to auto-create case for job", exc_info=True)
                    return
            case_dir = cm._case_path(case_id)
            jdir = case_dir / "jobs"
            jdir.mkdir(parents=True, exist_ok=True)
            (jdir / f"{job.id}.json").write_text(
                json.dumps(job.to_dict(), indent=2, default=str),
                encoding="utf-8")
            err = (job.error or "").strip()
            if job.status == "completed":
                event = f"Job '{job.title}' completed -> jobs/{job.id}.json"
            elif job.status == "cancelled":
                event = f"Job '{job.title}' cancelled -> jobs/{job.id}.json"
            else:
                event = (f"Job '{job.title}' failed"
                         + (f": {err[:200]}" if err else "")
                         + f" -> jobs/{job.id}.json")
            cm.ir_timeline_add(
                case_id,
                datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                event, severity="info", source="system")
        except Exception:
            logger.debug("Failed to attach job result to case", exc_info=True)

    def _persist(self):
        if not self._persist_path:
            return
        try:
            # Snapshot + write under the lock so a persisted state can never
            # miss an in-flight mutation (stale write).
            with self._lock:
                self._persist_path.parent.mkdir(parents=True, exist_ok=True)
                tmp = self._persist_path.with_suffix(self._persist_path.suffix + ".tmp")
                tmp.write_text(
                    json.dumps([j.to_dict() for j in self._jobs.values()],
                               indent=2, default=str),
                    encoding="utf-8")
                tmp.replace(self._persist_path)
        except Exception:
            logger.debug("Failed to persist jobs", exc_info=True)

    def _load(self):
        if not self._persist_path or not self._persist_path.exists():
            return
        try:
            raw = json.loads(self._persist_path.read_text(encoding="utf-8"))
            if isinstance(raw, list):
                for d in raw:
                    if not isinstance(d, dict) or not d.get("id"):
                        continue
                    job = JobInfo.from_dict(d)
                    # Jobs interrupted by a restart can never resume.
                    if job.status in ("queued", "running"):
                        job.status = "failed"
                        job.error = "Dashboard restarted while this job was running"
                        job.completed_at = datetime.now(timezone.utc).isoformat()
                    self._jobs[job.id] = job
        except Exception:
            logger.debug("Failed to load persisted jobs", exc_info=True)

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