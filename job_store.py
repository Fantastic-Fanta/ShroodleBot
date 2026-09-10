from __future__ import annotations

from runner import ShroodlerJob

_RUNNING = frozenset({"pending", "running"})


class JobStore:
    def __init__(self) -> None:
        self._jobs: dict[str, ShroodlerJob] = {}

    def add(self, job: ShroodlerJob) -> None:
        self._jobs[job.job_id] = job

    def get(self, job_id: str) -> ShroodlerJob | None:
        return self._jobs.get(job_id)

    def list_running(self) -> list[ShroodlerJob]:
        return [job for job in self._jobs.values() if job.status in _RUNNING]

    def remove(self, job_id: str) -> None:
        self._jobs.pop(job_id, None)
