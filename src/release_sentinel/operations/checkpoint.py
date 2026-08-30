from __future__ import annotations

from dataclasses import dataclass, field
from threading import RLock


@dataclass
class RunCheckpoint:
    run_id: str
    completed_scenarios: set[str] = field(default_factory=set)
    cancelled: bool = False
    attempts: dict[int, int] = field(default_factory=dict)


class InMemoryCheckpointStore:
    def __init__(self) -> None:
        self._lock = RLock()
        self._runs: dict[str, RunCheckpoint] = {}

    def get_or_create(self, run_id: str) -> RunCheckpoint:
        with self._lock:
            return self._runs.setdefault(run_id, RunCheckpoint(run_id))

    def mark_complete(self, run_id: str, scenario_id: str) -> None:
        with self._lock:
            self.get_or_create(run_id).completed_scenarios.add(scenario_id)

    def request_cancel(self, run_id: str) -> None:
        with self._lock:
            self.get_or_create(run_id).cancelled = True
