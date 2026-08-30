from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ExecutionResult:
    command_id: str
    return_code: int
    timed_out: bool
    stdout_sha256: str
    stderr_sha256: str
    duration_ms: int

    @property
    def passed(self) -> bool:
        return not self.timed_out and self.return_code == 0
