from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from release_sentinel.execution.model import ExecutionResult
from release_sentinel.policy.model import PolicyCommand


class SandboxUnavailable(RuntimeError):
    pass


class SandboxExecutor(ABC):
    @abstractmethod
    def execute(self, repository: Path, command: PolicyCommand) -> ExecutionResult:
        raise NotImplementedError
