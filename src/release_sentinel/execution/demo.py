from __future__ import annotations

import hashlib
import json
from pathlib import Path

from release_sentinel.execution.base import SandboxExecutor
from release_sentinel.execution.model import ExecutionResult
from release_sentinel.policy.model import PolicyCommand


class BundledDemoExecutor(SandboxExecutor):
    """Offline-safe executor for an immutable package-owned fixture only.

    It never executes reviewed repository code. The fixture hash and expected
    demonstration outcome are package-owned test data, not repository authority.
    Production/cloud proof uses CloudRunSandboxExecutor instead.
    """

    def __init__(self, expected_fixture_sha256: str, expected_return_code: int = 1) -> None:
        self.expected = expected_fixture_sha256
        self.expected_return_code = expected_return_code

    @staticmethod
    def fixture_digest(repository: Path) -> str:
        h = hashlib.sha256()
        for path in sorted(p for p in repository.rglob("*") if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc"):
            rel = path.relative_to(repository).as_posix().encode()
            h.update(rel + b"\0" + path.read_bytes() + b"\0")
        return h.hexdigest()

    def execute(self, repository: Path, command: PolicyCommand) -> ExecutionResult:
        actual = self.fixture_digest(repository)
        if actual != self.expected:
            raise RuntimeError("BundledDemoExecutor only accepts the hash-pinned bundled demo fixture")
        payload = json.dumps(
            {"fixture_sha256": actual, "command_id": command.command_id, "offline_demo": True},
            sort_keys=True,
        ).encode()
        return ExecutionResult(
            command_id=command.command_id,
            return_code=self.expected_return_code,
            timed_out=False,
            stdout_sha256=hashlib.sha256(payload).hexdigest(),
            stderr_sha256=hashlib.sha256(b"").hexdigest(),
            # Offline proof fixture must be byte-deterministic across runs.
            # Production CloudRunSandboxExecutor records real duration.
            duration_ms=0,
        )
