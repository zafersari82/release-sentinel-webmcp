from __future__ import annotations

import hashlib
import shutil
import subprocess
import time
from pathlib import Path

from release_sentinel.execution.base import SandboxExecutor, SandboxUnavailable
from release_sentinel.execution.model import ExecutionResult
from release_sentinel.policy.model import PolicyCommand


class CloudRunSandboxExecutor(SandboxExecutor):
    """Execute organization-owned commands through Cloud Run Sandbox.

    There is intentionally no host-execution fallback. Repository code executes
    only inside the sandbox process boundary.
    """

    def __init__(self, sandbox_binary: str = "/usr/local/gcp/bin/sandbox") -> None:
        self.binary = sandbox_binary

    def execute(self, repository: Path, command: PolicyCommand) -> ExecutionResult:
        binary = shutil.which(self.binary)
        if not binary:
            raise SandboxUnavailable("Cloud Run sandbox binary is unavailable; refusing host execution")
        repository = repository.resolve()
        cwd = (repository / command.cwd).resolve()
        if repository not in [cwd, *cwd.parents]:
            raise ValueError("policy cwd escaped repository")
        argv = [binary, "do", "--", "/usr/bin/env", "-C", str(cwd), *command.argv]
        started = time.monotonic()
        try:
            proc = subprocess.run(
                argv,
                cwd=cwd,
                capture_output=True,
                text=False,
                timeout=command.timeout_seconds,
                check=False,
            )
            stdout = proc.stdout or b""
            stderr = proc.stderr or b""
            return_code = proc.returncode
            timed_out = False
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout or b""
            stderr = exc.stderr or b""
            return_code = 124
            timed_out = True
        duration = int((time.monotonic() - started) * 1000)
        return ExecutionResult(
            command_id=command.command_id,
            return_code=return_code,
            timed_out=timed_out,
            stdout_sha256=hashlib.sha256(stdout).hexdigest(),
            stderr_sha256=hashlib.sha256(stderr).hexdigest(),
            duration_ms=duration,
        )
