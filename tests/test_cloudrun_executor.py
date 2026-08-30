import subprocess

import pytest

from release_sentinel.execution.base import SandboxUnavailable
from release_sentinel.execution.cloudrun import CloudRunSandboxExecutor
from release_sentinel.policy.model import build_policy


def command():
    policy = build_policy(
        {
            "policy_id": "p",
            "revision": 1,
            "commands": [
                {
                    "id": "x",
                    "argv": ["/bin/true"],
                    "cwd": ".",
                    "timeout_seconds": 10,
                    "severity": "HIGH",
                }
            ],
        }
    )
    return policy.commands[0]


def test_no_sandbox_never_falls_back_to_host(tmp_path, monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _: None)

    with pytest.raises(SandboxUnavailable):
        CloudRunSandboxExecutor().execute(tmp_path, command())


def test_cloudrun_uses_sandbox_do_not_shell(tmp_path, monkeypatch):
    calls = {}
    monkeypatch.setattr("shutil.which", lambda _: "/usr/local/gcp/bin/sandbox")

    class Process:
        returncode = 0
        stdout = b""
        stderr = b""

    def fake_run(argv, **kwargs):
        calls["argv"] = argv
        calls["kwargs"] = kwargs
        return Process()

    monkeypatch.setattr("subprocess.run", fake_run)

    result = CloudRunSandboxExecutor().execute(tmp_path, command())

    assert calls["argv"][:3] == ["/usr/local/gcp/bin/sandbox", "do", "--"]
    assert "env" not in calls["kwargs"]
    assert "shell" not in calls["kwargs"]
    assert "--env" not in calls["argv"]
    assert "--allow-egress" not in calls["argv"]
    assert result.passed


def test_cloudrun_timeout_is_machine_result_not_host_fallback(tmp_path, monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _: "/usr/local/gcp/bin/sandbox")

    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(
            args[0],
            kwargs["timeout"],
            output=b"partial",
            stderr=b"late",
        )

    monkeypatch.setattr("subprocess.run", fake_run)

    result = CloudRunSandboxExecutor().execute(tmp_path, command())

    assert result.timed_out is True
    assert result.return_code == 124
    assert not result.passed
