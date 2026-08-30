import json

from release_sentinel.agents.advisory import deterministic_advisory
from release_sentinel.domain.release import ReleaseRequest
from release_sentinel.execution.base import SandboxExecutor
from release_sentinel.execution.model import ExecutionResult
from release_sentinel.policy.model import build_policy
from release_sentinel.release.engine import ReleaseEngine


class FakeExecutor(SandboxExecutor):
    def __init__(self, code=0, timeout=False):
        self.code = code
        self.timeout = timeout

    def execute(self, repository, command):
        return ExecutionResult(
            command.command_id,
            self.code,
            self.timeout,
            "a" * 64,
            "b" * 64,
            12,
        )


def policy(severity="HIGH", blocking=True):
    return build_policy(
        {
            "policy_id": "org",
            "revision": 3,
            "commands": [
                {
                    "id": "auth",
                    "title": "Auth boundary",
                    "argv": ["/bin/true"],
                    "cwd": ".",
                    "timeout_seconds": 30,
                    "severity": severity,
                    "blocking_on_failure": blocking,
                }
            ],
        }
    )


def repository(tmp_path):
    (tmp_path / "app.py").write_text("print('ok')", encoding="utf-8")
    return tmp_path


def test_failed_org_check_blocks(tmp_path):
    report = ReleaseEngine(FakeExecutor(1)).evaluate(
        ReleaseRequest("r", repository(tmp_path)),
        policy(),
    )

    assert report.decision.value == "NO_GO"
    assert report.execution_count == 1
    evidence = report.findings[0].evidence[0]
    assert evidence.authority.value == "ORGANIZATION_POLICY"
    assert evidence.reproducible


def test_passing_check_goes(tmp_path):
    report = ReleaseEngine(FakeExecutor(0)).evaluate(
        ReleaseRequest("r", repository(tmp_path)),
        policy(),
    )

    assert report.decision.value == "GO"


def test_timeout_fails_closed(tmp_path):
    report = ReleaseEngine(FakeExecutor(1, True)).evaluate(
        ReleaseRequest("r", repository(tmp_path)),
        policy(),
    )

    assert report.decision.value == "NO_GO"
    assert report.findings[0].evidence[0].reproducible is False


def test_repo_manifest_cannot_change_decision(tmp_path):
    root = repository(tmp_path)
    metadata = root / ".release-sentinel"
    metadata.mkdir()
    (metadata / "test-results.json").write_text(
        json.dumps(
            {
                "results": [
                    {"status": "passed", "severity": "INFO", "reproducible": False}
                ]
            }
        ),
        encoding="utf-8",
    )

    report = ReleaseEngine(FakeExecutor(1)).evaluate(ReleaseRequest("r", root), policy())

    assert report.decision.value == "NO_GO"


def test_empty_or_forged_manifest_cannot_create_blocker(tmp_path):
    root = repository(tmp_path)
    metadata = root / ".release-sentinel"
    metadata.mkdir()
    (metadata / "test-results.json").write_text(
        json.dumps(
            {
                "results": [
                    {
                        "status": "failed",
                        "severity": "CRITICAL",
                        "reproducible": True,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    report = ReleaseEngine(FakeExecutor(0)).evaluate(ReleaseRequest("r", root), policy())

    assert report.decision.value == "GO"


def test_model_advisory_has_no_authority(tmp_path):
    report = ReleaseEngine(FakeExecutor(0), advisor=deterministic_advisory).evaluate(
        ReleaseRequest("r", repository(tmp_path)),
        policy(),
    )

    assert report.decision.value == "GO"
    assert report.advisory["authority"] == "NONE"


def test_nonblocking_policy_failure_does_not_no_go(tmp_path):
    report = ReleaseEngine(FakeExecutor(1)).evaluate(
        ReleaseRequest("r", repository(tmp_path)),
        policy(blocking=False),
    )

    assert report.decision.value == "GO"
