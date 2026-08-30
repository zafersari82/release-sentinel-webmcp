import json
from importlib.resources import files
from pathlib import Path

import pytest

from release_sentinel.domain.release import ReleaseRequest
from release_sentinel.execution.demo import BundledDemoExecutor
from release_sentinel.operations.attestation import build_evidence_bundle, canonical_bytes
from release_sentinel.policy.model import build_policy
from release_sentinel.release.engine import ReleaseEngine
from release_sentinel.release.gatekeeper import LocalDeterministicGatekeeper


def demo_fixture():
    base = Path(str(files("release_sentinel"))) / "demo_fixture"
    policy = build_policy(json.loads((base / "organization-policy.json").read_text()))
    source_sha256 = (base / "repository_vulnerable.sha256").read_text().strip()
    return base, policy, source_sha256


def test_demo_fixture_is_pinned_and_fails_check():
    base, policy, source_sha256 = demo_fixture()
    executor = BundledDemoExecutor(source_sha256)

    result = executor.execute(base / "repository_vulnerable", policy.commands[0])

    assert result.return_code == 1
    assert not result.timed_out


def test_demo_executor_rejects_any_modified_fixture(tmp_path):
    _, policy, source_sha256 = demo_fixture()
    executor = BundledDemoExecutor(source_sha256)
    observations = tmp_path / "observations"
    observations.mkdir()
    (observations / "auth-boundary.json").write_text(
        '{"expected_status":403,"actual_status":403}',
        encoding="utf-8",
    )

    with pytest.raises(RuntimeError):
        executor.execute(tmp_path, policy.commands[0])


def test_bundled_demo_executor_is_byte_deterministic_for_proof_harness():
    base, policy, source_sha256 = demo_fixture()

    def artifact():
        report = ReleaseEngine(
            BundledDemoExecutor(source_sha256),
            gatekeeper=LocalDeterministicGatekeeper(),
        ).evaluate(ReleaseRequest("determinism", base / "repository_vulnerable"), policy)
        bundle = build_evidence_bundle(
            report,
            source_sha256=source_sha256,
            now_unix=1_750_000_000,
            execution_id="fixed-exec",
            nonce="fixed-nonce",
        )
        return canonical_bytes(bundle.to_dict())

    assert artifact() == artifact() == artifact()
