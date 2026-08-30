from __future__ import annotations

import json
from importlib.resources import files
from pathlib import Path
from typing import Any

from release_sentinel.domain.release import ReleaseRequest
from release_sentinel.execution.demo import BundledDemoExecutor
from release_sentinel.infrastructure.attestor import EvidenceAttestorClient
from release_sentinel.infrastructure.settings import CloudSettings
from release_sentinel.operations.attestation import build_evidence_bundle, demo_signer_from_env, sign_evidence_bundle
from release_sentinel.policy.model import build_policy
from release_sentinel.release.engine import ReleaseEngine
from release_sentinel.release.gatekeeper import LocalDeterministicGatekeeper


_FIXTURES: dict[str, tuple[str, int]] = {
    # Stable internal aliases retained for the existing current-release and attack paths.
    "vulnerable": ("repository_vulnerable", 1),
    "fixed": ("repository_fixed", 0),
    # Scenario-owned identities used by the WebMCP remediation registry.
    "cross_tenant_vulnerable": ("repository_vulnerable", 1),
    "cross_tenant_fixed": ("repository_fixed", 0),
    "path_traversal_vulnerable": ("repository_path_traversal_vulnerable", 1),
    "path_traversal_fixed": ("repository_path_traversal_fixed", 0),
    "evidence_tamper_vulnerable": ("repository_evidence_tamper_vulnerable", 1),
    "evidence_tamper_fixed": ("repository_evidence_tamper_fixed", 0),
}


def demo_base() -> Path:
    return Path(str(files("release_sentinel"))) / "demo_fixture"


def demo_policy():
    base = demo_base()
    return build_policy(json.loads((base / "organization-policy.json").read_text(encoding="utf-8")))


def _fixture_definition(fixture_name: str) -> tuple[str, int]:
    try:
        return _FIXTURES[fixture_name]
    except KeyError as exc:
        raise ValueError(f"unknown package-owned demo fixture: {fixture_name}") from exc


def fixture_source_sha(fixture_name: str) -> str:
    base = demo_base()
    directory, _ = _fixture_definition(fixture_name)
    return BundledDemoExecutor.fixture_digest(base / directory)


def evaluate_fixture(fixture_name: str, *, release_id: str):
    base = demo_base()
    directory, expected_return_code = _fixture_definition(fixture_name)
    source_sha = fixture_source_sha(fixture_name)
    report = ReleaseEngine(
        BundledDemoExecutor(source_sha, expected_return_code=expected_return_code),
        advisor=None,
        gatekeeper=LocalDeterministicGatekeeper(),
    ).evaluate(ReleaseRequest(release_id, base / directory), demo_policy())
    return report, source_sha


def signed_fixture(fixture_name: str, release_id: str) -> dict[str, Any]:
    settings = CloudSettings.from_env()
    if settings.attestor_url:
        return EvidenceAttestorClient(
            settings.attestor_url,
            audience=settings.attestor_audience or settings.attestor_url,
        ).attest_fixture(fixture_name, release_id=release_id)
    report, source_sha = evaluate_fixture(fixture_name, release_id=release_id)
    signed = sign_evidence_bundle(build_evidence_bundle(report, source_sha256=source_sha), demo_signer_from_env())
    return {
        "source_sha256": source_sha,
        "policy_sha256": report.policy_sha256,
        "report": report.to_dict(),
        "signed_evidence_bundle": signed.to_dict(),
    }
