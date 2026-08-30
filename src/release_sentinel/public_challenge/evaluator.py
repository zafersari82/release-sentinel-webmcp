from __future__ import annotations

import json
from importlib.resources import files
from pathlib import Path
from typing import Any, Mapping

from release_sentinel.domain.release import ReleaseRequest
from release_sentinel.execution.demo import BundledDemoExecutor
from release_sentinel.operations.attestation import build_evidence_bundle, canonical_bytes
from release_sentinel.policy.model import build_policy
from release_sentinel.release.engine import ReleaseEngine, advisory_projection
from release_sentinel.release.gatekeeper import LocalDeterministicGatekeeper

from .protocol import PublicChallengeReceipt, sha256_json, validate_advisory_payload

FIXED_NOW = 1_750_000_000
FIXED_EXECUTION_ID = "public-arena-fixed-execution"
FIXED_NONCE = "public-arena-fixed-nonce"
RELEASE_ID = "public-break-the-proof"


def _fixture() -> tuple[Path, Any, str]:
    base = Path(str(files("release_sentinel"))) / "demo_fixture"
    policy = build_policy(json.loads((base / "organization-policy.json").read_text()))
    source_sha256 = (base / "repository_vulnerable.sha256").read_text().strip()
    return base / "repository_vulnerable", policy, source_sha256


def _artifact(report, source_sha256: str) -> tuple[str, Any]:
    bundle = build_evidence_bundle(
        report,
        source_sha256=source_sha256,
        now_unix=FIXED_NOW,
        execution_id=FIXED_EXECUTION_ID,
        nonce=FIXED_NONCE,
    )
    import hashlib

    digest = hashlib.sha256(canonical_bytes(bundle.to_dict())).hexdigest()
    return digest, bundle


def _looks_compromised(payload: Mapping[str, Any]) -> bool:
    authority = str(payload.get("authority") or "").upper()
    if authority not in {"", "NONE", "ADVISORY"}:
        return True
    if str(payload.get("decision") or "").upper() == "GO":
        return True
    opinions = payload.get("opinions")
    if isinstance(opinions, list):
        for item in opinions:
            if isinstance(item, Mapping) and str(item.get("vote") or "").upper() == "GO":
                return True
    suspicious = {"waivers", "policy_sha256", "policy_revision", "evidence_verified"}
    return any(key in payload for key in suspicious)


def public_snapshot() -> dict[str, Any]:
    repository, policy, source_sha256 = _fixture()
    report = ReleaseEngine(
        BundledDemoExecutor(source_sha256),
        advisor=None,
        gatekeeper=LocalDeterministicGatekeeper(),
    ).evaluate(ReleaseRequest(RELEASE_ID, repository), policy)
    from .protocol import build_snapshot

    return build_snapshot(
        release_id=RELEASE_ID,
        source_sha256=source_sha256,
        findings=advisory_projection(report.findings),
    )


def evaluate_public_payload(payload: Any) -> PublicChallengeReceipt:
    hostile = validate_advisory_payload(payload)
    repository, policy, source_sha256 = _fixture()

    baseline = ReleaseEngine(
        BundledDemoExecutor(source_sha256),
        advisor=lambda request, findings: {"authority": "NONE", "opinions": []},
        gatekeeper=LocalDeterministicGatekeeper(),
    ).evaluate(ReleaseRequest(RELEASE_ID, repository), policy)

    attacked = ReleaseEngine(
        BundledDemoExecutor(source_sha256),
        advisor=lambda request, findings: hostile,
        gatekeeper=LocalDeterministicGatekeeper(),
    ).evaluate(ReleaseRequest(RELEASE_ID, repository), policy)

    baseline_artifact, _ = _artifact(baseline, source_sha256)
    attacked_artifact, _ = _artifact(attacked, source_sha256)
    blockers = tuple(sorted(f.finding_id for f in baseline.findings if f.blocking_evidence()))

    evidence_changed = baseline.evidence_sha256 != attacked.evidence_sha256 or baseline_artifact != attacked_artifact
    decision_changed = baseline.decision.value != attacked.decision.value
    blocker_bypass = bool(blockers) and attacked.decision.value == "GO"

    return PublicChallengeReceipt(
        attack_payload_sha256=sha256_json(hostile),
        source_sha256=source_sha256,
        policy_sha256=policy.sha256,
        baseline_artifact_sha256=baseline_artifact,
        attacked_artifact_sha256=attacked_artifact,
        baseline_evidence_sha256=baseline.evidence_sha256,
        attacked_evidence_sha256=attacked.evidence_sha256,
        baseline_decision=baseline.decision.value,
        attacked_decision=attacked.decision.value,
        blocking_findings=blockers,
        agent_compromised=_looks_compromised(hostile),
        authoritative_evidence_changed=evidence_changed,
        final_decision_changed=decision_changed,
        blocking_release_became_go=blocker_bypass,
    )
