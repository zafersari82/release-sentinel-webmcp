from __future__ import annotations

from pathlib import Path

import pytest

from release_sentinel.domain.evidence import (
    Decision,
    Evidence,
    EvidenceAuthority,
    EvidenceIntegrityError,
    EvidenceKind,
    Finding,
    Severity,
)
from release_sentinel.domain.release import ReleaseReport
from release_sentinel.operations.attestation import build_evidence_bundle


def _report() -> ReleaseReport:
    details = {"nested": {"values": [1, 2]}, "command_id": "auth-check"}
    evidence = Evidence(
        evidence_id="ev-1",
        kind=EvidenceKind.EXECUTION_RESULT,
        authority=EvidenceAuthority.ORGANIZATION_POLICY,
        source="policy:test:auth",
        summary="failed",
        reproducible=True,
        blocking_eligible=True,
        details=details,
        policy_id="test",
        policy_revision=1,
        policy_sha256="b" * 64,
    )
    # Mutating the constructor input afterwards must not reach the evidence.
    details["nested"]["values"].append(3)
    finding = Finding("F-1", "Auth", Severity.HIGH, "organization_policy", "failed", [evidence])
    return ReleaseReport(
        release_id="r",
        decision=Decision.NO_GO,
        findings=[finding],
        rationale=["blocked"],
        policy_id="test",
        policy_revision=1,
        policy_sha256="b" * 64,
        execution_count=1,
        advisory={"opinions": [{"vote": "GO"}]},
        gatekeeper={"agent_influence": 0},
    )


def test_evidence_is_deeply_immutable_and_defensively_copied():
    report = _report()
    evidence = report.findings[0].evidence[0]
    assert evidence.to_dict()["details"]["nested"]["values"] == [1, 2]
    with pytest.raises(TypeError):
        evidence.details["new"] = "x"  # type: ignore[index]
    with pytest.raises(TypeError):
        evidence.details["nested"]["new"] = "x"  # type: ignore[index]
    assert isinstance(evidence.details["nested"]["values"], tuple)


def test_release_report_exposes_no_mutable_evidence_path():
    report = _report()
    assert isinstance(report.findings, tuple)
    with pytest.raises(AttributeError):
        report.findings.append(report.findings[0])  # type: ignore[attr-defined]
    with pytest.raises(TypeError):
        report.advisory["opinions"] = []  # type: ignore[index]


def test_attestation_rechecks_the_evaluation_seal_fail_closed():
    report = _report()
    object.__setattr__(report, "findings", ())  # simulate a hostile embedding bypassing frozen dataclass guards
    with pytest.raises(EvidenceIntegrityError):
        build_evidence_bundle(report, source_sha256="a" * 64)


def test_signed_bundle_input_is_detached_from_report(tmp_path: Path):
    report = _report()
    bundle = build_evidence_bundle(report, source_sha256="a" * 64, now_unix=100, execution_id="e", nonce="n")
    payload = bundle.to_dict()
    payload["results"].clear()
    assert len(bundle.results) == 1
