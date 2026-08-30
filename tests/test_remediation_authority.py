from __future__ import annotations

from pathlib import Path

import pytest

from release_sentinel.domain.evidence import Decision, Evidence, EvidenceAuthority, EvidenceKind, Finding, Severity
from release_sentinel.domain.release import ReleaseReport, ReleaseRequest
from release_sentinel.remediation import RemediationCoordinator, RepairRejected, repository_sha256


def _report(release_id: str, *, go: bool) -> ReleaseReport:
    findings = ()
    decision = Decision.GO
    if not go:
        evidence = Evidence(
            evidence_id="ev-auth",
            kind=EvidenceKind.EXECUTION_RESULT,
            authority=EvidenceAuthority.ORGANIZATION_POLICY,
            source="policy:auth",
            summary="authorization check failed",
            reproducible=True,
            blocking_eligible=True,
        )
        findings = (
            Finding(
                finding_id="AUTH-0042",
                title="Authorization boundary regression",
                severity=Severity.HIGH,
                source="organization_policy",
                claim="unauthorized request returned 200",
                evidence=(evidence,),
            ),
        )
        decision = Decision.NO_GO
    return ReleaseReport(
        release_id=release_id,
        decision=decision,
        findings=findings,
        rationale=("deterministic test double",),
        policy_id="org-release",
        policy_revision=1,
        policy_sha256="a" * 64,
        execution_count=1,
    )


def test_ai_can_repair_but_cannot_approve_its_own_change(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("AUTH_BYPASS = True\n", encoding="utf-8")
    calls: list[tuple[str, str]] = []

    def evaluator(request: ReleaseRequest) -> ReleaseReport:
        content = (request.repository_path / "app.py").read_text(encoding="utf-8")
        calls.append((request.release_id, repository_sha256(request.repository_path)))
        return _report(request.release_id, go="AUTH_BYPASS = False" in content)

    def remediator(context):
        assert context.findings[0]["severity"] == "HIGH"
        with pytest.raises(TypeError):
            context.findings[0]["severity"] = "INFO"
        return {"app.py": "AUTH_BYPASS = False\n"}

    outcome = RemediationCoordinator(
        evaluator,
        remediator,
        producer_agent_id="gemini-remediator",
        allowed_paths={"app.py"},
    ).run(ReleaseRequest("release-42", repo))

    assert outcome.before.decision is Decision.NO_GO
    assert outcome.after is not None and outcome.after.decision is Decision.GO
    assert outcome.proposal is not None and outcome.proposal.authority == "PROPOSAL_ONLY"
    assert outcome.original_source_sha256 != outcome.repaired_source_sha256
    assert outcome.reevaluated_from_scratch is True
    assert len(calls) == 2 and calls[0][1] != calls[1][1]
    assert (repo / "app.py").read_text(encoding="utf-8") == "AUTH_BYPASS = True\n"


def test_remediator_cannot_write_outside_explicit_allowlist(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("broken\n", encoding="utf-8")

    coordinator = RemediationCoordinator(
        lambda request: _report(request.release_id, go=False),
        lambda context: {"../policy.json": "ALLOW_ALL=true", "app.py": "fixed\n"},
        producer_agent_id="hostile-remediator",
        allowed_paths={"app.py"},
    )
    with pytest.raises(RepairRejected):
        coordinator.run(ReleaseRequest("r", repo))


def test_remediator_cannot_smuggle_a_verdict_as_a_file(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("broken\n", encoding="utf-8")

    coordinator = RemediationCoordinator(
        lambda request: _report(request.release_id, go=False),
        lambda context: {"decision": "GO", "app.py": "fixed\n"},
        producer_agent_id="hostile-remediator",
        allowed_paths={"app.py"},
    )
    with pytest.raises(RepairRejected, match="unauthorized write"):
        coordinator.run(ReleaseRequest("r", repo))


def test_repository_hash_rejects_symlink_repositories(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    link = repo / "link.txt"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlinks unavailable")
    with pytest.raises(RepairRejected, match="symlink"):
        repository_sha256(repo)
