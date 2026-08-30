from __future__ import annotations

from typing import Any, Callable

from release_sentinel.release.engine import evidence_fingerprint
from release_sentinel.webmcp.attacks import run_remote_attack
from release_sentinel.webmcp.contracts import AttackName
from release_sentinel.webmcp.coverage_service import CoverageArenaAdapter
from release_sentinel.webmcp.demo_runtime import evaluate_fixture, fixture_source_sha
from release_sentinel.webmcp.demo_scenarios import (
    DemoReleaseId,
    ProofId,
    fixture_for_proof,
    supported_proof_ids,
)
from release_sentinel.webmcp.errors import WebMCPServiceError
from release_sentinel.webmcp.remediation_service import RemediationAdapter

AttackRunner = Callable[[str], dict[str, Any]]


class WebMCPChallengeService:
    """Non-authoritative facade over existing trust, coverage, and release kernels."""

    def __init__(self, *, attack_runner: AttackRunner | None = None) -> None:
        self._attack_runner = attack_runner or run_remote_attack
        self._coverage = CoverageArenaAdapter()
        self._remediation = RemediationAdapter()

    def inspect_release(self) -> dict[str, Any]:
        report, source_sha = evaluate_fixture("vulnerable", release_id="webmcp-demo-current")
        blockers = [
            {"finding_id": item.finding_id, "severity": item.severity.value, "title": item.title}
            for item in report.findings
            if item.blocking_evidence()
        ]
        return {
            "release_id": report.release_id,
            "source_sha256": source_sha,
            "policy_sha256": report.policy_sha256,
            "current_verdict": report.decision.value,
            "blocking_findings": blockers,
            "proof_available": True,
            "authority": "DETERMINISTIC_GATEKEEPER",
            "webmcp_authority": "NO_RELEASE_AUTHORITY",
        }

    @staticmethod
    def inspect_trust_boundary() -> dict[str, Any]:
        return {
            "repository_text_authority": "NONE",
            "model_authority": "ADVISORY_ONLY",
            "webmcp_authority": "NO_RELEASE_AUTHORITY",
            "blocking_authorities": ["PLATFORM", "ORGANIZATION_POLICY"],
            "decision_authority": "DETERMINISTIC_GATEKEEPER",
            "production_gatekeeper": "GO_A2A_SERVICE",
            "authority_chain": [
                "AI_AGENT",
                "WEBMCP_CAPABILITY",
                "RELEASE_SENTINEL_API",
                "SIGNED_EVIDENCE",
                "DETERMINISTIC_GATEKEEPER",
            ],
        }

    def run_attack(self, attack_name: str) -> dict[str, Any]:
        try:
            bounded = AttackName(attack_name).value
        except ValueError as exc:
            allowed = ", ".join(item.value for item in AttackName)
            raise WebMCPServiceError(
                "UNKNOWN_ATTACK",
                "unknown bounded attack scenario",
                status_code=422,
                next_action=f"Retry run_attack with one of: {allowed}.",
            ) from exc
        try:
            result = dict(self._attack_runner(bounded))
        except WebMCPServiceError:
            raise
        except Exception as exc:
            raise WebMCPServiceError(
                "GATEKEEPER_DEPENDENCY_UNAVAILABLE",
                f"attack requires the deterministic remote Gatekeeper: {type(exc).__name__}",
                status_code=503,
                next_action=(
                    "The Gatekeeper is unreachable, so the attack cannot be scored. "
                    "The gate remains fail-closed; continue with find_counterexamples or retry later."
                ),
            ) from exc
        result["webmcp_authority"] = "NO_RELEASE_AUTHORITY"
        return result

    def inspect_coverage(self, challenge: str, revision: int = 3) -> dict[str, Any]:
        return self._coverage.inspect_coverage(challenge, revision)

    def compare_gate_revisions(self, challenge: str) -> dict[str, Any]:
        return self._coverage.compare_gate_revisions(challenge)

    def find_counterexamples(self, challenge: str, revision: int = 1) -> dict[str, Any]:
        return self._coverage.find_counterexamples(challenge, revision)

    def minimize_counterexample(self, challenge: str, candidate_id: str) -> dict[str, Any]:
        return self._coverage.minimize_counterexample(challenge, candidate_id)

    def propose_remediation(self, demo_release_id: str = DemoReleaseId.CROSS_TENANT.value) -> dict[str, Any]:
        return self._remediation.propose_remediation(demo_release_id)

    def rebuild_candidate(self, proposal_id: str, proposal_digest: str) -> dict[str, Any]:
        return self._remediation.rebuild_candidate(proposal_id, proposal_digest)

    def reverify_candidate(self, candidate_id: str, new_source_sha256: str) -> dict[str, Any]:
        return self._remediation.reverify_candidate(candidate_id, new_source_sha256)

    def verify_proof(self, proof_id: str | ProofId = ProofId.CURRENT.value) -> dict[str, Any]:
        try:
            fixture, _scenario = fixture_for_proof(proof_id)
            bounded_proof = proof_id if isinstance(proof_id, ProofId) else ProofId(proof_id)
        except (KeyError, ValueError) as exc:
            allowed = ", ".join(supported_proof_ids())
            raise WebMCPServiceError(
                "UNKNOWN_PROOF",
                "unsupported proof identity",
                status_code=404,
                next_action=f"Supported proof_id values are: {allowed}.",
            ) from exc

        proof_value = bounded_proof.value
        report, source_sha = evaluate_fixture(fixture, release_id=f"webmcp-proof-{proof_value}")
        evidence_ok = evidence_fingerprint(report.findings) == report.evidence_sha256
        source_ok = source_sha == fixture_source_sha(fixture)
        return {
            "proof_id": proof_value,
            "source_sha256": source_sha,
            "policy_sha256": report.policy_sha256,
            "evidence_sha256": report.evidence_sha256,
            "evidence_integrity_verified": evidence_ok,
            "context_bound": source_ok and evidence_ok,
            "signature_status": "LOCAL_DETERMINISTIC_PROOF_CONTEXT",
            "verdict": report.decision.value,
            "authority": "DETERMINISTIC_GATEKEEPER",
            "replay_context_mismatch": False,
        }
