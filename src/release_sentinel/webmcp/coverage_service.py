from __future__ import annotations

import hashlib
from functools import lru_cache
from typing import Any, Callable

from release_sentinel.coverage.canonical import canonical_json_bytes
from release_sentinel.coverage.comparison import build_reference_demo_payload
from release_sentinel.coverage.minimizer import MinimizationBudget, minimize_lines
from release_sentinel.coverage.models import CoverageClassification, OracleVerdict
from release_sentinel.coverage.oracle import CrossTenantOracle
from release_sentinel.coverage.path_oracle import PathTraversalOracle
from release_sentinel.coverage.path_reference_policy import evaluate_path_reference_gate
from release_sentinel.coverage.receipt import verify_signed_coverage_receipt
from release_sentinel.coverage.reference_policy import evaluate_reference_gate
from release_sentinel.coverage.runner import (
    ReferenceArenaRun,
    run_reference_cross_tenant_arena,
    run_reference_path_traversal_arena,
)
from release_sentinel.coverage.signing import HmacSha256Authority, SignatureEnvelope
from release_sentinel.domain.evidence import Decision
from release_sentinel.webmcp.contracts import ChallengeId, PolicyRevision
from release_sentinel.webmcp.errors import WebMCPServiceError


class CoverageArenaAdapter:
    @staticmethod
    @lru_cache(maxsize=6)
    def _coverage_run(challenge: ChallengeId, revision: PolicyRevision) -> ReferenceArenaRun:
        if challenge is ChallengeId.CROSS_TENANT:
            return run_reference_cross_tenant_arena(policy_revision=int(revision))
        return run_reference_path_traversal_arena(policy_revision=int(revision))

    @staticmethod
    def _coverage_authority() -> HmacSha256Authority:
        return HmacSha256Authority(b"release-sentinel-reference-receipt-v1", "reference-receipt-test-key")

    def inspect_coverage(self, challenge: str, revision: int = 3) -> dict[str, Any]:
        try:
            challenge_id = ChallengeId(challenge)
            policy_revision = PolicyRevision(revision)
        except ValueError as exc:
            raise WebMCPServiceError(
                "INVALID_COVERAGE_SCOPE", "unsupported challenge or policy revision", status_code=422
            ) from exc
        run = self._coverage_run(challenge_id, policy_revision)
        verify_signed_coverage_receipt(run.signed_receipt, verifier=self._coverage_authority())
        scope = run.signed_receipt.receipt.scope.to_dict()
        return {
            "challenge": challenge_id.value,
            "challenge_id": run.benchmark.manifest.challenge_id,
            "revision": int(policy_revision),
            "oracle_qualified": run.oracle_qualification.passed,
            "benchmark_manifest_sha256": run.benchmark.manifest.sha256,
            "policy_sha256": scope["policy_sha256"],
            "counts": run.counts.to_dict(),
            "receipt_sha256": run.signed_receipt.receipt.sha256,
            "receipt_verified": True,
            "tested_scope": list(scope["tested"]),
            "not_tested_scope": list(scope["not_tested"]),
            "claim": "SCOPED_GATE_GAP_MEASUREMENT",
            "authority": "MEASUREMENT_ONLY",
        }

    def compare_gate_revisions(self, challenge: str) -> dict[str, Any]:
        try:
            challenge_id = ChallengeId(challenge)
        except ValueError as exc:
            raise WebMCPServiceError("INVALID_COVERAGE_SCOPE", "unsupported challenge", status_code=422) from exc
        payload = build_reference_demo_payload(challenge_id.value)
        signed = payload["tradeoff"]["signed_comparison_receipt"]
        receipt = signed["receipt"]
        signature = SignatureEnvelope(**signed["signature"])
        authority = HmacSha256Authority(
            b"release-sentinel-reference-comparison-v1", "reference-comparison-test-key"
        )
        raw = canonical_json_bytes(receipt)
        verified = (
            hashlib.sha256(raw).hexdigest() == signature.payload_sha256
            and authority.verify(
                raw,
                signature.signature_bytes(),
                key_id=signature.key_id,
                algorithm=signature.algorithm,
            )
        )
        if not verified:
            raise WebMCPServiceError(
                "COMPARISON_RECEIPT_INVALID", "coverage comparison receipt verification failed"
            )
        points = [
            {
                "revision": int(point["policy_revision"]),
                "policy_sha256": point["policy_sha256"],
                "escapes": point["escapes"],
                "overblocks": point["overblocks"],
                "escape_rate": point["escape_rate"],
                "overblock_rate": point["overblock_rate"],
            }
            for point in payload["tradeoff"]["points"]
        ]
        return {
            "challenge": challenge_id.value,
            "challenge_id": payload["challenge_id"],
            "oracle_qualified": payload["oracle_qualified"],
            "revisions": points,
            "paired_diagnostics": payload["tradeoff"]["mcnemar"],
            "comparison_scope_sha256": payload["tradeoff"]["comparison_scope_sha256"],
            "comparison_receipt_verified": True,
            "scope_warning": "0 observed escapes is scoped to this fixed benchmark corpus.",
            "authority": "MEASUREMENT_ONLY",
        }

    def find_counterexamples(self, challenge: str, revision: int = 1) -> dict[str, Any]:
        try:
            challenge_id = ChallengeId(challenge)
            policy_revision = PolicyRevision(revision)
        except ValueError as exc:
            raise WebMCPServiceError(
                "INVALID_COVERAGE_SCOPE", "unsupported challenge or policy revision", status_code=422
            ) from exc
        run = self._coverage_run(challenge_id, policy_revision)
        rows = [
            {
                "candidate_id": measurement.candidate_id,
                "candidate_sha256": measurement.candidate_sha256,
                "classification": measurement.classification.value,
                "gate_decision": measurement.gate_decision.value,
                "oracle_verdict": measurement.oracle_verdict.value,
                "policy_revision": int(policy_revision),
            }
            for measurement in run.measurements
            if measurement.classification is CoverageClassification.ESCAPE
        ]
        return {
            "challenge": challenge_id.value,
            "revision": int(policy_revision),
            "counterexamples": rows,
            "source_exposure": "IDENTITY_ONLY",
            "authority": "MEASUREMENT_ONLY",
        }

    def minimize_counterexample(self, challenge: str, candidate_id: str) -> dict[str, Any]:
        try:
            challenge_id = ChallengeId(challenge)
        except ValueError as exc:
            raise WebMCPServiceError("INVALID_COVERAGE_SCOPE", "unsupported challenge", status_code=422) from exc

        selected_revision: PolicyRevision | None = None
        selected_source: str | None = None
        for revision in PolicyRevision:
            run = self._coverage_run(challenge_id, revision)
            escape_ids = {
                item.candidate_id
                for item in run.measurements
                if item.classification is CoverageClassification.ESCAPE
            }
            if candidate_id not in escape_ids:
                continue
            candidate = next((item for item in run.benchmark.candidates if item.candidate_id == candidate_id), None)
            if candidate is not None:
                selected_revision = revision
                selected_source = candidate.source
                break
        if selected_revision is None or selected_source is None:
            raise WebMCPServiceError(
                "UNKNOWN_COUNTEREXAMPLE",
                "counterexample is not a package-owned observed escape",
                status_code=404,
            )

        predicate = self._escape_predicate(challenge_id, selected_revision)
        result = minimize_lines(
            selected_source,
            predicate,
            MinimizationBudget(max_evaluations=128, max_seconds=2.0),
        )
        if not predicate(result.source):
            raise WebMCPServiceError(
                "MINIMIZATION_VERIFICATION_FAILED", "minimized source no longer reproduces the escape"
            )
        return {
            "challenge": challenge_id.value,
            "candidate_id": candidate_id,
            "policy_revision": int(selected_revision),
            "original_sha256": hashlib.sha256(selected_source.encode("utf-8")).hexdigest(),
            "minimized_sha256": hashlib.sha256(result.source.encode("utf-8")).hexdigest(),
            "minimized_source": result.source,
            "status": result.status.value,
            "evaluations": result.evaluations,
            "removed_lines": result.removed_lines,
            "verified_escape": True,
            "authority": "MEASUREMENT_ONLY",
        }

    @staticmethod
    def _escape_predicate(challenge: ChallengeId, revision: PolicyRevision) -> Callable[[str], bool]:
        symbol = "can_read" if challenge is ChallengeId.CROSS_TENANT else "can_open_path"

        def predicate(source: str) -> bool:
            namespace: dict[str, Any] = {"__name__": "webmcp_minimized_candidate"}
            try:
                exec(compile(source, "<webmcp-minimize>", "exec"), namespace, namespace)
            except Exception:
                return False
            candidate = namespace.get(symbol)
            if not callable(candidate):
                return False
            if challenge is ChallengeId.CROSS_TENANT:
                gate, _ = evaluate_reference_gate(candidate, source, policy_revision=int(revision))
                oracle = CrossTenantOracle().evaluate_callable(candidate).verdict
            else:
                gate, _ = evaluate_path_reference_gate(candidate, source, policy_revision=int(revision))
                oracle = PathTraversalOracle().evaluate_callable(candidate).verdict
            return gate is Decision.GO and oracle is OracleVerdict.UNSAFE

        return predicate
