from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Protocol

from release_sentinel.coverage.canonical import sha256_json
from release_sentinel.coverage.models import MeasurementContext, OracleVerdict
from release_sentinel.coverage.oracle import OracleEvaluation, OracleQualificationResult
from release_sentinel.coverage.signing import SignatureEnvelope, Signer, Verifier, sign_json, verify_json
from release_sentinel.domain.evidence import Decision


class CoverageProtocolError(RuntimeError):
    pass


class CoverageOracle(Protocol):
    @property
    def qualification_manifest_sha256(self) -> str: ...

    def evaluate_callable(self, candidate_callable: Callable[..., Any]) -> OracleEvaluation: ...


@dataclass(frozen=True)
class GateSnapshot:
    schema: str
    measurement_id: str
    context_sha256: str
    candidate_sha256: str
    fixture_sha256: str
    policy_sha256: str
    benchmark_manifest_sha256: str
    gatekeeper_digest: str
    gatekeeper_revision: str
    build_receipt_sha256: str
    gate_decision: Decision
    gate_response_sha256: str
    sequence: int
    oracle_result_present: bool
    run_nonce: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "measurement_id": self.measurement_id,
            "context_sha256": self.context_sha256,
            "candidate_sha256": self.candidate_sha256,
            "fixture_sha256": self.fixture_sha256,
            "policy_sha256": self.policy_sha256,
            "benchmark_manifest_sha256": self.benchmark_manifest_sha256,
            "gatekeeper_digest": self.gatekeeper_digest,
            "gatekeeper_revision": self.gatekeeper_revision,
            "build_receipt_sha256": self.build_receipt_sha256,
            "gate_decision": self.gate_decision.value,
            "gate_response_sha256": self.gate_response_sha256,
            "sequence": self.sequence,
            "oracle_result_present": self.oracle_result_present,
            "run_nonce": self.run_nonce,
        }

    @property
    def sha256(self) -> str:
        return sha256_json(self.to_dict())


@dataclass(frozen=True)
class SignedGateSnapshot:
    snapshot: GateSnapshot
    signature: SignatureEnvelope

    @property
    def snapshot_sha256(self) -> str:
        return self.snapshot.sha256

    def to_dict(self) -> dict[str, Any]:
        return {"snapshot": self.snapshot.to_dict(), "signature": self.signature.to_dict()}


@dataclass(frozen=True)
class OracleResult:
    schema: str
    measurement_id: str
    context_sha256: str
    candidate_sha256: str
    gate_snapshot_sha256: str
    verdict: OracleVerdict
    total_vectors: int
    failed_vectors: int
    oracle_digest: str
    qualification_manifest_sha256: str
    oracle_selftest_sha256: str
    sequence: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "measurement_id": self.measurement_id,
            "context_sha256": self.context_sha256,
            "candidate_sha256": self.candidate_sha256,
            "gate_snapshot_sha256": self.gate_snapshot_sha256,
            "verdict": self.verdict.value,
            "total_vectors": self.total_vectors,
            "failed_vectors": self.failed_vectors,
            "oracle_digest": self.oracle_digest,
            "qualification_manifest_sha256": self.qualification_manifest_sha256,
            "oracle_selftest_sha256": self.oracle_selftest_sha256,
            "sequence": self.sequence,
        }

    @property
    def sha256(self) -> str:
        return sha256_json(self.to_dict())


@dataclass(frozen=True)
class SignedOracleResult:
    result: OracleResult
    signature: SignatureEnvelope

    @property
    def result_sha256(self) -> str:
        return self.result.sha256

    def to_dict(self) -> dict[str, Any]:
        return {"result": self.result.to_dict(), "signature": self.signature.to_dict()}


def build_gate_snapshot(
    *,
    context: MeasurementContext,
    gate_decision: Decision,
    gate_response_sha256: str,
    build_receipt_sha256: str,
    gatekeeper_revision: str,
    signer: Signer,
) -> SignedGateSnapshot:
    if gate_decision not in {Decision.GO, Decision.NO_GO}:
        raise CoverageProtocolError("coverage gate snapshot requires GO or NO_GO")
    snapshot = GateSnapshot(
        schema="release-sentinel.gate-snapshot.v1",
        measurement_id=context.measurement_id,
        context_sha256=context.context_sha256,
        candidate_sha256=context.candidate_sha256,
        fixture_sha256=context.fixture_sha256,
        policy_sha256=context.policy_sha256,
        benchmark_manifest_sha256=context.benchmark_manifest_sha256,
        gatekeeper_digest=context.gatekeeper_digest,
        gatekeeper_revision=gatekeeper_revision,
        build_receipt_sha256=build_receipt_sha256,
        gate_decision=gate_decision,
        gate_response_sha256=gate_response_sha256,
        sequence=1,
        oracle_result_present=False,
        run_nonce=context.run_nonce,
    )
    return SignedGateSnapshot(snapshot=snapshot, signature=sign_json(snapshot.to_dict(), signer))


def _assert_gate_context(snapshot: GateSnapshot, context: MeasurementContext) -> None:
    expected = {
        "measurement_id": context.measurement_id,
        "context_sha256": context.context_sha256,
        "candidate_sha256": context.candidate_sha256,
        "fixture_sha256": context.fixture_sha256,
        "policy_sha256": context.policy_sha256,
        "benchmark_manifest_sha256": context.benchmark_manifest_sha256,
        "gatekeeper_digest": context.gatekeeper_digest,
        "run_nonce": context.run_nonce,
    }
    actual = {
        "measurement_id": snapshot.measurement_id,
        "context_sha256": snapshot.context_sha256,
        "candidate_sha256": snapshot.candidate_sha256,
        "fixture_sha256": snapshot.fixture_sha256,
        "policy_sha256": snapshot.policy_sha256,
        "benchmark_manifest_sha256": snapshot.benchmark_manifest_sha256,
        "gatekeeper_digest": snapshot.gatekeeper_digest,
        "run_nonce": snapshot.run_nonce,
    }
    if actual != expected:
        raise CoverageProtocolError("gate snapshot context mismatch")


def verify_signed_gate_snapshot(
    signed: SignedGateSnapshot,
    *,
    context: MeasurementContext,
    verifier: Verifier,
) -> None:
    snapshot = signed.snapshot
    if snapshot.sequence != 1:
        raise CoverageProtocolError("gate snapshot sequence must be 1")
    if snapshot.oracle_result_present is not False:
        raise CoverageProtocolError("gate snapshot oracle_result_present must be false")
    _assert_gate_context(snapshot, context)
    if not verify_json(snapshot.to_dict(), signed.signature, verifier):
        raise CoverageProtocolError("gate snapshot signature verification failed")


def evaluate_after_gate_snapshot(
    *,
    signed_gate_snapshot: SignedGateSnapshot,
    context: MeasurementContext,
    candidate_callable: Callable[..., Any],
    oracle: CoverageOracle,
    qualification: OracleQualificationResult,
    gate_verifier: Verifier,
    oracle_signer: Signer,
) -> SignedOracleResult:
    verify_signed_gate_snapshot(signed_gate_snapshot, context=context, verifier=gate_verifier)
    if not qualification.passed:
        raise CoverageProtocolError("oracle qualification is not valid")
    if qualification.manifest_sha256 != oracle.qualification_manifest_sha256:
        raise CoverageProtocolError("oracle qualification manifest mismatch")
    evaluation = oracle.evaluate_callable(candidate_callable)
    result = OracleResult(
        schema="release-sentinel.oracle-result.v1",
        measurement_id=context.measurement_id,
        context_sha256=context.context_sha256,
        candidate_sha256=context.candidate_sha256,
        gate_snapshot_sha256=signed_gate_snapshot.snapshot_sha256,
        verdict=evaluation.verdict,
        total_vectors=evaluation.total_vectors,
        failed_vectors=len(evaluation.failed_vectors),
        oracle_digest=context.oracle_digest,
        qualification_manifest_sha256=qualification.manifest_sha256,
        oracle_selftest_sha256=qualification.selftest_sha256,
        sequence=2,
    )
    return SignedOracleResult(result=result, signature=sign_json(result.to_dict(), oracle_signer))


def verify_signed_oracle_result(
    signed: SignedOracleResult,
    *,
    context: MeasurementContext,
    gate_snapshot: SignedGateSnapshot,
    verifier: Verifier,
) -> None:
    result = signed.result
    if result.sequence != 2:
        raise CoverageProtocolError("oracle result sequence must be 2")
    if result.measurement_id != context.measurement_id or result.context_sha256 != context.context_sha256:
        raise CoverageProtocolError("oracle result context mismatch")
    if result.candidate_sha256 != context.candidate_sha256:
        raise CoverageProtocolError("oracle result candidate mismatch")
    if result.oracle_digest != context.oracle_digest:
        raise CoverageProtocolError("oracle result oracle digest mismatch")
    if result.gate_snapshot_sha256 != gate_snapshot.snapshot_sha256:
        raise CoverageProtocolError("oracle result gate snapshot mismatch")
    if not verify_json(result.to_dict(), signed.signature, verifier):
        raise CoverageProtocolError("oracle result signature verification failed")
