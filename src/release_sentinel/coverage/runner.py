from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from release_sentinel.coverage.assessment import CoverageCounts, CoverageObservation, aggregate_observations
from release_sentinel.coverage.benchmark import BenchmarkCandidate, BenchmarkSuite, generate_cross_tenant_benchmark
from release_sentinel.coverage.canonical import sha256_json
from release_sentinel.coverage.challenge import CoverageChallenge, load_cross_tenant_challenge, load_path_traversal_challenge
from release_sentinel.coverage.models import CandidateValidity, CoverageClassification, MeasurementContext, OracleVerdict
from release_sentinel.coverage.oracle import CrossTenantOracle, OracleQualificationResult
from release_sentinel.coverage.path_oracle import PathTraversalOracle
from release_sentinel.coverage.path_benchmark import generate_path_traversal_benchmark
from release_sentinel.coverage.path_reference_policy import evaluate_path_reference_gate, path_reference_policy_document
from release_sentinel.coverage.protocol import (
    SignedGateSnapshot,
    SignedOracleResult,
    build_gate_snapshot,
    evaluate_after_gate_snapshot,
)
from release_sentinel.coverage.reference_policy import evaluate_reference_gate, reference_policy_document
from release_sentinel.coverage.receipt import CoverageScope, SignedCoverageReceipt, build_coverage_receipt, sign_coverage_receipt
from release_sentinel.coverage.signing import HmacSha256Authority
from release_sentinel.domain.evidence import Decision


@dataclass(frozen=True)
class ReferenceMeasurement:
    candidate_id: str
    candidate_sha256: str
    gate_decision: Decision
    oracle_verdict: OracleVerdict
    classification: CoverageClassification
    signed_gate_snapshot: SignedGateSnapshot
    signed_oracle_result: SignedOracleResult


@dataclass(frozen=True)
class ReferenceArenaRun:
    benchmark: BenchmarkSuite
    oracle_qualification: OracleQualificationResult
    counts: CoverageCounts
    measurements: tuple[ReferenceMeasurement, ...]
    signed_receipt: SignedCoverageReceipt


@dataclass(frozen=True)
class ReferenceChallengeDefinition:
    challenge_loader: Callable[[], CoverageChallenge]
    benchmark_loader: Callable[[], BenchmarkSuite]
    oracle_factory: Callable[[], Any]
    fixed_callable: Callable[..., Any]
    vulnerable_callable: Callable[..., Any]
    candidate_symbol: str
    policy_document: Callable[[int], dict[str, Any]]
    gate_evaluator: Callable[..., tuple[Decision, str]]
    gate_component: str
    gate_revision_prefix: str


def _qualified_fixed(requester_tenant: Any, resource_tenant: Any) -> bool:
    if not isinstance(requester_tenant, str) or not isinstance(resource_tenant, str):
        return False
    if not requester_tenant or not resource_tenant:
        return False
    return requester_tenant == resource_tenant


def _known_vulnerable(_requester_tenant: Any, _resource_tenant: Any) -> bool:
    return True


def _qualified_path_fixed(base_dir: Any, requested_path: Any, resolved_target: Any) -> bool:
    import posixpath
    from urllib.parse import unquote

    if not all(isinstance(value, str) for value in (base_dir, requested_path, resolved_target)):
        return False
    if not base_dir.startswith("/") or not resolved_target.startswith("/") or not requested_path:
        return False
    if "\x00" in requested_path:
        return False
    decoded = requested_path
    for _ in range(3):
        next_value = unquote(decoded)
        if next_value == decoded:
            break
        decoded = next_value
    decoded = decoded.replace("\\", "/")
    if decoded.startswith("/"):
        return False
    base = posixpath.normpath(base_dir)
    lexical = posixpath.normpath(posixpath.join(base, decoded))
    resolved = posixpath.normpath(resolved_target)
    try:
        return posixpath.commonpath((base, lexical)) == base and posixpath.commonpath((base, resolved)) == base
    except ValueError:
        return False


def _known_path_vulnerable(_base_dir: Any, _requested_path: Any, _resolved_target: Any) -> bool:
    return True


def _load_package_owned_candidate(candidate: BenchmarkCandidate, symbol: str) -> Callable[..., Any]:
    namespace: dict[str, Any] = {"__name__": f"coverage_candidate_{candidate.candidate_id}"}
    code = compile(candidate.source, f"<{candidate.candidate_id}>", "exec")
    exec(code, namespace, namespace)
    candidate_callable = namespace.get(symbol)
    if not callable(candidate_callable):
        raise ValueError(f"benchmark candidate does not expose {symbol}")
    return candidate_callable


def _run_reference_arena(definition: ReferenceChallengeDefinition, *, policy_revision: int) -> ReferenceArenaRun:
    """Run one deterministic package-owned challenge through the shared Arena protocol."""

    benchmark = definition.benchmark_loader()
    oracle = definition.oracle_factory()
    qualification = oracle.qualify(
        fixed_callable=definition.fixed_callable,
        vulnerable_callable=definition.vulnerable_callable,
    )
    if not qualification.passed:
        raise RuntimeError("oracle qualification failed; refusing coverage measurement")

    challenge = definition.challenge_loader()
    if benchmark.manifest.challenge_id != challenge.challenge_id or benchmark.manifest.challenge_revision != challenge.revision:
        raise RuntimeError("benchmark/challenge identity mismatch")
    challenge_sha256 = challenge.sha256
    policy_document = definition.policy_document(policy_revision)
    policy_sha256 = sha256_json(policy_document)
    oracle_digest = sha256_json(
        {
            "revision": oracle.REVISION,
            "qualification_manifest_sha256": qualification.manifest_sha256,
        }
    )
    gatekeeper_digest = sha256_json({"component": definition.gate_component, "revision": policy_revision})
    runner_digest = sha256_json({"component": "package-owned-reference-runner", "revision": 2})

    gate_authority = HmacSha256Authority(b"release-sentinel-reference-gate-v1", "reference-gate-test-key")
    oracle_authority = HmacSha256Authority(b"release-sentinel-reference-oracle-v1", "reference-oracle-test-key")
    receipt_authority = HmacSha256Authority(b"release-sentinel-reference-receipt-v1", "reference-receipt-test-key")

    observations: list[CoverageObservation] = []
    measurements: list[ReferenceMeasurement] = []
    for candidate in benchmark.candidates:
        try:
            candidate_callable = _load_package_owned_candidate(candidate, definition.candidate_symbol)
        except Exception:
            observations.append(CoverageObservation(candidate.candidate_id, CandidateValidity.INVALID, None, None))
            continue

        gate_decision, gate_response_sha256 = definition.gate_evaluator(
            candidate_callable,
            candidate.source,
            policy_revision=policy_revision,
        )
        context = MeasurementContext(
            challenge_sha256=challenge_sha256,
            fixture_sha256=benchmark.manifest.base_fixture_sha256,
            candidate_sha256=candidate.source_sha256,
            policy_sha256=policy_sha256,
            benchmark_manifest_sha256=benchmark.manifest.sha256,
            oracle_digest=oracle_digest,
            gatekeeper_digest=gatekeeper_digest,
            runner_digest=runner_digest,
            run_nonce=sha256_json(
                {"lane": "REFERENCE", "challenge_id": challenge.challenge_id, "candidate_id": candidate.candidate_id}
            )[:32],
        )
        build_receipt_sha256 = sha256_json(
            {
                "candidate_sha256": candidate.source_sha256,
                "build_valid": True,
                "runner_digest": runner_digest,
            }
        )
        signed_gate = build_gate_snapshot(
            context=context,
            gate_decision=gate_decision,
            gate_response_sha256=gate_response_sha256,
            build_receipt_sha256=build_receipt_sha256,
            gatekeeper_revision=f"{definition.gate_revision_prefix}-v{policy_revision}",
            signer=gate_authority,
        )
        signed_oracle = evaluate_after_gate_snapshot(
            signed_gate_snapshot=signed_gate,
            context=context,
            candidate_callable=candidate_callable,
            oracle=oracle,
            qualification=qualification,
            gate_verifier=gate_authority,
            oracle_signer=oracle_authority,
        )
        observation = CoverageObservation(
            candidate.candidate_id,
            CandidateValidity.VALID,
            gate_decision,
            signed_oracle.result.verdict,
        )
        observations.append(observation)
        measurements.append(
            ReferenceMeasurement(
                candidate_id=candidate.candidate_id,
                candidate_sha256=candidate.source_sha256,
                gate_decision=gate_decision,
                oracle_verdict=signed_oracle.result.verdict,
                classification=observation.classification,
                signed_gate_snapshot=signed_gate,
                signed_oracle_result=signed_oracle,
            )
        )

    counts = aggregate_observations(observations)
    scope = CoverageScope(
        challenge_sha256=challenge_sha256,
        fixture_sha256=benchmark.manifest.base_fixture_sha256,
        policy_sha256=policy_sha256,
        benchmark_manifest_sha256=benchmark.manifest.sha256,
        oracle_digest=oracle_digest,
        gatekeeper_digest=gatekeeper_digest,
        runner_digest=runner_digest,
        oracle_qualification_manifest_sha256=qualification.manifest_sha256,
        oracle_selftest_sha256=qualification.selftest_sha256,
        tested=tuple(challenge.payload["scope"]["tested"]),
        not_tested=tuple(challenge.payload["scope"]["not_tested"]),
    )
    signed_receipt = sign_coverage_receipt(build_coverage_receipt(scope=scope, counts=counts), receipt_authority)
    return ReferenceArenaRun(
        benchmark=benchmark,
        oracle_qualification=qualification,
        counts=counts,
        measurements=tuple(measurements),
        signed_receipt=signed_receipt,
    )


_CROSS_TENANT = ReferenceChallengeDefinition(
    challenge_loader=load_cross_tenant_challenge,
    benchmark_loader=generate_cross_tenant_benchmark,
    oracle_factory=CrossTenantOracle,
    fixed_callable=_qualified_fixed,
    vulnerable_callable=_known_vulnerable,
    candidate_symbol="can_read",
    policy_document=reference_policy_document,
    gate_evaluator=evaluate_reference_gate,
    gate_component="reference-auth-boundary-gate",
    gate_revision_prefix="reference-auth-boundary-gate",
)

_PATH_TRAVERSAL = ReferenceChallengeDefinition(
    challenge_loader=load_path_traversal_challenge,
    benchmark_loader=generate_path_traversal_benchmark,
    oracle_factory=PathTraversalOracle,
    fixed_callable=_qualified_path_fixed,
    vulnerable_callable=_known_path_vulnerable,
    candidate_symbol="can_open_path",
    policy_document=path_reference_policy_document,
    gate_evaluator=evaluate_path_reference_gate,
    gate_component="reference-path-containment-gate",
    gate_revision_prefix="reference-path-containment-gate",
)


def run_reference_cross_tenant_arena(*, policy_revision: int = 1) -> ReferenceArenaRun:
    return _run_reference_arena(_CROSS_TENANT, policy_revision=policy_revision)


def run_reference_path_traversal_arena(*, policy_revision: int = 1) -> ReferenceArenaRun:
    return _run_reference_arena(_PATH_TRAVERSAL, policy_revision=policy_revision)
