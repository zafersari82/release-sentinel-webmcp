from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from release_sentinel.coverage.assessment import CoverageCounts
from release_sentinel.coverage.canonical import sha256_json
from release_sentinel.coverage.signing import SignatureEnvelope, Signer, Verifier, sign_json, verify_json


def _require_sha256(name: str, value: str) -> None:
    if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value.lower()):
        raise ValueError(f"{name} must be a 64-character SHA-256 hex digest")


@dataclass(frozen=True)
class CoverageScope:
    challenge_sha256: str
    fixture_sha256: str
    policy_sha256: str
    benchmark_manifest_sha256: str
    oracle_digest: str
    gatekeeper_digest: str
    runner_digest: str
    oracle_qualification_manifest_sha256: str
    oracle_selftest_sha256: str
    tested: tuple[str, ...]
    not_tested: tuple[str, ...]

    def __post_init__(self) -> None:
        for name in (
            "challenge_sha256",
            "fixture_sha256",
            "policy_sha256",
            "benchmark_manifest_sha256",
            "oracle_digest",
            "gatekeeper_digest",
            "runner_digest",
            "oracle_qualification_manifest_sha256",
            "oracle_selftest_sha256",
        ):
            _require_sha256(name, getattr(self, name))
        tested = tuple(self.tested)
        not_tested = tuple(self.not_tested)
        if not tested:
            raise ValueError("tested scope must be non-empty")
        if set(tested) & set(not_tested):
            raise ValueError("tested and not_tested scope must be disjoint")
        object.__setattr__(self, "tested", tested)
        object.__setattr__(self, "not_tested", not_tested)

    def to_dict(self) -> dict[str, Any]:
        return {
            "challenge_sha256": self.challenge_sha256,
            "fixture_sha256": self.fixture_sha256,
            "policy_sha256": self.policy_sha256,
            "benchmark_manifest_sha256": self.benchmark_manifest_sha256,
            "oracle_digest": self.oracle_digest,
            "gatekeeper_digest": self.gatekeeper_digest,
            "runner_digest": self.runner_digest,
            "oracle_qualification_manifest_sha256": self.oracle_qualification_manifest_sha256,
            "oracle_selftest_sha256": self.oracle_selftest_sha256,
            "tested": list(self.tested),
            "not_tested": list(self.not_tested),
        }


@dataclass(frozen=True)
class CoverageReceipt:
    schema: str
    claim: str
    scope: CoverageScope
    counts: CoverageCounts
    benchmark_lane: str
    agent_authority: str
    historical_replay: Mapping[str, Any] | None = None
    hunt: Mapping[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema": self.schema,
            "claim": self.claim,
            "scope": self.scope.to_dict(),
            "counts": self.counts.to_dict(),
            "benchmark_lane": self.benchmark_lane,
            "agent_authority": self.agent_authority,
        }
        if self.historical_replay is not None:
            payload["historical_replay"] = dict(self.historical_replay)
        if self.hunt is not None:
            payload["hunt"] = dict(self.hunt)
        return payload

    @property
    def sha256(self) -> str:
        return sha256_json(self.to_dict())


@dataclass(frozen=True)
class CoverageComparisonReceipt:
    schema: str
    claim: str
    comparison_scope_sha256: str
    benchmark_manifest_sha256: str
    points: tuple[Mapping[str, Any], ...]
    mcnemar: Mapping[str, Any]
    agent_authority: str

    def __post_init__(self) -> None:
        _require_sha256("comparison_scope_sha256", self.comparison_scope_sha256)
        _require_sha256("benchmark_manifest_sha256", self.benchmark_manifest_sha256)
        if len(self.points) < 2:
            raise ValueError("comparison receipt requires at least two policy points")
        for point in self.points:
            _require_sha256("policy_sha256", str(point.get("policy_sha256", "")))
        if self.mcnemar.get("paired_by") != "candidate_id":
            raise ValueError("comparison receipt requires candidate_id paired McNemar data")
        if self.agent_authority != "NONE":
            raise ValueError("comparison receipt agent authority must be NONE")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "claim": self.claim,
            "comparison_scope_sha256": self.comparison_scope_sha256,
            "benchmark_manifest_sha256": self.benchmark_manifest_sha256,
            "points": [dict(point) for point in self.points],
            "mcnemar": dict(self.mcnemar),
            "agent_authority": self.agent_authority,
        }

    @property
    def sha256(self) -> str:
        return sha256_json(self.to_dict())


@dataclass(frozen=True)
class SignedCoverageComparisonReceipt:
    receipt: CoverageComparisonReceipt
    signature: SignatureEnvelope

    def to_dict(self) -> dict[str, Any]:
        return {"receipt": self.receipt.to_dict(), "signature": self.signature.to_dict()}


@dataclass(frozen=True)
class SignedCoverageReceipt:
    receipt: CoverageReceipt
    signature: SignatureEnvelope

    def to_dict(self) -> dict[str, Any]:
        return {"receipt": self.receipt.to_dict(), "signature": self.signature.to_dict()}


def build_coverage_receipt(
    *,
    scope: CoverageScope,
    counts: CoverageCounts,
    historical_replay: Mapping[str, Any] | None = None,
    hunt: Mapping[str, Any] | None = None,
) -> CoverageReceipt:
    if counts.confirmed_safe != counts.correct_accepts + counts.overblocks:
        raise ValueError("safe population does not reconcile")
    if counts.confirmed_unsafe != counts.correct_blocks + counts.escapes:
        raise ValueError("unsafe population does not reconcile")
    return CoverageReceipt(
        schema="release-sentinel.coverage-receipt.v1",
        claim="SCOPED_GATE_GAP_MEASUREMENT",
        scope=scope,
        counts=counts,
        benchmark_lane="DETERMINISTIC",
        agent_authority="NONE",
        historical_replay=historical_replay,
        hunt=hunt,
    )


def sign_coverage_receipt(receipt: CoverageReceipt, signer: Signer) -> SignedCoverageReceipt:
    if receipt.agent_authority != "NONE":
        raise ValueError("coverage receipt agent authority must be NONE")
    return SignedCoverageReceipt(receipt=receipt, signature=sign_json(receipt.to_dict(), signer))


def verify_signed_coverage_receipt(signed: SignedCoverageReceipt, *, verifier: Verifier) -> None:
    if signed.receipt.agent_authority != "NONE":
        raise ValueError("coverage receipt authority contract violated")
    if not verify_json(signed.receipt.to_dict(), signed.signature, verifier):
        raise ValueError("coverage receipt signature verification failed")


def build_coverage_comparison_receipt(
    *,
    comparison_scope_sha256: str,
    benchmark_manifest_sha256: str,
    points: tuple[Mapping[str, Any], ...],
    mcnemar: Mapping[str, Any],
) -> CoverageComparisonReceipt:
    return CoverageComparisonReceipt(
        schema="release-sentinel.coverage-comparison-receipt.v1",
        claim="SCOPED_PAIRED_POLICY_TRADEOFF",
        comparison_scope_sha256=comparison_scope_sha256,
        benchmark_manifest_sha256=benchmark_manifest_sha256,
        points=tuple(points),
        mcnemar=dict(mcnemar),
        agent_authority="NONE",
    )


def sign_coverage_comparison_receipt(
    receipt: CoverageComparisonReceipt, signer: Signer
) -> SignedCoverageComparisonReceipt:
    if receipt.agent_authority != "NONE":
        raise ValueError("comparison receipt agent authority must be NONE")
    return SignedCoverageComparisonReceipt(receipt=receipt, signature=sign_json(receipt.to_dict(), signer))


def verify_signed_coverage_comparison_receipt(
    signed: SignedCoverageComparisonReceipt, *, verifier: Verifier
) -> None:
    if signed.receipt.agent_authority != "NONE":
        raise ValueError("comparison receipt authority contract violated")
    if not verify_json(signed.receipt.to_dict(), signed.signature, verifier):
        raise ValueError("comparison receipt signature verification failed")
