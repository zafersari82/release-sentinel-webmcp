from dataclasses import replace

import pytest

from release_sentinel.coverage.models import MeasurementContext, OracleVerdict
from release_sentinel.coverage.oracle import CrossTenantOracle
from release_sentinel.coverage.protocol import (
    CoverageProtocolError,
    build_gate_snapshot,
    evaluate_after_gate_snapshot,
    verify_signed_gate_snapshot,
    verify_signed_oracle_result,
)
from release_sentinel.coverage.signing import HmacSha256Authority
from release_sentinel.domain.evidence import Decision


def context(candidate_sha256="c" * 64):
    return MeasurementContext(
        challenge_sha256="a" * 64,
        fixture_sha256="b" * 64,
        candidate_sha256=candidate_sha256,
        policy_sha256="d" * 64,
        benchmark_manifest_sha256="e" * 64,
        oracle_digest="f" * 64,
        gatekeeper_digest="1" * 64,
        runner_digest="2" * 64,
        run_nonce="nonce-123",
    )


def robust_fixed(requester_tenant, resource_tenant):
    if not isinstance(requester_tenant, str) or not isinstance(resource_tenant, str):
        return False
    if not requester_tenant or not resource_tenant:
        return False
    return requester_tenant == resource_tenant


def test_signed_gate_snapshot_is_verified_and_binds_measurement_context():
    authority = HmacSha256Authority(b"gate-secret", "gate-test-key")
    ctx = context()
    signed = build_gate_snapshot(
        context=ctx,
        gate_decision=Decision.GO,
        gate_response_sha256="3" * 64,
        build_receipt_sha256="4" * 64,
        gatekeeper_revision="go-gatekeeper-test",
        signer=authority,
    )
    verify_signed_gate_snapshot(signed, context=ctx, verifier=authority)
    assert signed.snapshot.measurement_id == ctx.measurement_id
    assert signed.snapshot.sequence == 1
    assert signed.snapshot.oracle_result_present is False


def test_tampered_gate_snapshot_is_rejected():
    authority = HmacSha256Authority(b"gate-secret", "gate-test-key")
    ctx = context()
    signed = build_gate_snapshot(
        context=ctx,
        gate_decision=Decision.GO,
        gate_response_sha256="3" * 64,
        build_receipt_sha256="4" * 64,
        gatekeeper_revision="go-gatekeeper-test",
        signer=authority,
    )
    tampered = replace(signed, snapshot=replace(signed.snapshot, gate_decision=Decision.NO_GO))
    with pytest.raises(CoverageProtocolError, match="signature"):
        verify_signed_gate_snapshot(tampered, context=ctx, verifier=authority)


def test_gate_snapshot_from_other_context_is_rejected():
    authority = HmacSha256Authority(b"gate-secret", "gate-test-key")
    signed = build_gate_snapshot(
        context=context(),
        gate_decision=Decision.GO,
        gate_response_sha256="3" * 64,
        build_receipt_sha256="4" * 64,
        gatekeeper_revision="go-gatekeeper-test",
        signer=authority,
    )
    with pytest.raises(CoverageProtocolError, match="context"):
        verify_signed_gate_snapshot(signed, context=context("9" * 64), verifier=authority)


def test_oracle_refuses_to_run_without_valid_signed_gate_snapshot():
    gate_authority = HmacSha256Authority(b"gate-secret", "gate-test-key")
    oracle_authority = HmacSha256Authority(b"oracle-secret", "oracle-test-key")
    ctx = context()
    signed = build_gate_snapshot(
        context=ctx,
        gate_decision=Decision.GO,
        gate_response_sha256="3" * 64,
        build_receipt_sha256="4" * 64,
        gatekeeper_revision="go-gatekeeper-test",
        signer=gate_authority,
    )
    tampered = replace(signed, snapshot=replace(signed.snapshot, oracle_result_present=True))
    qualification = CrossTenantOracle().qualify(
        fixed_callable=robust_fixed,
        vulnerable_callable=lambda _a, _b: True,
    )
    with pytest.raises(CoverageProtocolError, match="oracle_result_present"):
        evaluate_after_gate_snapshot(
            signed_gate_snapshot=tampered,
            context=ctx,
            candidate_callable=robust_fixed,
            oracle=CrossTenantOracle(),
            qualification=qualification,
            gate_verifier=gate_authority,
            oracle_signer=oracle_authority,
        )


def test_oracle_result_binds_verified_gate_snapshot_digest_and_candidate():
    gate_authority = HmacSha256Authority(b"gate-secret", "gate-test-key")
    oracle_authority = HmacSha256Authority(b"oracle-secret", "oracle-test-key")
    ctx = context()
    signed_gate = build_gate_snapshot(
        context=ctx,
        gate_decision=Decision.GO,
        gate_response_sha256="3" * 64,
        build_receipt_sha256="4" * 64,
        gatekeeper_revision="go-gatekeeper-test",
        signer=gate_authority,
    )
    oracle = CrossTenantOracle()
    qualification = oracle.qualify(
        fixed_callable=robust_fixed,
        vulnerable_callable=lambda _a, _b: True,
    )
    signed_oracle = evaluate_after_gate_snapshot(
        signed_gate_snapshot=signed_gate,
        context=ctx,
        candidate_callable=robust_fixed,
        oracle=oracle,
        qualification=qualification,
        gate_verifier=gate_authority,
        oracle_signer=oracle_authority,
    )
    verify_signed_oracle_result(
        signed_oracle,
        context=ctx,
        gate_snapshot=signed_gate,
        verifier=oracle_authority,
    )
    assert signed_oracle.result.verdict is OracleVerdict.SAFE
    assert signed_oracle.result.gate_snapshot_sha256 == signed_gate.snapshot_sha256
    assert signed_oracle.result.candidate_sha256 == ctx.candidate_sha256
    assert signed_oracle.result.sequence == 2


def test_unqualified_oracle_cannot_issue_measurement_result():
    gate_authority = HmacSha256Authority(b"gate-secret", "gate-test-key")
    oracle_authority = HmacSha256Authority(b"oracle-secret", "oracle-test-key")
    ctx = context()
    signed_gate = build_gate_snapshot(
        context=ctx,
        gate_decision=Decision.GO,
        gate_response_sha256="3" * 64,
        build_receipt_sha256="4" * 64,
        gatekeeper_revision="go-gatekeeper-test",
        signer=gate_authority,
    )
    oracle = CrossTenantOracle()
    failed_qualification = oracle.qualify(
        fixed_callable=lambda _a, _b: True,
        vulnerable_callable=lambda _a, _b: True,
    )
    assert failed_qualification.passed is False
    with pytest.raises(CoverageProtocolError, match="qualification"):
        evaluate_after_gate_snapshot(
            signed_gate_snapshot=signed_gate,
            context=ctx,
            candidate_callable=robust_fixed,
            oracle=oracle,
            qualification=failed_qualification,
            gate_verifier=gate_authority,
            oracle_signer=oracle_authority,
        )
