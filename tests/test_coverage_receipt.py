from dataclasses import replace

from release_sentinel.coverage.assessment import CoverageCounts
from release_sentinel.coverage.receipt import (
    CoverageScope,
    build_coverage_comparison_receipt,
    build_coverage_receipt,
    sign_coverage_comparison_receipt,
    sign_coverage_receipt,
    verify_signed_coverage_comparison_receipt,
    verify_signed_coverage_receipt,
)
from release_sentinel.coverage.signing import HmacSha256Authority


def scope():
    return CoverageScope(
        challenge_sha256="a" * 64,
        fixture_sha256="b" * 64,
        policy_sha256="c" * 64,
        benchmark_manifest_sha256="d" * 64,
        oracle_digest="e" * 64,
        gatekeeper_digest="f" * 64,
        runner_digest="1" * 64,
        oracle_qualification_manifest_sha256="2" * 64,
        oracle_selftest_sha256="3" * 64,
        tested=(
            "tenant isolation",
            "strict identifier distinction",
            "same-tenant availability",
            "malformed identity rejection",
        ),
        not_tested=("SQL injection", "rate limiting", "cryptographic misuse", "availability"),
    )


def counts():
    return CoverageCounts(
        confirmed_safe=12,
        confirmed_unsafe=53,
        correct_accepts=11,
        overblocks=1,
        correct_blocks=51,
        escapes=2,
        invalid_candidates=4,
    )


def test_receipt_binds_full_measurement_scope_and_raw_counts():
    receipt = build_coverage_receipt(scope=scope(), counts=counts())
    payload = receipt.to_dict()
    assert payload["schema"] == "release-sentinel.coverage-receipt.v1"
    assert payload["scope"]["fixture_sha256"] == "b" * 64
    assert payload["scope"]["policy_sha256"] == "c" * 64
    assert payload["scope"]["benchmark_manifest_sha256"] == "d" * 64
    assert payload["scope"]["oracle_digest"] == "e" * 64
    assert payload["scope"]["gatekeeper_digest"] == "f" * 64
    assert payload["scope"]["runner_digest"] == "1" * 64
    assert payload["counts"]["confirmed_unsafe"] == 53
    assert payload["counts"]["escapes"] == 2
    assert payload["counts"]["escape_rate"]["numerator"] == 2
    assert payload["counts"]["escape_rate"]["denominator"] == 53


def test_receipt_explicitly_lists_unmeasured_scope_and_zero_agent_authority():
    receipt = build_coverage_receipt(scope=scope(), counts=counts())
    payload = receipt.to_dict()
    assert "SQL injection" in payload["scope"]["not_tested"]
    assert "tenant isolation" in payload["scope"]["tested"]
    assert payload["agent_authority"] == "NONE"
    assert payload["claim"] == "SCOPED_GATE_GAP_MEASUREMENT"


def test_scope_change_changes_receipt_digest():
    first = build_coverage_receipt(scope=scope(), counts=counts())
    second = build_coverage_receipt(
        scope=replace(scope(), fixture_sha256="9" * 64),
        counts=counts(),
    )
    assert first.sha256 != second.sha256


def test_signed_receipt_verifies_and_tampering_fails():
    authority = HmacSha256Authority(b"receipt-secret", "receipt-test-key")
    signed = sign_coverage_receipt(build_coverage_receipt(scope=scope(), counts=counts()), authority)
    verify_signed_coverage_receipt(signed, verifier=authority)
    tampered = replace(signed, receipt=replace(signed.receipt, agent_authority="MODEL"))
    try:
        verify_signed_coverage_receipt(tampered, verifier=authority)
    except ValueError as exc:
        assert "authority" in str(exc) or "signature" in str(exc)
    else:
        raise AssertionError("tampered receipt was accepted")


def test_scope_requires_tested_and_not_tested_to_be_disjoint():
    try:
        CoverageScope(
            challenge_sha256="a" * 64,
            fixture_sha256="b" * 64,
            policy_sha256="c" * 64,
            benchmark_manifest_sha256="d" * 64,
            oracle_digest="e" * 64,
            gatekeeper_digest="f" * 64,
            runner_digest="1" * 64,
            oracle_qualification_manifest_sha256="2" * 64,
            oracle_selftest_sha256="3" * 64,
            tested=("tenant isolation",),
            not_tested=("tenant isolation",),
        )
    except ValueError as exc:
        assert "disjoint" in str(exc)
    else:
        raise AssertionError("overlapping scope was accepted")


def test_signed_comparison_receipt_binds_scope_points_and_mcnemar():
    authority = HmacSha256Authority(b"comparison-secret", "comparison-test-key")
    receipt = build_coverage_comparison_receipt(
        comparison_scope_sha256="a" * 64,
        benchmark_manifest_sha256="b" * 64,
        points=(
            {"policy_revision": 1, "policy_sha256": "c" * 64, "escapes": 7, "overblocks": 0},
            {"policy_revision": 2, "policy_sha256": "d" * 64, "escapes": 1, "overblocks": 3},
        ),
        mcnemar={
            "method": "EXACT_TWO_SIDED_BINOMIAL_P_0_5",
            "paired_by": "candidate_id",
            "inference_scope": "FIXED_HASH_BOUND_BENCHMARK_ONLY",
            "comparisons": [
                {
                    "metric": "escape",
                    "policy_revision_from": 1,
                    "policy_revision_to": 2,
                    "only_from": 6,
                    "only_to": 0,
                    "discordant_pairs": 6,
                    "exact_p_value": 0.03125,
                    "reject_null_at_alpha": True,
                }
            ],
        },
    )
    signed = sign_coverage_comparison_receipt(receipt, authority)
    verify_signed_coverage_comparison_receipt(signed, verifier=authority)
    payload = signed.to_dict()
    assert payload["receipt"]["claim"] == "SCOPED_PAIRED_POLICY_TRADEOFF"
    assert payload["receipt"]["comparison_scope_sha256"] == "a" * 64
    assert payload["receipt"]["mcnemar"]["paired_by"] == "candidate_id"
    assert payload["receipt"]["agent_authority"] == "NONE"
    assert payload["signature"]["algorithm"] == "HMAC_SHA256_TEST_ONLY"
