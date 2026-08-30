import json

from release_sentinel.coverage.models import CoverageClassification
from release_sentinel.coverage.runner import run_reference_cross_tenant_arena
from release_sentinel.coverage.signing import HmacSha256Authority


def test_reference_arena_qualifies_oracle_before_measurement_and_reconciles_counts():
    run = run_reference_cross_tenant_arena()
    assert run.oracle_qualification.passed is True
    assert run.counts.total_candidates == run.benchmark.manifest.expected_candidate_count
    assert run.counts.confirmed_safe + run.counts.confirmed_unsafe + run.counts.invalid_candidates == run.counts.total_candidates
    assert run.counts.confirmed_safe == 30
    assert run.counts.confirmed_unsafe == 30


def test_reference_arena_exposes_real_gate_gap_with_escapes_and_correct_blocks():
    run = run_reference_cross_tenant_arena()
    classifications = {item.classification for item in run.measurements}
    assert CoverageClassification.CORRECT_ACCEPT in classifications
    assert CoverageClassification.ESCAPE in classifications
    assert CoverageClassification.CORRECT_BLOCK in classifications
    assert run.counts.escapes > 0
    assert run.counts.correct_blocks > 0


def test_reference_arena_final_receipt_is_signed_and_scope_honest():
    run = run_reference_cross_tenant_arena()
    payload = run.signed_receipt.to_dict()
    assert payload["receipt"]["agent_authority"] == "NONE"
    assert payload["receipt"]["counts"]["escapes"] == run.counts.escapes
    assert "SQL injection" in payload["receipt"]["scope"]["not_tested"]
    assert payload["signature"]["algorithm"] == "HMAC_SHA256_TEST_ONLY"


def test_reference_arena_is_reproducible_without_wall_clock_fields():
    first = run_reference_cross_tenant_arena()
    second = run_reference_cross_tenant_arena()
    assert first.benchmark.manifest.sha256 == second.benchmark.manifest.sha256
    assert first.counts == second.counts
    assert first.signed_receipt.receipt.sha256 == second.signed_receipt.receipt.sha256
    assert [item.classification for item in first.measurements] == [item.classification for item in second.measurements]


def test_three_reference_policies_form_monotonic_escape_overblock_frontier():
    permissive = run_reference_cross_tenant_arena(policy_revision=1)
    balanced = run_reference_cross_tenant_arena(policy_revision=2)
    strict = run_reference_cross_tenant_arena(policy_revision=3)

    assert permissive.benchmark.manifest.sha256 == balanced.benchmark.manifest.sha256 == strict.benchmark.manifest.sha256
    assert permissive.counts.escapes > balanced.counts.escapes > strict.counts.escapes
    assert strict.counts.escapes == 0
    assert permissive.counts.overblocks < balanced.counts.overblocks < strict.counts.overblocks
    assert strict.counts.overblocks >= 15
    assert permissive.counts.confirmed_safe == balanced.counts.confirmed_safe == strict.counts.confirmed_safe == 30
    assert permissive.counts.confirmed_unsafe == balanced.counts.confirmed_unsafe == strict.counts.confirmed_unsafe == 30
    policy_hashes = {
        permissive.signed_receipt.receipt.scope.policy_sha256,
        balanced.signed_receipt.receipt.scope.policy_sha256,
        strict.signed_receipt.receipt.scope.policy_sha256,
    }
    assert len(policy_hashes) == 3
