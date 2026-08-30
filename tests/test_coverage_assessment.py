import pytest

from release_sentinel.coverage.assessment import (
    CoverageObservation,
    aggregate_observations,
    classify_observation,
    holm_bonferroni,
    paired_mcnemar_exact,
    wilson_interval,
)
from release_sentinel.coverage.models import CandidateValidity, CoverageClassification, OracleVerdict
from release_sentinel.domain.evidence import Decision


@pytest.mark.parametrize(
    ("gate", "oracle", "expected"),
    [
        (Decision.GO, OracleVerdict.SAFE, CoverageClassification.CORRECT_ACCEPT),
        (Decision.GO, OracleVerdict.UNSAFE, CoverageClassification.ESCAPE),
        (Decision.NO_GO, OracleVerdict.SAFE, CoverageClassification.OVERBLOCK),
        (Decision.NO_GO, OracleVerdict.UNSAFE, CoverageClassification.CORRECT_BLOCK),
    ],
)
def test_classification_covers_all_gate_oracle_cells(gate, oracle, expected):
    assert classify_observation(CandidateValidity.VALID, gate, oracle) is expected


def test_invalid_candidate_is_excluded_even_without_gate_oracle_results():
    assert classify_observation(CandidateValidity.INVALID, None, None) is CoverageClassification.INVALID_CANDIDATE


def test_valid_candidate_requires_gate_and_oracle_results():
    with pytest.raises(ValueError, match="valid candidate requires"):
        classify_observation(CandidateValidity.VALID, None, OracleVerdict.SAFE)


def test_aggregate_counts_reconcile_without_polluting_denominators():
    observations = [
        CoverageObservation("safe-ok", CandidateValidity.VALID, Decision.GO, OracleVerdict.SAFE),
        CoverageObservation("safe-blocked", CandidateValidity.VALID, Decision.NO_GO, OracleVerdict.SAFE),
        CoverageObservation("unsafe-blocked", CandidateValidity.VALID, Decision.NO_GO, OracleVerdict.UNSAFE),
        CoverageObservation("unsafe-escape", CandidateValidity.VALID, Decision.GO, OracleVerdict.UNSAFE),
        CoverageObservation("invalid", CandidateValidity.INVALID, None, None),
    ]
    counts = aggregate_observations(observations)
    assert counts.confirmed_safe == 2
    assert counts.confirmed_unsafe == 2
    assert counts.correct_accepts == 1
    assert counts.overblocks == 1
    assert counts.correct_blocks == 1
    assert counts.escapes == 1
    assert counts.invalid_candidates == 1
    assert counts.valid_candidates == 4
    assert counts.total_candidates == 5


def test_wilson_interval_matches_known_small_sample_escape_case():
    low, high = wilson_interval(2, 53)
    assert low == pytest.approx(0.0104102873, rel=1e-7)
    assert high == pytest.approx(0.1275428720, rel=1e-7)


def test_wilson_interval_for_zero_denominator_is_none():
    assert wilson_interval(0, 0) is None


def test_aggregate_exposes_raw_counts_before_derived_rates():
    counts = aggregate_observations(
        [
            CoverageObservation("u1", CandidateValidity.VALID, Decision.NO_GO, OracleVerdict.UNSAFE),
            CoverageObservation("u2", CandidateValidity.VALID, Decision.GO, OracleVerdict.UNSAFE),
        ]
    )
    payload = counts.to_dict()
    assert payload["confirmed_unsafe"] == 2
    assert payload["escapes"] == 1
    assert payload["escape_rate"]["numerator"] == 1
    assert payload["escape_rate"]["denominator"] == 2
    assert payload["escape_rate"]["wilson_95"] is not None


def test_paired_mcnemar_exact_matches_known_discordant_counts():
    first = {f"c{i}": i < 20 for i in range(30)}
    second = {f"c{i}": False for i in range(30)}
    result = paired_mcnemar_exact(first, second)
    assert result["total_pairs"] == 30
    assert result["only_first"] == 20
    assert result["only_second"] == 0
    assert result["discordant_pairs"] == 20
    assert result["exact_p_value"] == pytest.approx(1.9073486328125e-06)


def test_paired_mcnemar_exact_rejects_mismatched_candidate_sets():
    with pytest.raises(ValueError, match="identical candidate ids"):
        paired_mcnemar_exact({"a": True}, {"b": True})


def test_paired_mcnemar_exact_handles_no_discordant_pairs():
    result = paired_mcnemar_exact({"a": True, "b": False}, {"a": True, "b": False})
    assert result["discordant_pairs"] == 0
    assert result["exact_p_value"] == 1.0


def test_holm_bonferroni_applies_step_down_family_wise_correction():
    p_values = [
        2.384185791015625e-07,
        9.5367431640625e-07,
        1.9073486328125e-06,
        1.52587890625e-05,
        0.125,
        0.25,
    ]
    results = holm_bonferroni(p_values, alpha=0.05)
    assert [item["adjusted_alpha"] for item in results] == pytest.approx([
        0.05 / 6,
        0.05 / 5,
        0.05 / 4,
        0.05 / 3,
        0.05 / 2,
        0.05,
    ])
    assert [item["reject_null_after_correction"] for item in results] == [
        True, True, True, True, False, False
    ]


def test_holm_bonferroni_preserves_input_order_after_ranking():
    results = holm_bonferroni([0.25, 1e-6, 0.125], alpha=0.05)
    assert [item["raw_p_value"] for item in results] == [0.25, 1e-6, 0.125]
    assert [item["holm_rank"] for item in results] == [3, 1, 2]
    assert [item["reject_null_after_correction"] for item in results] == [False, True, False]
