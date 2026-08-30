import json
import sys

import pytest

from release_sentinel.interfaces.cli import main


def test_cli_coverage_demo_compares_three_scoped_reference_policies(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["release-sentinel", "coverage-demo"])
    assert main() == 0
    payload = json.loads(capsys.readouterr().out)

    assert payload["mode"] == "REFERENCE_OFFLINE"
    assert payload["oracle_qualified"] is True
    assert payload["agent_authority"] == "NONE"
    assert payload["production_release_authority"] == "UNCHANGED"
    assert "intentionally simplified demo policies" in payload["interpretation"]

    assert [run["policy_revision"] for run in payload["policy_comparison"]] == [1, 2, 3]
    rev1, rev2, rev3 = payload["policy_comparison"]
    assert rev1["benchmark_manifest_sha256"] == rev2["benchmark_manifest_sha256"] == rev3["benchmark_manifest_sha256"]
    assert rev1["counts"]["confirmed_safe"] == 30
    assert rev1["counts"]["confirmed_unsafe"] == 30
    assert rev1["counts"]["escapes"] > rev2["counts"]["escapes"] > rev3["counts"]["escapes"]
    assert rev3["counts"]["escapes"] == 0
    assert rev1["counts"]["overblocks"] < rev2["counts"]["overblocks"] < rev3["counts"]["overblocks"]
    assert rev3["counts"]["overblocks"] >= 15
    for run in (rev1, rev2, rev3):
        assert run["signed_receipt"]["signature"]["algorithm"] == "HMAC_SHA256_TEST_ONLY"

    tradeoff = payload["tradeoff"]
    assert len(tradeoff["comparison_scope_sha256"]) == 64
    assert tradeoff["benchmark_manifest_sha256"] == rev1["benchmark_manifest_sha256"]
    assert [point["policy_revision"] for point in tradeoff["points"]] == [1, 2, 3]
    assert [point["escapes"] for point in tradeoff["points"]] == [
        rev1["counts"]["escapes"], rev2["counts"]["escapes"], rev3["counts"]["escapes"]
    ]
    assert [point["overblocks"] for point in tradeoff["points"]] == [
        rev1["counts"]["overblocks"], rev2["counts"]["overblocks"], rev3["counts"]["overblocks"]
    ]
    for point in tradeoff["points"]:
        assert point["escape_rate"]["observed"] == point["escapes"] / 30
        assert point["escape_rate"]["denominator"] == 30
        assert len(point["escape_rate"]["wilson_95"]) == 2
        assert point["overblock_rate"]["observed"] == point["overblocks"] / 30
        assert point["overblock_rate"]["denominator"] == 30
        assert len(point["overblock_rate"]["wilson_95"]) == 2


def test_cli_coverage_demo_reports_paired_exact_mcnemar_for_frontier(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["release-sentinel", "coverage-demo"])
    assert main() == 0
    payload = json.loads(capsys.readouterr().out)
    mcnemar = payload["tradeoff"]["mcnemar"]

    assert mcnemar["method"] == "EXACT_TWO_SIDED_BINOMIAL_P_0_5"
    assert mcnemar["paired_by"] == "candidate_id"
    assert mcnemar["alpha"] == 0.05
    assert mcnemar["null_hypothesis"] == "DISCORDANT_DIRECTION_PROBABILITY_EQUALS_0_5"
    assert mcnemar["inference_scope"] == "FIXED_HASH_BOUND_BENCHMARK_ONLY"
    assert "fixed hash-bound benchmark corpus" in mcnemar["interpretation"]
    assert mcnemar["family_wise_correction"] == "HOLM_BONFERRONI"
    assert mcnemar["family_size"] == 6

    comparisons = {
        (item["metric"], item["policy_revision_from"], item["policy_revision_to"]): item
        for item in mcnemar["comparisons"]
    }
    expected = {
        ("escape", 1, 2): (20, 0, 1.9073486328125e-06, True),
        ("escape", 2, 3): (3, 0, 0.25, False),
        ("escape", 1, 3): (23, 0, 2.384185791015625e-07, True),
        ("overblock", 1, 2): (0, 4, 0.125, False),
        ("overblock", 2, 3): (0, 17, 1.52587890625e-05, True),
        ("overblock", 1, 3): (0, 21, 9.5367431640625e-07, True),
    }
    assert set(comparisons) == set(expected)
    for key, (only_from, only_to, p_value, significant) in expected.items():
        item = comparisons[key]
        assert item["total_pairs"] == 30
        assert item["only_from"] == only_from
        assert item["only_to"] == only_to
        assert item["discordant_pairs"] == only_from + only_to
        assert item["exact_p_value"] == pytest.approx(p_value)
        assert item["reject_null_at_alpha"] is significant
        assert "adjusted_alpha" in item
        assert "reject_null_after_correction" in item
        assert "holm_rank" in item
        assert len(item["policy_sha256_from"]) == 64
        assert len(item["policy_sha256_to"]) == 64


def test_cli_tradeoff_has_signed_self_contained_comparison_receipt(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["release-sentinel", "coverage-demo"])
    assert main() == 0
    payload = json.loads(capsys.readouterr().out)
    tradeoff = payload["tradeoff"]
    signed = tradeoff["signed_comparison_receipt"]
    receipt = signed["receipt"]
    assert receipt["claim"] == "SCOPED_PAIRED_POLICY_TRADEOFF"
    assert receipt["comparison_scope_sha256"] == tradeoff["comparison_scope_sha256"]
    assert receipt["benchmark_manifest_sha256"] == tradeoff["benchmark_manifest_sha256"]
    assert receipt["points"] == tradeoff["points"]
    assert receipt["mcnemar"] == tradeoff["mcnemar"]
    assert receipt["agent_authority"] == "NONE"
    assert signed["signature"]["algorithm"] == "HMAC_SHA256_TEST_ONLY"


def test_cli_coverage_demo_applies_holm_bonferroni_to_mcnemar_family(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["release-sentinel", "coverage-demo"])
    assert main() == 0
    payload = json.loads(capsys.readouterr().out)
    comparisons = {
        (item["metric"], item["policy_revision_from"], item["policy_revision_to"]): item
        for item in payload["tradeoff"]["mcnemar"]["comparisons"]
    }
    expected = {
        ("escape", 1, 3): (1, 0.05 / 6, True),
        ("overblock", 1, 3): (2, 0.05 / 5, True),
        ("escape", 1, 2): (3, 0.05 / 4, True),
        ("overblock", 2, 3): (4, 0.05 / 3, True),
        ("overblock", 1, 2): (5, 0.05 / 2, False),
        ("escape", 2, 3): (6, 0.05, False),
    }
    for key, (rank, adjusted_alpha, rejected) in expected.items():
        item = comparisons[key]
        assert item["holm_rank"] == rank
        assert item["adjusted_alpha"] == pytest.approx(adjusted_alpha)
        assert item["reject_null_after_correction"] is rejected
