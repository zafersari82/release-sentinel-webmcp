from __future__ import annotations

from typing import Any, Callable

from release_sentinel.coverage.assessment import holm_bonferroni, paired_mcnemar_exact
from release_sentinel.coverage.canonical import sha256_json
from release_sentinel.coverage.models import CoverageClassification, OracleVerdict
from release_sentinel.coverage.receipt import build_coverage_comparison_receipt, sign_coverage_comparison_receipt
from release_sentinel.coverage.runner import ReferenceArenaRun, run_reference_cross_tenant_arena, run_reference_path_traversal_arena
from release_sentinel.coverage.signing import HmacSha256Authority


def _runner_for(challenge: str) -> tuple[str, Callable[..., ReferenceArenaRun]]:
    if challenge == "cross-tenant":
        return "cross-tenant-authorization", run_reference_cross_tenant_arena
    if challenge == "path-traversal":
        return "path-traversal-containment", run_reference_path_traversal_arena
    raise ValueError(f"unsupported coverage challenge: {challenge}")


def build_reference_demo_payload(challenge: str = "cross-tenant") -> dict[str, Any]:
    challenge_id, arena_runner = _runner_for(challenge)
    runs: list[dict[str, Any]] = []
    arena_runs: list[ReferenceArenaRun] = []
    qualified = True
    for policy_revision in (1, 2, 3):
        run = arena_runner(policy_revision=policy_revision)
        qualified = qualified and run.oracle_qualification.passed
        arena_runs.append(run)
        scope = run.signed_receipt.receipt.scope.to_dict()
        runs.append(
            {
                "policy_revision": policy_revision,
                "policy_sha256": scope["policy_sha256"],
                "benchmark_manifest_sha256": run.benchmark.manifest.sha256,
                "counts": run.counts.to_dict(),
                "signed_receipt": run.signed_receipt.to_dict(),
            }
        )

    common_scope_keys = (
        "challenge_sha256",
        "fixture_sha256",
        "benchmark_manifest_sha256",
        "oracle_digest",
        "runner_digest",
        "oracle_qualification_manifest_sha256",
        "oracle_selftest_sha256",
        "tested",
        "not_tested",
    )
    reference_scope = runs[0]["signed_receipt"]["receipt"]["scope"]
    comparison_scope = {key: reference_scope[key] for key in common_scope_keys}
    for run in runs[1:]:
        candidate_scope = run["signed_receipt"]["receipt"]["scope"]
        if any(candidate_scope[key] != comparison_scope[key] for key in common_scope_keys):
            raise RuntimeError("reference policy comparison scope mismatch")

    points = []
    for run in runs:
        counts = run["counts"]
        points.append(
            {
                "policy_revision": run["policy_revision"],
                "policy_sha256": run["policy_sha256"],
                "escapes": counts["escapes"],
                "overblocks": counts["overblocks"],
                "escape_rate": counts["escape_rate"],
                "overblock_rate": counts["overblock_rate"],
            }
        )

    comparisons = []
    pair_specs = ((0, 1), (1, 2), (0, 2))
    metric_specs = (
        ("escape", OracleVerdict.UNSAFE, CoverageClassification.ESCAPE),
        ("overblock", OracleVerdict.SAFE, CoverageClassification.OVERBLOCK),
    )
    for metric, oracle_verdict, event_classification in metric_specs:
        event_maps = [
            {
                measurement.candidate_id: measurement.classification is event_classification
                for measurement in arena_run.measurements
                if measurement.oracle_verdict is oracle_verdict
            }
            for arena_run in arena_runs
        ]
        for first_index, second_index in pair_specs:
            result = paired_mcnemar_exact(event_maps[first_index], event_maps[second_index])
            p_value = result["exact_p_value"]
            comparisons.append(
                {
                    "metric": metric,
                    "policy_revision_from": runs[first_index]["policy_revision"],
                    "policy_revision_to": runs[second_index]["policy_revision"],
                    "policy_sha256_from": runs[first_index]["policy_sha256"],
                    "policy_sha256_to": runs[second_index]["policy_sha256"],
                    "total_pairs": result["total_pairs"],
                    "only_from": result["only_first"],
                    "only_to": result["only_second"],
                    "discordant_pairs": result["discordant_pairs"],
                    "exact_p_value": p_value,
                    "reject_null_at_alpha": p_value < 0.05,
                }
            )

    holm_results = holm_bonferroni((item["exact_p_value"] for item in comparisons), alpha=0.05)
    for comparison, correction in zip(comparisons, holm_results, strict=True):
        comparison.update(correction)

    comparison_scope_sha256 = sha256_json(comparison_scope)
    mcnemar_payload = {
        "method": "EXACT_TWO_SIDED_BINOMIAL_P_0_5",
        "paired_by": "candidate_id",
        "alpha": 0.05,
        "family_wise_correction": "HOLM_BONFERRONI",
        "family_size": len(comparisons),
        "null_hypothesis": "DISCORDANT_DIRECTION_PROBABILITY_EQUALS_0_5",
        "inference_scope": "FIXED_HASH_BOUND_BENCHMARK_ONLY",
        "interpretation": (
            "Exact paired comparisons over this fixed hash-bound benchmark corpus; "
            "p-values are scoped diagnostics, not population-wide security significance."
        ),
        "comparisons": comparisons,
    }
    comparison_receipt = build_coverage_comparison_receipt(
        comparison_scope_sha256=comparison_scope_sha256,
        benchmark_manifest_sha256=runs[0]["benchmark_manifest_sha256"],
        points=tuple(points),
        mcnemar=mcnemar_payload,
    )
    signed_comparison_receipt = sign_coverage_comparison_receipt(
        comparison_receipt,
        HmacSha256Authority(b"release-sentinel-reference-comparison-v1", "reference-comparison-test-key"),
    )
    return {
        "mode": "REFERENCE_OFFLINE",
        "challenge_id": challenge_id,
        "interpretation": (
            "This measures intentionally simplified demo policies; Coverage Arena is the measurement instrument, "
            "not a claim that any demo policy is production-complete."
        ),
        "claim": "SCOPED_GATE_GAP_MEASUREMENT",
        "oracle_qualified": qualified,
        "agent_authority": "NONE",
        "production_release_authority": "UNCHANGED",
        "policy_comparison": runs,
        "tradeoff": {
            "comparison_scope_sha256": comparison_scope_sha256,
            "benchmark_manifest_sha256": runs[0]["benchmark_manifest_sha256"],
            "points": points,
            "mcnemar": mcnemar_payload,
            "signed_comparison_receipt": signed_comparison_receipt.to_dict(),
        },
    }
