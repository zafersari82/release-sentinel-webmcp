import json
import sys

from release_sentinel.coverage.models import OracleVerdict


def robust_path_guard(base_dir, requested_path, resolved_target):
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


def obvious_path_vulnerable(_base_dir, _requested_path, _resolved_target):
    return True


def load_path_callable(source: str):
    namespace = {"__name__": "coverage_path_candidate"}
    exec(compile(source, "<coverage-path-candidate>", "exec"), namespace, namespace)
    return namespace["can_open_path"]


def test_path_traversal_challenge_is_versioned_and_scope_honest():
    from release_sentinel.coverage.challenge import load_path_traversal_challenge

    challenge = load_path_traversal_challenge()
    assert challenge.challenge_id == "path-traversal-containment"
    assert challenge.revision == 1
    assert challenge.payload["interface"] == "can_open_path(base_dir, requested_path, resolved_target) -> bool"
    assert "path containment" in challenge.payload["scope"]["tested"]
    assert "authorization" in challenge.payload["scope"]["not_tested"]
    assert len(challenge.sha256) == 64


def test_path_traversal_oracle_qualifies_known_answers_and_mutants():
    from release_sentinel.coverage.path_oracle import PathTraversalOracle

    oracle = PathTraversalOracle()
    fixed = oracle.evaluate_callable(robust_path_guard)
    vulnerable = oracle.evaluate_callable(obvious_path_vulnerable)
    qualification = oracle.qualify(
        fixed_callable=robust_path_guard,
        vulnerable_callable=obvious_path_vulnerable,
    )
    assert fixed.verdict is OracleVerdict.SAFE
    assert vulnerable.verdict is OracleVerdict.UNSAFE
    assert qualification.passed is True
    assert qualification.mutation_survived == 0
    categories = {vector.category for vector in oracle.vectors}
    assert {"dotdot", "encoded", "backslash", "absolute", "symlink_escape", "prefix_collision"} <= categories


def test_path_traversal_benchmark_is_deterministic_balanced_and_oracle_confirmed():
    from release_sentinel.coverage.benchmark import BenchmarkKind, generate_path_traversal_benchmark
    from release_sentinel.coverage.path_oracle import PathTraversalOracle

    first = generate_path_traversal_benchmark()
    second = generate_path_traversal_benchmark()
    assert first.manifest.sha256 == second.manifest.sha256
    assert first.manifest.challenge_id == "path-traversal-containment"
    safe = [item for item in first.candidates if item.kind is BenchmarkKind.SAFE]
    unsafe = [item for item in first.candidates if item.kind is BenchmarkKind.UNSAFE]
    assert len(safe) == len(unsafe) == 30
    assert len({item.candidate_id for item in first.candidates}) == 60
    oracle = PathTraversalOracle()
    assert all(oracle.evaluate_callable(load_path_callable(item.source)).verdict is OracleVerdict.SAFE for item in safe)
    assert all(oracle.evaluate_callable(load_path_callable(item.source)).verdict is OracleVerdict.UNSAFE for item in unsafe)


def test_path_traversal_reference_frontier_uses_same_measurement_protocol():
    from release_sentinel.coverage.runner import run_reference_path_traversal_arena

    runs = [run_reference_path_traversal_arena(policy_revision=revision) for revision in (1, 2, 3)]
    assert all(run.oracle_qualification.passed for run in runs)
    assert len({run.benchmark.manifest.sha256 for run in runs}) == 1
    assert [run.counts.confirmed_safe for run in runs] == [30, 30, 30]
    assert [run.counts.confirmed_unsafe for run in runs] == [30, 30, 30]
    escapes = [run.counts.escapes for run in runs]
    overblocks = [run.counts.overblocks for run in runs]
    assert escapes[0] > escapes[1] > escapes[2]
    assert escapes[2] == 0
    assert overblocks[0] < overblocks[1] < overblocks[2]
    for run in runs:
        for measurement in run.measurements:
            assert measurement.signed_gate_snapshot.snapshot.sequence == 1
            assert measurement.signed_gate_snapshot.snapshot.oracle_result_present is False
            assert measurement.signed_oracle_result.result.sequence == 2
        assert run.signed_receipt.receipt.agent_authority == "NONE"


def test_cli_can_run_second_invariant_without_changing_cross_tenant_default(monkeypatch, capsys):
    from release_sentinel.interfaces.cli import main

    monkeypatch.setattr(sys, "argv", ["release-sentinel", "coverage-demo", "--challenge", "path-traversal"])
    assert main() == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["challenge_id"] == "path-traversal-containment"
    assert payload["claim"] == "SCOPED_GATE_GAP_MEASUREMENT"
    assert payload["oracle_qualified"] is True
    assert [run["policy_revision"] for run in payload["policy_comparison"]] == [1, 2, 3]
    assert payload["tradeoff"]["mcnemar"]["family_wise_correction"] == "HOLM_BONFERRONI"

    monkeypatch.setattr(sys, "argv", ["release-sentinel", "coverage-demo"])
    assert main() == 0
    default_payload = json.loads(capsys.readouterr().out)
    assert default_payload.get("challenge_id", "cross-tenant-authorization") == "cross-tenant-authorization"
