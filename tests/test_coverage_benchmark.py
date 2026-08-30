from release_sentinel.coverage.benchmark import (
    BenchmarkKind,
    generate_cross_tenant_benchmark,
)
from release_sentinel.coverage.models import OracleVerdict
from release_sentinel.coverage.oracle import CrossTenantOracle


def load_can_read(source: str):
    namespace = {"__name__": "coverage_candidate"}
    exec(compile(source, "<coverage-candidate>", "exec"), namespace, namespace)
    return namespace["can_read"]


def test_cross_tenant_benchmark_is_byte_deterministic():
    first = generate_cross_tenant_benchmark()
    second = generate_cross_tenant_benchmark()
    assert first.manifest.sha256 == second.manifest.sha256
    assert [item.candidate_id for item in first.candidates] == [item.candidate_id for item in second.candidates]
    assert [item.source for item in first.candidates] == [item.source for item in second.candidates]


def test_benchmark_inventory_has_unique_stable_safe_and_unsafe_populations():
    suite = generate_cross_tenant_benchmark()
    ids = [item.candidate_id for item in suite.candidates]
    assert len(ids) == len(set(ids))
    safe = [item for item in suite.candidates if item.kind is BenchmarkKind.SAFE]
    unsafe = [item for item in suite.candidates if item.kind is BenchmarkKind.UNSAFE]
    assert len(safe) == 30
    assert len(unsafe) == 30
    assert suite.manifest.expected_candidate_count == len(suite.candidates)
    assert suite.manifest.operator_ids == tuple(item.operator_id for item in suite.candidates)


def test_safe_population_is_oracle_confirmed_safe_by_construction():
    oracle = CrossTenantOracle()
    suite = generate_cross_tenant_benchmark()
    safe = [item for item in suite.candidates if item.kind is BenchmarkKind.SAFE]
    for candidate in safe:
        result = oracle.evaluate_callable(load_can_read(candidate.source))
        assert result.verdict is OracleVerdict.SAFE, candidate.operator_id


def test_unsafe_population_contains_oracle_confirmed_unsafe_candidates():
    oracle = CrossTenantOracle()
    suite = generate_cross_tenant_benchmark()
    unsafe = [item for item in suite.candidates if item.kind is BenchmarkKind.UNSAFE]
    verdicts = {
        candidate.operator_id: oracle.evaluate_callable(load_can_read(candidate.source)).verdict
        for candidate in unsafe
    }
    assert set(verdicts.values()) == {OracleVerdict.UNSAFE}
    assert "casefold-equality" in verdicts
    assert "empty-default-allow" in verdicts
    assert "unicode-normalized-equality" in verdicts


def test_every_candidate_preserves_callable_public_interface_and_valid_python():
    suite = generate_cross_tenant_benchmark()
    for candidate in suite.candidates:
        can_read = load_can_read(candidate.source)
        assert callable(can_read)
        assert isinstance(can_read("tenant-a", "tenant-b"), bool)
        assert len(candidate.source_sha256) == 64


def test_fixed_benchmark_manifest_has_no_cosmetic_seed_parameter():
    suite = generate_cross_tenant_benchmark()
    payload = suite.manifest.to_dict()
    assert payload["schema"] == "release-sentinel.coverage-benchmark.v3"
    assert payload["generation_revision"] == "cross-tenant-benchmark-v3"
    assert "seed" not in payload
    assert payload["candidate_sha256"] == [item.source_sha256 for item in suite.candidates]
    assert len(suite.manifest.sha256) == 64


def test_benchmark_case_data_is_packaged_with_release_sentinel():
    import tomllib
    from pathlib import Path

    root = Path(__file__).parents[1]
    config = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    package_data = config["tool"]["setuptools"]["package-data"]
    assert "*.json" in package_data["release_sentinel.coverage"]
