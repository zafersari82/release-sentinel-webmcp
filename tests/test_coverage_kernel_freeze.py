from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).parents[1]

REQUIRED = {
    "src/release_sentinel/coverage/canonical.py",
    "src/release_sentinel/coverage/models.py",
    "src/release_sentinel/coverage/benchmark_models.py",
    "src/release_sentinel/coverage/challenge.py",
    "src/release_sentinel/coverage/challenges/cross_tenant_v1.json",
    "src/release_sentinel/coverage/challenges/path_traversal_v1.json",
    "src/release_sentinel/coverage/oracle.py",
    "src/release_sentinel/coverage/path_oracle.py",
    "src/release_sentinel/coverage/benchmark.py",
    "src/release_sentinel/coverage/path_benchmark.py",
    "src/release_sentinel/coverage/benchmark_safe_v3.json",
    "src/release_sentinel/coverage/benchmark_unsafe_v3.json",
    "src/release_sentinel/coverage/path_benchmark_safe_v1.json",
    "src/release_sentinel/coverage/path_benchmark_unsafe_v1.json",
    "src/release_sentinel/coverage/reference_policy.py",
    "src/release_sentinel/coverage/path_reference_policy.py",
    "src/release_sentinel/coverage/comparison.py",
    "src/release_sentinel/coverage/assessment.py",
    "src/release_sentinel/coverage/signing.py",
    "src/release_sentinel/coverage/protocol.py",
    "src/release_sentinel/coverage/receipt.py",
    "src/release_sentinel/coverage/minimizer.py",
    "src/release_sentinel/coverage/corpus.py",
    "src/release_sentinel/coverage/hunt.py",
    "src/release_sentinel/coverage/runner.py",
    "tests/test_coverage_oracle.py",
    "tests/test_coverage_benchmark.py",
    "tests/test_coverage_assessment.py",
    "tests/test_coverage_protocol.py",
    "tests/test_coverage_receipt.py",
    "tests/test_coverage_path_traversal.py",
}


def lines(path: Path) -> list[str]:
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip() and not line.lstrip().startswith("#")]


def test_coverage_measurement_kernel_is_explicit_and_hash_frozen():
    scope = ROOT / "trust" / "COVERAGE_KERNEL.files"
    manifest = ROOT / "trust" / "COVERAGE_KERNEL.sha256"
    assert scope.is_file() and manifest.is_file()
    declared = lines(scope)
    rows = lines(manifest)
    manifested = [row.split("  ", 1)[1] for row in rows]
    assert len(declared) == len(set(declared))
    assert declared == manifested
    assert REQUIRED <= set(declared)
    for row in rows:
        expected, rel = row.split("  ", 1)
        target = ROOT / rel
        assert target.is_file(), rel
        assert hashlib.sha256(target.read_bytes()).hexdigest() == expected, rel
