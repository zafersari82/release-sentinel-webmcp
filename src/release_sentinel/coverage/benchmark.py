from __future__ import annotations

import json
from pathlib import Path

from release_sentinel.coverage.canonical import sha256_bytes
from release_sentinel.coverage.benchmark_models import BenchmarkCandidate, BenchmarkKind, BenchmarkManifest, BenchmarkSuite

_BASE_FIXED = '''def can_read(requester_tenant, resource_tenant):
    if not isinstance(requester_tenant, str) or not isinstance(resource_tenant, str):
        return False
    if not requester_tenant or not resource_tenant:
        return False
    return requester_tenant == resource_tenant
'''


def _load_case_file(name: str) -> tuple[tuple[str, str], ...]:
    path = Path(__file__).with_name(name)
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError(f"benchmark case file must be a list: {name}")
    result: list[tuple[str, str]] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ValueError(f"benchmark case must be an object: {name}[{index}]")
        operator_id = item.get("operator_id")
        source = item.get("source")
        if not isinstance(operator_id, str) or not operator_id:
            raise ValueError(f"benchmark operator_id invalid: {name}[{index}]")
        if not isinstance(source, str) or "def can_read" not in source:
            raise ValueError(f"benchmark source invalid: {name}[{index}]")
        result.append((operator_id, source))
    if len({operator_id for operator_id, _ in result}) != len(result):
        raise ValueError(f"benchmark operator ids must be unique: {name}")
    return tuple(result)


SAFE_TRANSFORMS = _load_case_file("benchmark_safe_v3.json")
UNSAFE_MUTATORS = _load_case_file("benchmark_unsafe_v3.json")


def _candidate(kind: BenchmarkKind, operator_id: str, source: str) -> BenchmarkCandidate:
    encoded = source.encode("utf-8")
    digest = sha256_bytes(encoded)
    return BenchmarkCandidate(
        candidate_id=f"candidate-{kind.value.lower()}-{operator_id}-{digest[:12]}",
        kind=kind,
        operator_id=operator_id,
        operator_revision=1,
        source=source,
        source_sha256=digest,
    )


def generate_cross_tenant_benchmark() -> BenchmarkSuite:
    candidates = tuple(
        [_candidate(BenchmarkKind.SAFE, operator_id, source) for operator_id, source in SAFE_TRANSFORMS]
        + [_candidate(BenchmarkKind.UNSAFE, operator_id, source) for operator_id, source in UNSAFE_MUTATORS]
    )
    manifest = BenchmarkManifest(
        challenge_id="cross-tenant-authorization",
        challenge_revision=1,
        generation_revision="cross-tenant-benchmark-v3",
        base_fixture_sha256=sha256_bytes(_BASE_FIXED.encode("utf-8")),
        expected_candidate_count=len(candidates),
        operator_ids=tuple(item.operator_id for item in candidates),
        candidate_sha256=tuple(item.source_sha256 for item in candidates),
        inventory=tuple(item.to_manifest_dict() for item in candidates),
    )
    return BenchmarkSuite(manifest=manifest, candidates=candidates)


def generate_path_traversal_benchmark() -> BenchmarkSuite:
    # Lazy import keeps the shared benchmark model acyclic while preserving the
    # public convenience API for built-in challenges.
    from release_sentinel.coverage.path_benchmark import generate_path_traversal_benchmark as generate

    return generate()
