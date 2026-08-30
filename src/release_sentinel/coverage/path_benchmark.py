from __future__ import annotations

import json
from pathlib import Path

from release_sentinel.coverage.benchmark_models import (
    BenchmarkCandidate,
    BenchmarkKind,
    BenchmarkManifest,
    BenchmarkSuite,
)
from release_sentinel.coverage.canonical import sha256_bytes


_BASE_FIXED = '''def can_open_path(base_dir, requested_path, resolved_target):
    import posixpath
    from urllib.parse import unquote
    if not all(isinstance(value, str) for value in (base_dir, requested_path, resolved_target)):
        return False
    if not base_dir.startswith("/") or not resolved_target.startswith("/") or not requested_path or "\\x00" in requested_path:
        return False
    decoded = requested_path
    for _ in range(3):
        next_value = unquote(decoded)
        if next_value == decoded:
            break
        decoded = next_value
    decoded = decoded.replace("\\\\", "/")
    if decoded.startswith("/"):
        return False
    base = posixpath.normpath(base_dir)
    lexical = posixpath.normpath(posixpath.join(base, decoded))
    resolved = posixpath.normpath(resolved_target)
    try:
        return posixpath.commonpath((base, lexical)) == base and posixpath.commonpath((base, resolved)) == base
    except ValueError:
        return False
'''


def _load_cases(name: str) -> tuple[tuple[str, str], ...]:
    raw = json.loads(Path(__file__).with_name(name).read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError(f"path benchmark case file must be a list: {name}")
    cases: list[tuple[str, str]] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ValueError(f"path benchmark case must be an object: {name}[{index}]")
        operator_id = item.get("operator_id")
        source = item.get("source")
        if not isinstance(operator_id, str) or not operator_id:
            raise ValueError(f"path benchmark operator invalid: {name}[{index}]")
        if not isinstance(source, str) or "def can_open_path" not in source:
            raise ValueError(f"path benchmark source invalid: {name}[{index}]")
        cases.append((operator_id, source))
    if len({operator_id for operator_id, _ in cases}) != len(cases):
        raise ValueError(f"path benchmark operator ids must be unique: {name}")
    return tuple(cases)


def _candidate(kind: BenchmarkKind, operator_id: str, source: str) -> BenchmarkCandidate:
    digest = sha256_bytes(source.encode("utf-8"))
    return BenchmarkCandidate(
        candidate_id=f"candidate-path-{kind.value.lower()}-{operator_id}-{digest[:12]}",
        kind=kind,
        operator_id=operator_id,
        operator_revision=1,
        source=source,
        source_sha256=digest,
    )


def generate_path_traversal_benchmark() -> BenchmarkSuite:
    safe = _load_cases("path_benchmark_safe_v1.json")
    unsafe = _load_cases("path_benchmark_unsafe_v1.json")
    candidates = tuple(
        [_candidate(BenchmarkKind.SAFE, operator_id, source) for operator_id, source in safe]
        + [_candidate(BenchmarkKind.UNSAFE, operator_id, source) for operator_id, source in unsafe]
    )
    manifest = BenchmarkManifest(
        challenge_id="path-traversal-containment",
        challenge_revision=1,
        generation_revision="path-traversal-benchmark-v1",
        base_fixture_sha256=sha256_bytes(_BASE_FIXED.encode("utf-8")),
        expected_candidate_count=len(candidates),
        operator_ids=tuple(item.operator_id for item in candidates),
        candidate_sha256=tuple(item.source_sha256 for item in candidates),
        inventory=tuple(item.to_manifest_dict() for item in candidates),
    )
    return BenchmarkSuite(manifest=manifest, candidates=candidates)
