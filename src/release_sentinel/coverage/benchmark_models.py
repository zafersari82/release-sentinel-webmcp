from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from release_sentinel.coverage.canonical import sha256_json


class BenchmarkKind(str, Enum):
    SAFE = "SAFE"
    UNSAFE = "UNSAFE"


@dataclass(frozen=True)
class BenchmarkCandidate:
    candidate_id: str
    kind: BenchmarkKind
    operator_id: str
    operator_revision: int
    source: str
    source_sha256: str

    def to_manifest_dict(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "kind": self.kind.value,
            "operator_id": self.operator_id,
            "operator_revision": self.operator_revision,
            "source_sha256": self.source_sha256,
        }


@dataclass(frozen=True)
class BenchmarkManifest:
    challenge_id: str
    challenge_revision: int
    generation_revision: str
    base_fixture_sha256: str
    expected_candidate_count: int
    operator_ids: tuple[str, ...]
    candidate_sha256: tuple[str, ...]
    inventory: tuple[dict[str, Any], ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "release-sentinel.coverage-benchmark.v3",
            "challenge_id": self.challenge_id,
            "challenge_revision": self.challenge_revision,
            "generation_revision": self.generation_revision,
            "base_fixture_sha256": self.base_fixture_sha256,
            "expected_candidate_count": self.expected_candidate_count,
            "operator_ids": list(self.operator_ids),
            "candidate_sha256": list(self.candidate_sha256),
            "inventory": list(self.inventory),
        }

    @property
    def sha256(self) -> str:
        return sha256_json(self.to_dict())


@dataclass(frozen=True)
class BenchmarkSuite:
    manifest: BenchmarkManifest
    candidates: tuple[BenchmarkCandidate, ...]

