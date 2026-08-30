from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any

from release_sentinel.coverage.canonical import sha256_json


class OracleVerdict(str, Enum):
    SAFE = "SAFE"
    UNSAFE = "UNSAFE"


class CandidateValidity(str, Enum):
    VALID = "VALID"
    INVALID = "INVALID"


class CoverageClassification(str, Enum):
    CORRECT_ACCEPT = "CORRECT_ACCEPT"
    ESCAPE = "ESCAPE"
    OVERBLOCK = "OVERBLOCK"
    CORRECT_BLOCK = "CORRECT_BLOCK"
    INVALID_CANDIDATE = "INVALID_CANDIDATE"


@dataclass(frozen=True)
class MeasurementContext:
    challenge_sha256: str
    fixture_sha256: str
    candidate_sha256: str
    policy_sha256: str
    benchmark_manifest_sha256: str
    oracle_digest: str
    gatekeeper_digest: str
    runner_digest: str
    run_nonce: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def context_sha256(self) -> str:
        return sha256_json(self.to_dict())

    @property
    def measurement_id(self) -> str:
        return "cov-" + self.context_sha256
