from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from typing import Any


class ParityCategory(str, Enum):
    PUBLIC_API = "PUBLIC_API"
    AUTHORIZATION = "AUTHORIZATION"
    DATABASE_BEHAVIOR = "DATABASE_BEHAVIOR"
    ERROR_CONTRACTS = "ERROR_CONTRACTS"
    EDGE_CASES = "EDGE_CASES"


@dataclass(frozen=True)
class ParityScenario:
    scenario_id: str
    category: ParityCategory
    blocking: bool = True
    method: str = "GET"
    path: str = "/"


@dataclass(frozen=True)
class Observation:
    status: int
    normalized_sha256: str

    @classmethod
    def from_payload(cls, status: int, payload: Any) -> "Observation":
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        return cls(status, hashlib.sha256(raw).hexdigest())


@dataclass(frozen=True)
class ParityCaseResult:
    scenario_id: str
    category: ParityCategory
    blocking: bool
    matched: bool
    legacy_sha256: str
    candidate_sha256: str
    mismatch_fields: tuple[str, ...]


@dataclass(frozen=True)
class ParityMatrix:
    cases: tuple[ParityCaseResult, ...]

    @property
    def blockers(self) -> tuple[ParityCaseResult, ...]:
        return tuple(c for c in self.cases if c.blocking and not c.matched)

    @property
    def score(self) -> float:
        if not self.cases:
            return 0.0
        return sum(1 for c in self.cases if c.matched) / len(self.cases)

    @property
    def cutover_allowed(self) -> bool:
        return bool(self.cases) and not self.blockers
