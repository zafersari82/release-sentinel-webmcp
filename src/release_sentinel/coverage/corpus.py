from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

from release_sentinel.coverage.canonical import canonical_json_bytes, sha256_json
from release_sentinel.coverage.models import CoverageClassification


def escape_id_for(
    *,
    candidate_sha256: str,
    policy_sha256: str,
    challenge_sha256: str,
    fixture_sha256: str,
    oracle_result_sha256: str,
) -> str:
    return sha256_json(
        {
            "candidate_sha256": candidate_sha256,
            "policy_sha256": policy_sha256,
            "challenge_sha256": challenge_sha256,
            "fixture_sha256": fixture_sha256,
            "oracle_result_sha256": oracle_result_sha256,
        }
    )


@dataclass(frozen=True)
class EscapeRecord:
    escape_id: str
    candidate_sha256: str
    policy_sha256: str
    challenge_sha256: str
    fixture_sha256: str
    oracle_result_sha256: str
    counterexample_sha256: str
    first_seen_receipt_sha256: str

    def to_dict(self) -> dict[str, str]:
        return {
            "escape_id": self.escape_id,
            "candidate_sha256": self.candidate_sha256,
            "policy_sha256": self.policy_sha256,
            "challenge_sha256": self.challenge_sha256,
            "fixture_sha256": self.fixture_sha256,
            "oracle_result_sha256": self.oracle_result_sha256,
            "counterexample_sha256": self.counterexample_sha256,
            "first_seen_receipt_sha256": self.first_seen_receipt_sha256,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, str]) -> "EscapeRecord":
        return cls(**payload)


class EscapeCorpus:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def _load(self) -> dict[str, EscapeRecord]:
        if not self.path.exists():
            return {}
        payload = json.loads(self.path.read_text(encoding="utf-8"))
        if payload.get("schema") != "release-sentinel.escape-corpus.v1":
            raise ValueError("unsupported escape corpus schema")
        records: dict[str, EscapeRecord] = {}
        for raw in payload.get("records") or []:
            item = EscapeRecord.from_dict(dict(raw))
            if item.escape_id in records:
                raise ValueError("duplicate escape id in corpus")
            records[item.escape_id] = item
        return records

    def _write(self, records: dict[str, EscapeRecord]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema": "release-sentinel.escape-corpus.v1",
            "records": [records[key].to_dict() for key in sorted(records)],
        }
        raw = canonical_json_bytes(payload) + b"\n"
        fd, tmp_name = tempfile.mkstemp(prefix=self.path.name + ".", suffix=".tmp", dir=self.path.parent)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, self.path)
        finally:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)

    def records(self) -> tuple[EscapeRecord, ...]:
        records = self._load()
        return tuple(records[key] for key in sorted(records))

    def add(self, record: EscapeRecord) -> bool:
        records = self._load()
        existing = records.get(record.escape_id)
        if existing is not None:
            if existing == record:
                return False
            raise ValueError("conflicting immutable escape record for existing escape_id")
        records[record.escape_id] = record
        self._write(records)
        return True


@dataclass(frozen=True)
class ReplaySummary:
    tested: int
    blocked: int
    regressions: int
    other: int

    def to_dict(self) -> dict[str, int | str]:
        return {
            "tested": self.tested,
            "blocked": self.blocked,
            "regressions": self.regressions,
            "other": self.other,
            "status": "COVERAGE_REGRESSION" if self.regressions else "CLEAN",
        }


def replay_corpus(
    records: Iterable[EscapeRecord],
    evaluator: Callable[[EscapeRecord], CoverageClassification],
) -> ReplaySummary:
    tested = blocked = regressions = other = 0
    for record in records:
        tested += 1
        classification = evaluator(record)
        if classification is CoverageClassification.CORRECT_BLOCK:
            blocked += 1
        elif classification is CoverageClassification.ESCAPE:
            regressions += 1
        else:
            other += 1
    return ReplaySummary(tested=tested, blocked=blocked, regressions=regressions, other=other)
