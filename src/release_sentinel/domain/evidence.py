from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence

from release_sentinel.domain.immutable import freeze_json, thaw_json


class EvidenceIntegrityError(RuntimeError):
    """Raised when a sealed authoritative evidence set no longer matches its seal."""


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Decision(str, Enum):
    GO = "GO"
    CONDITIONAL_GO = "CONDITIONAL_GO"
    NO_GO = "NO_GO"


class EvidenceAuthority(str, Enum):
    PLATFORM = "PLATFORM"
    ORGANIZATION_POLICY = "ORGANIZATION_POLICY"
    MODEL_ADVISORY = "MODEL_ADVISORY"


class EvidenceKind(str, Enum):
    STATIC_RULE = "STATIC_RULE"
    EXECUTION_RESULT = "EXECUTION_RESULT"
    INTEGRITY_CHECK = "INTEGRITY_CHECK"
    MODEL_NOTE = "MODEL_NOTE"


@dataclass(frozen=True)
class Evidence:
    evidence_id: str
    kind: EvidenceKind
    authority: EvidenceAuthority
    source: str
    summary: str
    reproducible: bool
    blocking_eligible: bool
    details: Mapping[str, Any] = field(default_factory=dict)
    policy_id: str | None = None
    policy_revision: int | None = None
    policy_sha256: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "details", freeze_json(self.details))

    def authoritative(self) -> bool:
        return self.authority in {
            EvidenceAuthority.PLATFORM,
            EvidenceAuthority.ORGANIZATION_POLICY,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "kind": self.kind.value,
            "authority": self.authority.value,
            "source": self.source,
            "summary": self.summary,
            "reproducible": self.reproducible,
            "blocking_eligible": self.blocking_eligible,
            "details": thaw_json(self.details),
            "policy_id": self.policy_id,
            "policy_revision": self.policy_revision,
            "policy_sha256": self.policy_sha256,
        }


@dataclass(frozen=True)
class Finding:
    """Deeply immutable authoritative evidence record."""

    finding_id: str
    title: str
    severity: Severity
    source: str
    claim: str
    evidence: tuple[Evidence, ...] = ()
    advisory_notes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "evidence", tuple(self.evidence))
        object.__setattr__(self, "advisory_notes", tuple(self.advisory_notes))

    def blocking_evidence(self) -> tuple[Evidence, ...]:
        return tuple(
            item
            for item in self.evidence
            if item.authoritative() and item.blocking_eligible
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "severity": self.severity.value,
            "source": self.source,
            "claim": self.claim,
            "evidence": [item.to_dict() for item in self.evidence],
            "advisory_notes": list(self.advisory_notes),
        }


def finding_set_sha256(findings: Sequence[Finding]) -> str:
    """Order-independent SHA-256 over the complete serialized evidence set."""
    payload = sorted(
        json.dumps(item.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        for item in findings
    )
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()
