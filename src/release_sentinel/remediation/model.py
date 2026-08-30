from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping

from release_sentinel.domain.immutable import freeze_json, thaw_json
from release_sentinel.domain.release import ReleaseReport


PROPOSAL_AUTHORITY = "PROPOSAL_ONLY"


def _canonical(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(
        thaw_json(payload), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


@dataclass(frozen=True)
class RepairContext:
    """Read-only information an untrusted remediation model may use.

    The context deliberately excludes evidence bodies, signing material, policy
    internals, and any decision capability. A model gets enough information to
    propose a code change, not enough authority to approve one.
    """

    release_id: str
    base_source_sha256: str
    findings: tuple[Mapping[str, Any], ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "findings", tuple(freeze_json(item) for item in self.findings))


@dataclass(frozen=True)
class RepairProposal:
    """A sealed patch proposal produced by an untrusted agent.

    `files` is a path -> complete UTF-8 content mapping. The trusted coordinator
    validates every path against an explicit allowlist before materializing it.
    There is intentionally no verdict/approval field in this object.
    """

    release_id: str
    base_source_sha256: str
    producer_agent_id: str
    files: Mapping[str, str]
    authority: str = PROPOSAL_AUTHORITY
    proposal_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        normalized = {str(k): str(v) for k, v in dict(self.files).items()}
        if not normalized:
            raise ValueError("repair proposal must change at least one file")
        if len(self.base_source_sha256) != 64:
            raise ValueError("base_source_sha256 must be a SHA-256 hex digest")
        if self.authority != PROPOSAL_AUTHORITY:
            raise ValueError("repair proposals cannot acquire decision authority")
        object.__setattr__(self, "files", MappingProxyType(dict(sorted(normalized.items()))))
        payload = {
            "release_id": self.release_id,
            "base_source_sha256": self.base_source_sha256,
            "producer_agent_id": self.producer_agent_id,
            "authority": self.authority,
            "files": dict(self.files),
        }
        object.__setattr__(self, "proposal_sha256", hashlib.sha256(_canonical(payload)).hexdigest())

    def to_dict(self) -> dict[str, Any]:
        return {
            "release_id": self.release_id,
            "base_source_sha256": self.base_source_sha256,
            "producer_agent_id": self.producer_agent_id,
            "authority": self.authority,
            "files": dict(self.files),
            "proposal_sha256": self.proposal_sha256,
        }


@dataclass(frozen=True)
class RemediationOutcome:
    """Result of one autonomous repair attempt.

    A successful repair still contains two independent release reports: one for
    the original source and a fresh one for the newly hashed source. Evidence is
    never copied from the first run into the second.
    """

    release_id: str
    original_source_sha256: str
    repaired_source_sha256: str | None
    before: ReleaseReport
    after: ReleaseReport | None
    proposal: RepairProposal | None
    reevaluated_from_scratch: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "release_id": self.release_id,
            "original_source_sha256": self.original_source_sha256,
            "repaired_source_sha256": self.repaired_source_sha256,
            "before": self.before.to_dict(),
            "after": self.after.to_dict() if self.after is not None else None,
            "proposal": self.proposal.to_dict() if self.proposal is not None else None,
            "reevaluated_from_scratch": self.reevaluated_from_scratch,
        }
