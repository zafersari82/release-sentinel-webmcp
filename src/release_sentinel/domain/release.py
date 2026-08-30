from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping
from uuid import uuid4

from release_sentinel.domain.evidence import Decision, EvidenceIntegrityError, Finding, finding_set_sha256
from release_sentinel.domain.immutable import freeze_json, thaw_json


@dataclass(frozen=True)
class ReleaseRequest:
    release_id: str
    repository_path: Path
    commit_sha: str | None = None

    def __post_init__(self) -> None:
        root = Path(self.repository_path)
        if not root.exists() or not root.is_dir():
            raise ValueError("repository_path must be an existing directory")
        object.__setattr__(self, "repository_path", root.resolve())


@dataclass(frozen=True)
class ReleaseReport:
    release_id: str
    decision: Decision
    findings: tuple[Finding, ...]
    rationale: tuple[str, ...]
    policy_id: str
    policy_revision: int
    policy_sha256: str
    execution_count: int
    evidence_sha256: str = ""
    advisory: Mapping[str, Any] | None = None
    gatekeeper: Mapping[str, Any] | None = None
    report_id: str = field(default_factory=lambda: f"report-{uuid4().hex}")
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def __post_init__(self) -> None:
        findings = tuple(self.findings)
        rationale = tuple(self.rationale)
        actual = finding_set_sha256(findings)
        if self.evidence_sha256 and self.evidence_sha256 != actual:
            raise EvidenceIntegrityError("release report evidence does not match its seal")
        object.__setattr__(self, "findings", findings)
        object.__setattr__(self, "rationale", rationale)
        object.__setattr__(self, "evidence_sha256", actual)
        if self.advisory is not None:
            object.__setattr__(self, "advisory", freeze_json(self.advisory))
        if self.gatekeeper is not None:
            object.__setattr__(self, "gatekeeper", freeze_json(self.gatekeeper))

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_id": self.report_id,
            "release_id": self.release_id,
            "decision": self.decision.value,
            "rationale": list(self.rationale),
            "policy_id": self.policy_id,
            "policy_revision": self.policy_revision,
            "policy_sha256": self.policy_sha256,
            "execution_count": self.execution_count,
            "evidence_sha256": self.evidence_sha256,
            "findings": [item.to_dict() for item in self.findings],
            "advisory": thaw_json(self.advisory) if self.advisory is not None else None,
            "gatekeeper": thaw_json(self.gatekeeper) if self.gatekeeper is not None else None,
            "created_at": self.created_at,
        }
