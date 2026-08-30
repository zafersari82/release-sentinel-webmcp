from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from release_sentinel.coverage.canonical import sha256_json
from release_sentinel.coverage.models import CoverageClassification


_FORBIDDEN_MODEL_FIELDS = {
    "oracle_verdict",
    "classification",
    "gate_decision",
    "receipt",
    "authority",
    "signature",
}


class AdversarialProposer(Protocol):
    def propose(self, context: dict[str, Any]) -> dict[str, Any]: ...


@dataclass(frozen=True)
class HuntProposal:
    source: str
    rationale: str
    proposer_id: str
    authority: str = "NONE"

    @classmethod
    def from_model_payload(cls, payload: dict[str, Any], *, proposer_id: str) -> "HuntProposal":
        forbidden = _FORBIDDEN_MODEL_FIELDS & set(payload)
        if forbidden:
            raise ValueError(f"model payload contains authoritative fields: {sorted(forbidden)}")
        if set(payload) - {"source", "rationale"}:
            raise ValueError("model payload contains unsupported non-candidate fields")
        source = payload.get("source")
        rationale = payload.get("rationale")
        if not isinstance(source, str) or not source.strip():
            raise ValueError("hunt proposal source is required")
        if not isinstance(rationale, str):
            raise ValueError("hunt proposal rationale must be a string")
        if not proposer_id:
            raise ValueError("proposer_id is required")
        return cls(source=source, rationale=rationale, proposer_id=proposer_id)

    @property
    def proposal_sha256(self) -> str:
        return sha256_json(
            {
                "source": self.source,
                "rationale": self.rationale,
                "proposer_id": self.proposer_id,
                "authority": self.authority,
            }
        )


@dataclass(frozen=True)
class HuntAttempt:
    proposal_sha256: str
    classification: CoverageClassification


@dataclass(frozen=True)
class HuntSummary:
    attempts: int
    new_escapes: int
    invalid: int

    def to_dict(self) -> dict[str, int | str]:
        return {
            "attempts": self.attempts,
            "new_escapes": self.new_escapes,
            "invalid": self.invalid,
            "lane": "ADAPTIVE_NON_STATISTICAL",
            "agent_authority": "NONE",
        }


def record_hunt_attempt(proposal: HuntProposal, classification: CoverageClassification) -> HuntAttempt:
    return HuntAttempt(proposal_sha256=proposal.proposal_sha256, classification=classification)


def summarize_hunt(attempts: list[HuntAttempt] | tuple[HuntAttempt, ...]) -> HuntSummary:
    items = tuple(attempts)
    return HuntSummary(
        attempts=len(items),
        new_escapes=sum(1 for item in items if item.classification is CoverageClassification.ESCAPE),
        invalid=sum(1 for item in items if item.classification is CoverageClassification.INVALID_CANDIDATE),
    )
