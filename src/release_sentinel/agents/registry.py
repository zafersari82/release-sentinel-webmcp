from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Iterable

from release_sentinel import __version__


class DecisionAuthority(str, Enum):
    ADVISORY = "ADVISORY"
    DETERMINISTIC = "DETERMINISTIC"


_ALLOWED_STATUS = {"ACTIVE", "DEGRADED", "DISABLED"}


@dataclass(frozen=True)
class AgentRecord:
    agent_id: str
    version: str
    runtime: str
    skill_tags: tuple[str, ...]
    decision_authority: DecisionAuthority
    transport: str
    status: str
    registered_at: str

    @classmethod
    def from_mapping(cls, raw: dict[str, Any]) -> "AgentRecord":
        authority_raw = raw.get("decision_authority")
        try:
            authority = DecisionAuthority(authority_raw)
        except Exception as exc:
            raise ValueError("unknown decision_authority") from exc
        status = str(raw.get("status") or "")
        if status not in _ALLOWED_STATUS:
            raise ValueError("unknown agent status")
        agent_id = str(raw.get("agent_id") or "").strip()
        if not agent_id or len(agent_id) > 64:
            raise ValueError("invalid agent_id")
        tags = tuple(str(tag)[:48] for tag in (raw.get("skill_tags") or ()))
        return cls(
            agent_id=agent_id,
            version=str(raw.get("version") or "")[:32],
            runtime=str(raw.get("runtime") or "")[:64],
            skill_tags=tags,
            decision_authority=authority,
            transport=str(raw.get("transport") or "")[:64],
            status=status,
            registered_at=str(raw.get("registered_at") or "")[:64],
        )

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["skill_tags"] = list(self.skill_tags)
        payload["decision_authority"] = self.decision_authority.value
        return payload


class AgentRegistry:
    """Trusted runtime registry.

    Deterministic authority can only come from trusted bootstrap records. Runtime
    self-registration is advisory-only by construction.
    """

    def __init__(self, records: Iterable[AgentRecord]) -> None:
        self._records: dict[str, AgentRecord] = {}
        for record in records:
            if record.agent_id in self._records:
                raise ValueError("duplicate agent_id")
            self._records[record.agent_id] = record

    def list(self) -> list[AgentRecord]:
        return [self._records[key] for key in sorted(self._records)]

    def get(self, agent_id: str) -> AgentRecord:
        return self._records[agent_id]

    def advisory_agents(self) -> list[AgentRecord]:
        return [
            record
            for record in self.list()
            if record.status == "ACTIVE" and record.decision_authority is DecisionAuthority.ADVISORY
        ]

    def deterministic_agents(self) -> list[AgentRecord]:
        return [
            record
            for record in self.list()
            if record.status == "ACTIVE" and record.decision_authority is DecisionAuthority.DETERMINISTIC
        ]

    def register_advisory(self, raw: dict[str, Any]) -> AgentRecord:
        record = AgentRecord.from_mapping(raw)
        if record.decision_authority is not DecisionAuthority.ADVISORY:
            raise PermissionError("runtime self-registration cannot acquire deterministic authority")
        if record.agent_id in self._records:
            raise ValueError("agent_id already registered")
        self._records[record.agent_id] = record
        return record

    def snapshot(self) -> list[dict[str, Any]]:
        return [record.to_dict() for record in self.list()]


_REGISTERED_AT = "2026-08-19T00:00:00Z"
_TRUSTED_RECORDS = (
    AgentRecord("security_reviewer", __version__, "python-adk", ("security", "challenge"), DecisionAuthority.ADVISORY, "ADK", "ACTIVE", _REGISTERED_AT),
    AgentRecord("test_reviewer", __version__, "python-adk", ("testing", "evidence"), DecisionAuthority.ADVISORY, "ADK", "ACTIVE", _REGISTERED_AT),
    AgentRecord("dissent_reviewer", __version__, "python-adk", ("dissent", "history"), DecisionAuthority.ADVISORY, "ADK", "ACTIVE", _REGISTERED_AT),
    AgentRecord("evidence_explainer", __version__, "python-adk", ("evidence", "explanation"), DecisionAuthority.ADVISORY, "ADK", "ACTIVE", _REGISTERED_AT),
    AgentRecord("go-gatekeeper", __version__, "go", ("policy", "signed-evidence", "verdict"), DecisionAuthority.DETERMINISTIC, "A2A_JSONRPC", "ACTIVE", _REGISTERED_AT),
)

_DEFAULT_REGISTRY = AgentRegistry(_TRUSTED_RECORDS)


def default_agent_registry() -> AgentRegistry:
    return _DEFAULT_REGISTRY
