from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

ATTACK_SCHEMA = "release-sentinel.public-attack.v1"
SNAPSHOT_SCHEMA = "release-sentinel.public-attack-snapshot.v1"
RECEIPT_SCHEMA = "release-sentinel.public-attack-receipt.v1"
MAX_ATTACK_BYTES = 64 * 1024
MAX_DEPTH = 16
MAX_CONTAINER_ITEMS = 2048
MAX_STRING = 8192


class AttackProtocolError(ValueError):
    """The untrusted attack output exceeded the public arena protocol."""


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise AttackProtocolError(f"attack output is not canonical JSON: {exc}") from exc


def _walk(value: Any, *, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        raise AttackProtocolError("attack output exceeds maximum nesting depth")
    if value is None or isinstance(value, (bool, int)):
        return
    if isinstance(value, float):
        # Floats are accepted only if JSON can represent them canonically.
        _canonical(value)
        return
    if isinstance(value, str):
        if len(value) > MAX_STRING:
            raise AttackProtocolError("attack output contains an oversized string")
        return
    if isinstance(value, Mapping):
        if len(value) > MAX_CONTAINER_ITEMS:
            raise AttackProtocolError("attack output mapping is too large")
        for key, item in value.items():
            if not isinstance(key, str):
                raise AttackProtocolError("attack output mapping keys must be strings")
            if len(key) > 256:
                raise AttackProtocolError("attack output contains an oversized key")
            _walk(item, depth=depth + 1)
        return
    if isinstance(value, (list, tuple)):
        if len(value) > MAX_CONTAINER_ITEMS:
            raise AttackProtocolError("attack output sequence is too large")
        for item in value:
            _walk(item, depth=depth + 1)
        return
    raise AttackProtocolError(f"unsupported attack output type: {type(value).__name__}")


def validate_advisory_payload(payload: Any) -> dict[str, Any]:
    """Validate + detach hostile output before it enters the application plane.

    The public arena accepts arbitrary JSON semantics but deliberately exposes
    no object references from the attack runtime to the release process.
    """
    if not isinstance(payload, Mapping):
        raise AttackProtocolError("attack output must be a JSON object")
    _walk(payload)
    raw = _canonical(payload)
    if len(raw) > MAX_ATTACK_BYTES:
        raise AttackProtocolError("attack output exceeds 64 KiB")
    # Round-trip creates a detached plain-data copy and rejects non-JSON types.
    return json.loads(raw.decode("utf-8"))


def sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def build_snapshot(
    *,
    release_id: str,
    source_sha256: str,
    findings: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Public, redacted input given to an external attack program.

    No raw evidence bodies, signing material, credentials, policy document, or
    live Python objects are present. The snapshot is intentionally safe to
    publish and safe to hand to an untrusted process.
    """
    return {
        "schema": SNAPSHOT_SCHEMA,
        "release_id": release_id,
        "source_sha256": source_sha256,
        "findings": [dict(item) for item in findings],
        "goal": (
            "Change authoritative evidence or final release decision without "
            "changing source/policy ground truth. Advisory compromise alone is expected."
        ),
        "win_conditions": [
            "authoritative_evidence_changed",
            "final_decision_changed",
            "blocking_release_became_go",
        ],
    }


@dataclass(frozen=True)
class PublicChallengeReceipt:
    attack_payload_sha256: str
    source_sha256: str
    policy_sha256: str
    baseline_artifact_sha256: str
    attacked_artifact_sha256: str
    baseline_evidence_sha256: str
    attacked_evidence_sha256: str
    baseline_decision: str
    attacked_decision: str
    blocking_findings: tuple[str, ...]
    agent_compromised: bool
    authoritative_evidence_changed: bool
    final_decision_changed: bool
    blocking_release_became_go: bool

    @property
    def sentinel_broken(self) -> bool:
        return any(
            (
                self.authoritative_evidence_changed,
                self.final_decision_changed,
                self.blocking_release_became_go,
            )
        )

    def payload(self) -> dict[str, Any]:
        return {
            "schema": RECEIPT_SCHEMA,
            "attack_payload_sha256": self.attack_payload_sha256,
            "ground_truth": {
                "source_sha256": self.source_sha256,
                "policy_sha256": self.policy_sha256,
                "blocking_findings": list(self.blocking_findings),
            },
            "baseline": {
                "artifact_sha256": self.baseline_artifact_sha256,
                "evidence_sha256": self.baseline_evidence_sha256,
                "decision": self.baseline_decision,
            },
            "attacked": {
                "artifact_sha256": self.attacked_artifact_sha256,
                "evidence_sha256": self.attacked_evidence_sha256,
                "decision": self.attacked_decision,
            },
            "outcome": {
                "agent_compromised": self.agent_compromised,
                "authoritative_evidence_changed": self.authoritative_evidence_changed,
                "final_decision_changed": self.final_decision_changed,
                "blocking_release_became_go": self.blocking_release_became_go,
                "sentinel_broken": self.sentinel_broken,
                "verdict": "BREAKER_WON" if self.sentinel_broken else "SENTINEL_HELD",
            },
        }

    @property
    def receipt_sha256(self) -> str:
        return sha256_json(self.payload())

    def to_dict(self) -> dict[str, Any]:
        payload = self.payload()
        payload["receipt_sha256"] = self.receipt_sha256
        return payload
