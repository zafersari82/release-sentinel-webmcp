from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from release_sentinel.domain.evidence import Severity


class PolicyError(ValueError):
    pass


@dataclass(frozen=True)
class PolicyCommand:
    command_id: str
    title: str
    argv: tuple[str, ...]
    cwd: str
    timeout_seconds: int
    severity: Severity
    blocking_on_failure: bool = True


@dataclass(frozen=True)
class ReleasePolicy:
    policy_id: str
    revision: int
    commands: tuple[PolicyCommand, ...]
    sha256: str

    def canonical_payload(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "revision": self.revision,
            "commands": [
                {
                    "id": c.command_id,
                    "title": c.title,
                    "argv": list(c.argv),
                    "cwd": c.cwd,
                    "timeout_seconds": c.timeout_seconds,
                    "severity": c.severity.value,
                    "blocking_on_failure": c.blocking_on_failure,
                }
                for c in self.commands
            ],
        }


def canonical_json_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def canonical_sha256(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def build_policy(document: dict[str, Any]) -> ReleasePolicy:
    if not isinstance(document, dict):
        raise PolicyError("policy must be an object")
    policy_id = document.get("policy_id")
    revision = document.get("revision")
    if not isinstance(policy_id, str) or not policy_id.strip():
        raise PolicyError("policy_id is required")
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
        raise PolicyError("revision must be a positive integer")
    raw_commands = document.get("commands")
    if not isinstance(raw_commands, list) or not raw_commands:
        raise PolicyError("policy must define commands")
    commands: list[PolicyCommand] = []
    seen: set[str] = set()
    for raw in raw_commands:
        if not isinstance(raw, dict):
            raise PolicyError("command must be an object")
        command_id = raw.get("id")
        if not isinstance(command_id, str) or not command_id or command_id in seen:
            raise PolicyError("command ids must be unique non-empty strings")
        seen.add(command_id)
        argv = raw.get("argv")
        if not isinstance(argv, list) or not argv or not all(isinstance(x, str) and x for x in argv):
            raise PolicyError(f"{command_id}: argv must be a non-empty string list")
        if not argv[0].startswith("/"):
            raise PolicyError(f"{command_id}: executable must be an absolute path")
        cwd = raw.get("cwd", ".")
        if not isinstance(cwd, str) or cwd.startswith("/") or ".." in cwd.split("/"):
            raise PolicyError(f"{command_id}: cwd must stay inside repository")
        timeout = raw.get("timeout_seconds", 120)
        if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= 1800:
            raise PolicyError(f"{command_id}: timeout_seconds out of range")
        try:
            severity = Severity(raw.get("severity", "HIGH"))
        except ValueError as exc:
            raise PolicyError(f"{command_id}: invalid severity") from exc
        blocking = raw.get("blocking_on_failure", True)
        if not isinstance(blocking, bool):
            raise PolicyError(f"{command_id}: blocking_on_failure must be boolean")
        commands.append(PolicyCommand(command_id, str(raw.get("title") or command_id), tuple(argv), cwd, timeout, severity, blocking))
    payload = {
        "policy_id": policy_id.strip(),
        "revision": revision,
        "commands": [
            {
                "id": c.command_id,
                "title": c.title,
                "argv": list(c.argv),
                "cwd": c.cwd,
                "timeout_seconds": c.timeout_seconds,
                "severity": c.severity.value,
                "blocking_on_failure": c.blocking_on_failure,
            }
            for c in commands
        ],
    }
    return ReleasePolicy(policy_id.strip(), revision, tuple(commands), canonical_sha256(payload))
