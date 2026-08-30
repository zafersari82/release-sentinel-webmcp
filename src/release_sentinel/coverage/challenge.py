from __future__ import annotations

import json
from dataclasses import dataclass
from importlib.resources import files
from typing import Any, Mapping

from release_sentinel.coverage.canonical import sha256_json


@dataclass(frozen=True)
class CoverageChallenge:
    payload: Mapping[str, Any]

    def __post_init__(self) -> None:
        data = dict(self.payload)
        if data.get("schema") != "release-sentinel.coverage-challenge.v1":
            raise ValueError("unsupported coverage challenge schema")
        if not isinstance(data.get("id"), str) or not data["id"]:
            raise ValueError("coverage challenge id is required")
        revision = data.get("revision")
        if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
            raise ValueError("coverage challenge revision must be positive")
        scope = data.get("scope")
        if not isinstance(scope, dict):
            raise ValueError("coverage challenge scope is required")
        tested = scope.get("tested") or []
        not_tested = scope.get("not_tested") or []
        if not tested or set(tested) & set(not_tested):
            raise ValueError("coverage challenge scope must be non-empty and disjoint")
        object.__setattr__(self, "payload", data)

    @property
    def challenge_id(self) -> str:
        return str(self.payload["id"])

    @property
    def revision(self) -> int:
        return int(self.payload["revision"])

    @property
    def sha256(self) -> str:
        return sha256_json(self.payload)


def _load_builtin_challenge(resource_name: str) -> CoverageChallenge:
    resource = files("release_sentinel.coverage.challenges").joinpath(resource_name)
    payload = json.loads(resource.read_text(encoding="utf-8"))
    return CoverageChallenge(payload)


def load_cross_tenant_challenge() -> CoverageChallenge:
    return _load_builtin_challenge("cross_tenant_v1.json")


def load_path_traversal_challenge() -> CoverageChallenge:
    return _load_builtin_challenge("path_traversal_v1.json")
