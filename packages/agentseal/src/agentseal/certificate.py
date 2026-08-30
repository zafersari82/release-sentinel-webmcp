"""Machine-verifiable counterfactual non-influence certificates."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any

from .check import InfluenceReport

__all__ = [
    "CERTIFICATE_SCHEMA",
    "CounterfactualCertificate",
    "build_certificate",
    "verify_certificate",
]


CERTIFICATE_SCHEMA = "agentseal.counterfactual-non-influence.v1"
_SCOPE = (
    "Differential hostile-substitution evidence for the tested pipeline and variants; "
    "not a universal proof against untested environmental or infrastructure compromise."
)


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


@dataclass(frozen=True)
class CounterfactualCertificate:
    schema: str
    subject: str
    artifact_kind: str
    baseline_artifact_sha256: str
    issued_at_unix: int
    scope: str
    interventions: tuple[dict[str, Any], ...]

    def payload(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "subject": self.subject,
            "artifact_kind": self.artifact_kind,
            "baseline_artifact_sha256": self.baseline_artifact_sha256,
            "issued_at_unix": self.issued_at_unix,
            "scope": self.scope,
            "interventions": [dict(item) for item in self.interventions],
        }

    @property
    def certificate_sha256(self) -> str:
        return hashlib.sha256(_canonical(self.payload())).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        payload = self.payload()
        payload["certificate_sha256"] = self.certificate_sha256
        payload["verified"] = verify_certificate(self)
        return payload


def build_certificate(
    report: InfluenceReport,
    *,
    subject: str,
    artifact_kind: str = "artifact-to-be-signed",
    now_unix: int | None = None,
) -> CounterfactualCertificate:
    interventions = tuple(
        {
            "name": result.name,
            "description": result.description,
            "outcome": result.status,
            "artifact_sha256": result.digest,
            "error": result.error,
        }
        for result in report.results
    )
    return CounterfactualCertificate(
        schema=CERTIFICATE_SCHEMA,
        subject=subject,
        artifact_kind=artifact_kind,
        baseline_artifact_sha256=report.baseline_digest,
        issued_at_unix=int(time.time()) if now_unix is None else int(now_unix),
        scope=_SCOPE,
        interventions=interventions,
    )


def verify_certificate(certificate: CounterfactualCertificate) -> bool:
    if certificate.schema != CERTIFICATE_SCHEMA:
        return False
    if len(certificate.baseline_artifact_sha256) != 64 or not certificate.interventions:
        return False
    for item in certificate.interventions:
        outcome = item.get("outcome")
        if outcome == "SEALED":
            if item.get("artifact_sha256") != certificate.baseline_artifact_sha256:
                return False
        elif outcome == "BLOCKED":
            if item.get("artifact_sha256") is not None:
                return False
        else:
            return False
    return True
