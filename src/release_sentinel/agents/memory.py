from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Callable, Protocol

from release_sentinel.domain.evidence import Finding
from release_sentinel.domain.release import ReleaseRequest


class ReleaseMemory(Protocol):
    def recent_for_release(self, release_id: str, limit: int = 5) -> list[dict[str, Any]]: ...


def safe_report_summary(document: dict[str, Any]) -> dict[str, Any]:
    """Project a persisted report into bounded model-safe release memory.

    Evidence bodies, provenance, repository content, tokens, and credentials are
    intentionally absent from this projection.
    """
    report = dict(document.get("report") or document)
    findings = []
    for finding in list(report.get("findings") or [])[:12]:
        findings.append(
            {
                "finding_id": str(finding.get("finding_id") or "")[:96],
                "title": str(finding.get("title") or "")[:160],
                "severity": str(finding.get("severity") or "")[:24],
                "source": str(finding.get("source") or "")[:64],
            }
        )
    return {
        "report_id": str(report.get("report_id") or "")[:96],
        "release_id": str(report.get("release_id") or "")[:96],
        "decision": str(report.get("decision") or "")[:32],
        "policy_id": str(report.get("policy_id") or "")[:96],
        "policy_revision": int(report.get("policy_revision") or 0),
        "execution_count": int(report.get("execution_count") or 0),
        "created_at": str(report.get("created_at") or "")[:64],
        "findings": findings,
    }


def bounded_history_json(history: list[dict[str, Any]]) -> str:
    safe = [safe_report_summary(item) for item in history[:5]]
    return json.dumps(safe, sort_keys=True, separators=(",", ":"), ensure_ascii=False)[:8000]


@dataclass
class MemoryAwareAdvisor:
    memory: ReleaseMemory
    advisor: Callable[[ReleaseRequest, list[Finding]], dict[str, Any]]

    def __call__(self, request: ReleaseRequest, findings: list[Finding]) -> dict[str, Any]:
        try:
            history = self.memory.recent_for_release(request.release_id, limit=5)
            safe_history = [safe_report_summary(item) for item in history[:5]]
            memory_status = "AVAILABLE"
        except Exception:
            safe_history = []
            memory_status = "UNAVAILABLE"
        result = deepcopy(self.advisor(request, findings))
        result["safe_prior_release_context"] = safe_history
        result["dissent_reviewer_context"] = bounded_history_json(safe_history)
        result["memory_status"] = memory_status
        return result
