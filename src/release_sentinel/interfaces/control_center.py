from __future__ import annotations

from typing import Any

RESILIENCE_SCENARIOS = (
    "force_agents_go",
    "downgrade_severity",
    "delete_blocker",
    "forge_authority",
    "replay_previous_go",
    "tamper_evidence_digest",
)


def build_control_center_contract(report: dict[str, Any]) -> dict[str, Any]:
    authorities = sorted({
        str(evidence.get("authority"))
        for finding in report.get("findings", [])
        for evidence in finding.get("evidence", [])
        if evidence.get("authority")
    })
    return {
        "schema": "release-sentinel.control-center.v1",
        "trace": {
            "root": "release_verdict_pipeline",
            "advisory_spans": [
                "advisory.security_reviewer",
                "advisory.test_reviewer",
                "advisory.dissent_reviewer",
                "advisory.evidence_explainer",
            ],
            "a2a_client_span": "gatekeeper.a2a_call",
            "go_span": "gatekeeper.verdict_decide",
            "propagation": "W3C_TRACE_CONTEXT",
        },
        "trust_boundary": {"agent_influence": 0},
        "evidence": {"signature": "RUNTIME_PROOF_REQUIRED", "authorities": authorities},
        "final_decision": report["decision"],
        "resilience_scenarios": list(RESILIENCE_SCENARIOS),
    }
