from __future__ import annotations

import pytest
from pydantic import ValidationError

from release_sentinel.webmcp.contracts import ProposalRequest, tool_catalog
from release_sentinel.webmcp.service import WebMCPChallengeService

SUPPORTED_DEMO_RELEASES = {
    "demo-cross-tenant",
    "demo-path-traversal",
    "demo-evidence-tamper",
}


def service() -> WebMCPChallengeService:
    return WebMCPChallengeService(
        attack_runner=lambda name: {
            "attack": name,
            "attack_blocked": True,
            "final_verdict": "NO_GO",
            "agent_influence": 0,
        }
    )


def test_proposal_schema_exposes_exact_package_owned_demo_allowlist():
    schemas = {row["name"]: row["input_schema"] for row in tool_catalog()}
    demo_release = schemas["propose_remediation"]["properties"]["demo_release_id"]

    assert set(demo_release["enum"]) == SUPPORTED_DEMO_RELEASES
    assert demo_release["default"] == "demo-cross-tenant"


def test_proposal_request_rejects_unknown_ids_and_extra_caller_fields():
    for release_id in SUPPORTED_DEMO_RELEASES:
        request = ProposalRequest(demo_release_id=release_id)
        assert request.demo_release_id.value == release_id

    with pytest.raises(ValidationError):
        ProposalRequest(demo_release_id="../../tmp/payload")
    with pytest.raises(ValidationError):
        ProposalRequest(demo_release_id="demo-cross-tenant", path="/tmp/payload")
    with pytest.raises(ValidationError):
        ProposalRequest(demo_release_id="demo-cross-tenant", source="print('caller code')")
    with pytest.raises(ValidationError):
        ProposalRequest(demo_release_id="demo-cross-tenant", shell="rm -rf /")


def test_all_demo_scenarios_use_distinct_package_owned_hash_transitions_and_fresh_proofs():
    challenge = service()
    transitions: set[tuple[str, str]] = set()

    for release_id in sorted(SUPPORTED_DEMO_RELEASES):
        proposal = challenge.propose_remediation(release_id)
        assert proposal["authority"] == "PROPOSAL_ONLY"
        assert proposal["demo_release_id"] == release_id

        rebuilt = challenge.rebuild_candidate(proposal["proposal_id"], proposal["proposal_digest"])
        assert rebuilt["old_source_sha256"] != rebuilt["new_source_sha256"]
        assert rebuilt["verdict"] == "NOT_YET_REVERIFIED"
        assert rebuilt["inherited_verdict"] is False
        transitions.add((rebuilt["old_source_sha256"], rebuilt["new_source_sha256"]))

        reverified = challenge.reverify_candidate(rebuilt["candidate_id"], rebuilt["new_source_sha256"])
        assert reverified["source_sha256"] == rebuilt["new_source_sha256"]
        assert reverified["final_verdict"] == "GO"
        assert reverified["fresh_evaluation"] is True
        assert reverified["proof_id"].endswith("-fixed")

        proof = challenge.verify_proof(reverified["proof_id"])
        assert proof["source_sha256"] == rebuilt["new_source_sha256"]
        assert proof["evidence_integrity_verified"] is True
        assert proof["context_bound"] is True

    assert len(transitions) == 3
