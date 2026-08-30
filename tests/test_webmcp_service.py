from __future__ import annotations

import pytest

from release_sentinel.webmcp.service import WebMCPChallengeService, WebMCPServiceError


@pytest.fixture()
def service() -> WebMCPChallengeService:
    return WebMCPChallengeService(
        attack_runner=lambda name: {
            "attack": name,
            "mutation": "AGENT_OPINIONS_ONLY",
            "payload_reached_gatekeeper": True,
            "gatekeeper_accepted_evidence": True,
            "rejection_code": None,
            "result_code": "VERDICT_UNCHANGED",
            "final_verdict": "NO_GO",
            "attack_blocked": True,
            "agent_influence": 0,
        }
    )


def test_inspect_release_and_trust_boundary_keep_webmcp_non_authoritative(service):
    release = service.inspect_release()
    trust = service.inspect_trust_boundary()
    assert release["current_verdict"] == "NO_GO"
    assert len(release["source_sha256"]) == 64
    assert release["authority"] == "DETERMINISTIC_GATEKEEPER"
    assert trust["webmcp_authority"] == "NO_RELEASE_AUTHORITY"
    assert trust["decision_authority"] == "DETERMINISTIC_GATEKEEPER"


def test_run_attack_uses_bounded_runner_and_does_not_create_authority(service):
    result = service.run_attack("force_agents_go")
    assert result["attack"] == "force_agents_go"
    assert result["attack_blocked"] is True
    assert result["final_verdict"] == "NO_GO"
    assert result["webmcp_authority"] == "NO_RELEASE_AUTHORITY"


def test_compare_revisions_exposes_scoped_counts_without_claiming_universal_security(service):
    body = service.compare_gate_revisions("cross-tenant")
    assert [point["revision"] for point in body["revisions"]] == [1, 2, 3]
    assert [point["escapes"] for point in body["revisions"]] == [23, 3, 0]
    assert body["scope_warning"] == "0 observed escapes is scoped to this fixed benchmark corpus."
    assert body["comparison_receipt_verified"] is True


def test_path_comparison_uses_existing_arena_results(service):
    body = service.compare_gate_revisions("path-traversal")
    assert [point["escapes"] for point in body["revisions"]] == [27, 6, 0]
    assert [point["overblocks"] for point in body["revisions"]] == [0, 4, 14]


def test_inspect_coverage_returns_verified_receipt_and_fixed_scope(service):
    body = service.inspect_coverage("cross-tenant", 2)
    assert body["revision"] == 2
    assert body["counts"]["escapes"] == 3
    assert body["receipt_verified"] is True
    assert body["oracle_qualified"] is True
    assert body["tested_scope"]
    assert body["not_tested_scope"]


def test_find_counterexamples_returns_only_package_owned_escape_ids(service):
    body = service.find_counterexamples("path-traversal", 1)
    assert body["counterexamples"]
    assert all(item["classification"] == "ESCAPE" for item in body["counterexamples"])
    assert all("candidate_id" in item and "candidate_sha256" in item for item in body["counterexamples"])
    assert all("source" not in item for item in body["counterexamples"])


def test_minimize_counterexample_accepts_only_known_package_candidate(service):
    candidate = service.find_counterexamples("cross-tenant", 1)["counterexamples"][0]
    result = service.minimize_counterexample("cross-tenant", candidate["candidate_id"])
    assert result["candidate_id"] == candidate["candidate_id"]
    assert result["verified_escape"] is True
    assert result["minimized_source"]
    assert result["minimized_sha256"]

    with pytest.raises(WebMCPServiceError, match="counterexample"):
        service.minimize_counterexample("cross-tenant", "caller-supplied-source")


def test_rebuild_requires_server_proposal_and_never_inherits_verdict(service):
    proposal = service.propose_remediation("demo-cross-tenant")
    assert proposal["authority"] == "PROPOSAL_ONLY"
    assert "final_verdict" not in proposal

    rebuilt = service.rebuild_candidate(proposal["proposal_id"], proposal["proposal_digest"])
    assert rebuilt["old_source_sha256"] != rebuilt["new_source_sha256"]
    assert rebuilt["verdict"] == "NOT_YET_REVERIFIED"
    assert "final_verdict" not in rebuilt


def test_reverify_is_hash_bound_and_returns_deterministic_gatekeeper_verdict(service):
    proposal = service.propose_remediation("demo-cross-tenant")
    rebuilt = service.rebuild_candidate(proposal["proposal_id"], proposal["proposal_digest"])
    result = service.reverify_candidate(rebuilt["candidate_id"], rebuilt["new_source_sha256"])
    assert result["source_sha256"] == rebuilt["new_source_sha256"]
    assert result["proof_id"] == "demo-cross-tenant-fixed"
    assert result["final_verdict"] == "GO"
    assert result["authority"] == "DETERMINISTIC_GATEKEEPER"
    assert result["fresh_evaluation"] is True


def test_replay_digest_and_state_mismatches_fail_closed(service):
    proposal = service.propose_remediation("demo-cross-tenant")
    with pytest.raises(WebMCPServiceError) as wrong_digest:
        service.rebuild_candidate(proposal["proposal_id"], "0" * 64)
    assert wrong_digest.value.code == "PROPOSAL_DIGEST_MISMATCH"

    rebuilt = service.rebuild_candidate(proposal["proposal_id"], proposal["proposal_digest"])
    with pytest.raises(WebMCPServiceError) as wrong_hash:
        service.reverify_candidate(rebuilt["candidate_id"], proposal["base_source_sha256"])
    assert wrong_hash.value.code == "SOURCE_CONTEXT_MISMATCH"

    with pytest.raises(WebMCPServiceError) as unknown:
        service.reverify_candidate("unknown", rebuilt["new_source_sha256"])
    assert unknown.value.code == "UNKNOWN_CANDIDATE"


def test_verify_proof_recomputes_supported_demo_context(service):
    body = service.verify_proof("demo-current")
    assert body["proof_id"] == "demo-current"
    assert body["context_bound"] is True
    assert body["evidence_integrity_verified"] is True
    assert body["verdict"] == "NO_GO"
