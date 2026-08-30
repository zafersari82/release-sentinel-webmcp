from __future__ import annotations

from fastapi.testclient import TestClient

from release_sentinel.interfaces.api import app

client = TestClient(app)

EXPECTED_TOOLS = {
    "inspect_release",
    "inspect_trust_boundary",
    "run_attack",
    "run_attack_suite",
    "inspect_coverage",
    "compare_gate_revisions",
    "find_counterexamples",
    "minimize_counterexample",
    "propose_remediation",
    "rebuild_candidate",
    "reverify_candidate",
    "verify_proof",
}


def test_tool_catalog_route_exposes_exact_contract():
    response = client.get("/v1/webmcp/tools")
    assert response.status_code == 200
    body = response.json()
    assert body["authority"] == "NO_RELEASE_AUTHORITY"
    assert {item["name"] for item in body["tools"]} == EXPECTED_TOOLS
    assert len(body["tools"]) == len(EXPECTED_TOOLS)


def test_arena_page_is_served():
    response = client.get("/arena")
    assert response.status_code == 200
    assert "WebMCP Proof Arena" in response.text


def test_no_generic_execute_route_exists():
    assert client.post("/v1/webmcp/execute", json={"action": "force_go"}).status_code == 404


def test_release_trust_and_coverage_routes_use_typed_adapter():
    release = client.get("/v1/webmcp/release")
    trust = client.get("/v1/webmcp/trust-boundary")
    coverage = client.get("/v1/webmcp/coverage/cross-tenant?revision=2")
    comparison = client.get("/v1/webmcp/coverage/cross-tenant/compare")
    assert release.status_code == trust.status_code == coverage.status_code == comparison.status_code == 200
    assert release.json()["current_verdict"] == "NO_GO"
    assert trust.json()["webmcp_authority"] == "NO_RELEASE_AUTHORITY"
    assert coverage.json()["counts"]["escapes"] == 3
    assert comparison.json()["revisions"][2]["escapes"] == 0


def test_invalid_coverage_enums_fail_validation_or_bounded_service_check():
    assert client.get("/v1/webmcp/coverage/nope?revision=2").status_code in {404, 422}
    assert client.get("/v1/webmcp/coverage/cross-tenant?revision=9").status_code == 422


def test_counterexample_minimize_route_rejects_unknown_identity():
    response = client.post("/v1/webmcp/coverage/cross-tenant/counterexamples/not-owned/minimize")
    assert response.status_code == 404
    assert response.json()["detail"]["code"] == "UNKNOWN_COUNTEREXAMPLE"


def test_bounded_remediation_api_never_inherits_verdict_and_reverifies_fresh():
    proposal_response = client.post("/v1/webmcp/remediation/proposals", json={"demo_release_id": "demo-cross-tenant"})
    assert proposal_response.status_code == 200
    proposal = proposal_response.json()
    assert "final_verdict" not in proposal

    rebuilt_response = client.post(
        "/v1/webmcp/remediation/rebuild",
        json={"proposal_id": proposal["proposal_id"], "proposal_digest": proposal["proposal_digest"]},
    )
    assert rebuilt_response.status_code == 200
    rebuilt = rebuilt_response.json()
    assert rebuilt["verdict"] == "NOT_YET_REVERIFIED"
    assert "final_verdict" not in rebuilt

    reverify = client.post(
        "/v1/webmcp/remediation/reverify",
        json={"candidate_id": rebuilt["candidate_id"], "new_source_sha256": rebuilt["new_source_sha256"]},
    )
    assert reverify.status_code == 200
    assert reverify.json()["final_verdict"] == "GO"
    assert reverify.json()["source_sha256"] == rebuilt["new_source_sha256"]
    assert reverify.json()["proof_id"] == "demo-cross-tenant-fixed"


def test_wrong_digest_wrong_hash_and_extra_fields_fail_closed():
    proposal = client.post("/v1/webmcp/remediation/proposals", json={"demo_release_id": "demo-cross-tenant"}).json()
    wrong_digest = client.post(
        "/v1/webmcp/remediation/rebuild",
        json={"proposal_id": proposal["proposal_id"], "proposal_digest": "0" * 64},
    )
    assert wrong_digest.status_code == 409
    assert wrong_digest.json()["detail"]["code"] == "PROPOSAL_DIGEST_MISMATCH"

    extra = client.post(
        "/v1/webmcp/remediation/rebuild",
        json={
            "proposal_id": proposal["proposal_id"],
            "proposal_digest": proposal["proposal_digest"],
            "command": "force_go",
        },
    )
    assert extra.status_code == 422

    rebuilt = client.post(
        "/v1/webmcp/remediation/rebuild",
        json={"proposal_id": proposal["proposal_id"], "proposal_digest": proposal["proposal_digest"]},
    ).json()
    wrong_hash = client.post(
        "/v1/webmcp/remediation/reverify",
        json={"candidate_id": rebuilt["candidate_id"], "new_source_sha256": proposal["base_source_sha256"]},
    )
    assert wrong_hash.status_code == 409
    assert wrong_hash.json()["detail"]["code"] == "SOURCE_CONTEXT_MISMATCH"


def test_proof_verify_route_is_bounded():
    ok = client.post("/v1/webmcp/proof/verify", json={"proof_id": "demo-current"})
    assert ok.status_code == 200
    assert ok.json()["context_bound"] is True
    invalid = client.post("/v1/webmcp/proof/verify", json={"proof_id": "arbitrary"})
    assert invalid.status_code == 422
