from fastapi.testclient import TestClient

from release_sentinel import __version__
from release_sentinel.interfaces.api import app

client = TestClient(app)


def test_health():
    assert client.get("/healthz").json() == {"status": "ok", "version": __version__}


def test_trust_model():
    body = client.get("/v1/trust-model").json()
    assert body["repository_text_authority"] == "NONE"
    assert body["model_authority"] == "ADVISORY_ONLY"


def test_demo_release_is_real_authoritative_no_go():
    body = client.get("/v1/demo/release").json()
    assert body["decision"] == "NO_GO"
    assert body["execution_count"] == 1
    assert body["findings"][0]["evidence"][0]["authority"] == "ORGANIZATION_POLICY"


def test_demo_parity_blocks():
    body = client.get("/v1/demo/parity").json()
    assert body["cutover_allowed"] is False
    assert body["blockers"] == 1


def test_root_dashboard_served():
    assert "Release Sentinel" in client.get("/").text


def test_cloud_runtime_endpoint_is_truthful_locally(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _: None)
    body = client.get("/v1/cloud-proof/runtime").json()
    assert body["sandbox_available"] is False


def test_cloud_proof_unknown_fixture_is_404():
    assert client.post("/v1/cloud-proof/release/nope").status_code == 404


def test_verdict_independence_endpoint():
    body = client.get("/v1/demo/verdict-independence").json()
    assert body["agents_all_go"] is True
    assert body["agent_go_count"] == body["agent_count"] == 4
    assert body["final_verdict"] == "NO_GO"
    assert body["unchanged"] is True
    assert body["gatekeeper"]["agent_influence"] == 0
    assert body["gatekeeper"]["llm_present"] is False


def test_repository_attack_fixture_has_zero_authority():
    body = client.get("/v1/demo/repository-attack").json()
    assert body["prompt_injection_fixture_present"] is True
    assert body["forged_claim_present"] is True
    assert body["repository_claim_authority"] == "NONE"
