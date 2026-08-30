from __future__ import annotations

import json
from importlib.resources import files
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from release_sentinel import __version__
from release_sentinel.agents.advisory import deterministic_advisory
from release_sentinel.agents.memory import MemoryAwareAdvisor, safe_report_summary
from release_sentinel.agents.registry import AgentRecord, AgentRegistry, DecisionAuthority, default_agent_registry
from release_sentinel.domain.release import ReleaseRequest
from release_sentinel.execution.demo import BundledDemoExecutor
from release_sentinel.interfaces.api import app
from release_sentinel.policy.model import build_policy
from release_sentinel.release.engine import ReleaseEngine
from release_sentinel.release.gatekeeper import A2AGatekeeperClient, LocalDeterministicGatekeeper


def _agent_mapping(**overrides):
    base = {
        "agent_id": "runtime-reviewer",
        "version": __version__,
        "runtime": "python-adk",
        "skill_tags": ["review"],
        "decision_authority": "ADVISORY",
        "transport": "ADK",
        "status": "ACTIVE",
        "registered_at": "2026-08-19T00:00:00Z",
    }
    base.update(overrides)
    return base


def _demo_evaluate(advisor):
    base = Path(str(files("release_sentinel"))) / "demo_fixture"
    policy = build_policy(json.loads((base / "organization-policy.json").read_text()))
    source = (base / "repository_vulnerable.sha256").read_text().strip()
    return ReleaseEngine(
        BundledDemoExecutor(source), advisor=advisor, gatekeeper=LocalDeterministicGatekeeper()
    ).evaluate(ReleaseRequest("enterprise-risk-test", base / "repository_vulnerable"), policy)


def test_registry_has_real_required_fleet_and_api_surface():
    registry = default_agent_registry()
    records = {record.agent_id: record for record in registry.list()}
    assert set(records) == {
        "security_reviewer", "test_reviewer", "dissent_reviewer", "evidence_explainer", "go-gatekeeper"
    }
    assert all(records[name].decision_authority is DecisionAuthority.ADVISORY for name in records if name != "go-gatekeeper")
    assert records["go-gatekeeper"].decision_authority is DecisionAuthority.DETERMINISTIC
    body = TestClient(app).get("/v1/agents").json()
    assert body["fleet"] == {"advisory": 4, "deterministic": 1}
    assert len(body["agents"]) == 5


def test_advisory_self_registration_cannot_escalate_to_deterministic():
    registry = AgentRegistry([])
    with pytest.raises(PermissionError):
        registry.register_advisory(_agent_mapping(decision_authority="DETERMINISTIC"))
    assert registry.deterministic_agents() == []


def test_registry_malformed_authority_fails_closed():
    with pytest.raises(ValueError, match="decision_authority"):
        AgentRecord.from_mapping(_agent_mapping(decision_authority="ROOT"))
    with pytest.raises(ValueError, match="decision_authority"):
        AgentRecord.from_mapping(_agent_mapping(decision_authority="deterministic"))


class PersistentLedgerDouble:
    def __init__(self):
        self.documents: list[dict] = []

    def persist(self, document: dict) -> None:
        self.documents.append(document)

    def recent_for_release(self, release_id: str, limit: int = 5) -> list[dict]:
        matching = [doc for doc in self.documents if (doc.get("report") or doc).get("release_id") == release_id]
        return [safe_report_summary(doc) for doc in matching[-limit:][::-1]]


class BrokenMemory:
    def recent_for_release(self, release_id: str, limit: int = 5):
        raise RuntimeError("memory backend unavailable")


def test_prior_release_safe_memory_appears_in_next_dissent_context_without_raw_evidence():
    ledger = PersistentLedgerDouble()
    ledger.persist({
        "report": {
            "report_id": "report-n",
            "release_id": "release-family",
            "decision": "NO_GO",
            "policy_id": "org",
            "policy_revision": 1,
            "execution_count": 1,
            "created_at": "2026-08-19T20:00:00+00:00",
            "findings": [{
                "finding_id": "F-1", "title": "Boundary failure", "severity": "HIGH", "source": "organization_policy",
                "evidence": [{"raw_payload": "SUPER_SECRET_EVIDENCE", "credential": "DO_NOT_EXPOSE"}],
            }],
        },
        "provenance": {"signature": "RAW_SIGNATURE_SECRET"},
    })
    # A separate advisor instance represents release N+1 / a later process session.
    result = MemoryAwareAdvisor(ledger, deterministic_advisory)(
        ReleaseRequest("release-family", Path(".")), []
    )
    assert result["memory_status"] == "AVAILABLE"
    assert result["safe_prior_release_context"][0]["report_id"] == "report-n"
    context = result["dissent_reviewer_context"]
    assert "Boundary failure" in context
    for secret in ("SUPER_SECRET_EVIDENCE", "DO_NOT_EXPOSE", "RAW_SIGNATURE_SECRET", "raw_payload", "credential"):
        assert secret not in context


def test_registry_failure_is_non_authoritative_to_verdict():
    def broken_registry_advisor(*_):
        raise RuntimeError("registry unavailable")
    report = _demo_evaluate(broken_registry_advisor)
    assert report.decision.value == "NO_GO"
    assert report.advisory["status"] == "UNAVAILABLE"
    assert report.gatekeeper["agent_influence"] == 0


def test_memory_failure_is_non_authoritative_to_verdict():
    report = _demo_evaluate(MemoryAwareAdvisor(BrokenMemory(), deterministic_advisory))
    assert report.decision.value == "NO_GO"
    assert report.advisory["memory_status"] == "UNAVAILABLE"
    assert report.gatekeeper["agent_influence"] == 0


def test_python_telemetry_failure_is_non_authoritative_to_verdict(monkeypatch):
    import release_sentinel.observability.tracing as tracing
    monkeypatch.setattr(tracing, "tracer", lambda: (_ for _ in ()).throw(RuntimeError("otel down")))
    report = _demo_evaluate(deterministic_advisory)
    assert report.decision.value == "NO_GO"
    assert report.gatekeeper["agent_influence"] == 0


def test_private_a2a_endpoint_and_identity_configuration_fail_closed():
    with pytest.raises(ValueError):
        A2AGatekeeperClient("https://example.com", audience="https://example.com")
    with pytest.raises(ValueError):
        A2AGatekeeperClient("https://gatekeeper-abc-uc.a.run.app", audience=None)
    with pytest.raises(ValueError):
        A2AGatekeeperClient(
            "https://gatekeeper-abc-uc.a.run.app",
            audience="https://other-abc-uc.a.run.app",
        )
    with pytest.raises(ValueError):
        A2AGatekeeperClient("https://gatekeeper-abc-uc.a.run.app/path", audience="https://gatekeeper-abc-uc.a.run.app")


def test_go_gatekeeper_runtime_has_no_llm_dependency():
    root = Path(__file__).parents[1] / "gatekeeper"
    text = "\n".join(path.read_text(errors="ignore") for path in root.rglob("*.go")) + (root / "go.mod").read_text()
    lowered = text.lower()
    for forbidden in ("openai", "anthropic", "gemini", "google.golang.org/genai", "vertexai"):
        assert forbidden not in lowered


def test_control_center_contract_exposes_required_judge_view():
    body = TestClient(app).get("/v1/control-center").json()
    assert body["trace"]["root"] == "release_verdict_pipeline"
    assert body["trace"]["a2a_client_span"] == "gatekeeper.a2a_call"
    assert body["trace"]["go_span"] == "gatekeeper.verdict_decide"
    assert body["trust_boundary"]["agent_influence"] == 0
    assert body["evidence"]["authorities"] == ["ORGANIZATION_POLICY"]
    assert len(body["resilience_scenarios"]) == 6
