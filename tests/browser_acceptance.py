from __future__ import annotations

import json
from pathlib import Path

from playwright.sync_api import sync_playwright

from release_sentinel import __version__

ROOT = Path(__file__).parents[1]
STATIC = ROOT / "src/release_sentinel/interfaces/static"
OUTPUT = ROOT / "artifacts/enterprise-control-plane-1440x900.png"
OUTPUT.parent.mkdir(exist_ok=True)

release = {
    "decision": "NO_GO",
    "execution_count": 1,
    "policy_sha256": "1234567890abcdef" * 4,
    "rationale": ["1 high/critical finding has authoritative blocking evidence."],
    "findings": [
        {
            "severity": "HIGH",
            "title": "Cross-tenant authorization boundary",
            "claim": "Required organization check failed.",
            "evidence": [
                {
                    "authority": "ORGANIZATION_POLICY",
                    "summary": "Organization-owned release check failed in isolated execution.",
                }
            ],
        }
    ],
}
health = {"status": "ok", "version": __version__}
proof = {
    "proof": "VERDICT_INDEPENDENCE",
    "baseline_decision": "NO_GO",
    "compromised_decision": "NO_GO",
    "agent_votes": [
        {"agent": agent_id, "vote": "GO"}
        for agent_id in (
            "security_reviewer",
            "test_reviewer",
            "dissent_reviewer",
            "evidence_explainer",
        )
    ],
    "agents_all_go": True,
    "agent_go_count": 4,
    "agent_count": 4,
    "final_verdict": "NO_GO",
    "gatekeeper": {
        "component": "release-sentinel-go-gatekeeper",
        "llm_present": False,
        "agent_influence": 0,
        "transport": "A2A_JSONRPC",
        "trace_id": "0123456789abcdef0123456789abcdef",
    },
    "unchanged": True,
    "signed_evidence_verified": True,
}
agents = [
    {
        "agent_id": "security_reviewer",
        "version": __version__,
        "runtime": "python-adk",
        "skill_tags": ["security", "challenge"],
        "decision_authority": "ADVISORY",
        "transport": "ADK",
        "status": "ACTIVE",
        "registered_at": "2026-08-19T00:00:00Z",
    },
    {
        "agent_id": "test_reviewer",
        "version": __version__,
        "runtime": "python-adk",
        "skill_tags": ["testing", "evidence"],
        "decision_authority": "ADVISORY",
        "transport": "ADK",
        "status": "ACTIVE",
        "registered_at": "2026-08-19T00:00:00Z",
    },
    {
        "agent_id": "dissent_reviewer",
        "version": __version__,
        "runtime": "python-adk",
        "skill_tags": ["dissent", "history"],
        "decision_authority": "ADVISORY",
        "transport": "ADK",
        "status": "ACTIVE",
        "registered_at": "2026-08-19T00:00:00Z",
    },
    {
        "agent_id": "evidence_explainer",
        "version": __version__,
        "runtime": "python-adk",
        "skill_tags": ["evidence", "explanation"],
        "decision_authority": "ADVISORY",
        "transport": "ADK",
        "status": "ACTIVE",
        "registered_at": "2026-08-19T00:00:00Z",
    },
    {
        "agent_id": "go-gatekeeper",
        "version": __version__,
        "runtime": "go",
        "skill_tags": ["policy", "signed-evidence", "verdict"],
        "decision_authority": "DETERMINISTIC",
        "transport": "A2A_JSONRPC",
        "status": "ACTIVE",
        "registered_at": "2026-08-19T00:00:00Z",
    },
]
registry = {
    "schema": "release-sentinel.agent-registry.v1",
    "agents": agents,
    "fleet": {"advisory": 4, "deterministic": 1},
    "authority": {"ADVISORY": 4, "DETERMINISTIC": 1},
}
center = {
    "schema": "release-sentinel.control-center.v1",
    "trace": {
        "root": "release_verdict_pipeline",
        "a2a_client_span": "gatekeeper.a2a_call",
        "go_span": "gatekeeper.verdict_decide",
    },
    "trust_boundary": {"agent_influence": 0},
    "evidence": {
        "signature": "RUNTIME_PROOF_REQUIRED",
        "authorities": ["ORGANIZATION_POLICY"],
    },
    "final_decision": "NO_GO",
    "resilience_scenarios": [
        "force_agents_go",
        "downgrade_severity",
        "delete_blocker",
        "forge_authority",
        "replay_previous_go",
        "tamper_evidence_digest",
    ],
}
attack_result = {
    "attack_blocked": True,
    "payload_reached_gatekeeper": True,
    "gatekeeper_accepted_evidence": False,
    "rejection_code": "DIGEST_MISMATCH",
    "final_verdict": None,
    "agent_influence": 0,
    "evidence_verified": False,
}

html = (STATIC / "index.html").read_text()
css = (STATIC / "app.css").read_text()
javascript = (STATIC / "app.js").read_text()
html = html.replace(
    '<link rel="stylesheet" href="/static/app.css">',
    f"<style>{css}</style>",
).replace('<script src="/static/app.js"></script>', "")

with sync_playwright() as playwright:
    browser = playwright.chromium.launch(
        headless=True,
        executable_path="/usr/bin/chromium",
        args=["--no-sandbox"],
    )
    page = browser.new_page(viewport={"width": 1440, "height": 900})
    page.set_content(html)
    page.evaluate(
        """
        ([health, release, proof, registry, center, attackResult]) => {
          window.fetch = async (url) => ({
            ok: true,
            json: async () => {
              url = String(url);
              if (url.includes('attack-gate')) return attackResult;
              if (url.includes('/healthz')) return health;
              if (url.includes('/v1/demo/release')) return release;
              if (url.includes('verdict-independence')) return proof;
              if (url.includes('/v1/agents')) return registry;
              if (url.includes('/v1/control-center')) return center;
              throw new Error('unexpected ' + url);
            },
          });
        }
        """,
        [health, release, proof, registry, center, attack_result],
    )
    page.add_script_tag(content=javascript)
    page.wait_for_function("document.querySelector('#finalVerdict').textContent === 'NO_GO'")
    page.click("#runAll")
    page.wait_for_function(
        "document.querySelector('#attackSummary').textContent.startsWith('6/6 PASS')"
    )
    metrics = page.evaluate(
        """
        () => ({
          height: document.documentElement.scrollHeight,
          viewport: innerHeight,
          decision: document.querySelector('#finalVerdict').textContent,
          advisory: document.querySelector('#advisoryCount').textContent,
          deterministic: document.querySelector('#deterministicCount').textContent,
          influence: document.querySelector('#agentInfluence').textContent,
          signature: document.querySelector('#signature').textContent,
          registryRows: document.querySelectorAll('#registryRows tr').length,
          resilience: document.querySelector('#attackSummary').textContent,
          body: document.body.innerText,
        })
        """
    )

    assert metrics["height"] <= 900, metrics
    assert metrics["decision"] == "NO_GO"
    assert metrics["advisory"] == "4"
    assert metrics["deterministic"] == "1"
    assert metrics["influence"] == "0"
    assert metrics["signature"] == "VERIFIED"
    assert metrics["registryRows"] == 5
    assert metrics["resilience"].startswith("6/6 PASS")
    assert "DISTRIBUTED TRACE" in metrics["body"]
    assert "LIVE AGENT REGISTRY" in metrics["body"]
    assert "PRIVATE IAM / OIDC" in metrics["body"]

    page.screenshot(path=str(OUTPUT), full_page=True)
    browser.close()

print(
    json.dumps(
        {
            "scrollHeight": metrics["height"],
            "viewport": metrics["viewport"],
            "decision": metrics["decision"],
            "advisory": metrics["advisory"],
            "deterministic": metrics["deterministic"],
            "agentInfluence": metrics["influence"],
            "signature": metrics["signature"],
            "registryRows": metrics["registryRows"],
            "resilience": metrics["resilience"],
            "screenshot": str(OUTPUT),
        }
    )
)
