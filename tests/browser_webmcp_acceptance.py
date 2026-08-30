from __future__ import annotations

import json
import os
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).parents[1]
STATIC = ROOT / "src/release_sentinel/interfaces/static"
OUTPUT = ROOT / "artifacts/webmcp-proof-arena-1440x900.png"
OUTPUT.parent.mkdir(exist_ok=True)

catalog = {
    "schema": "release-sentinel.webmcp-tools.v1",
    "authority": "NO_RELEASE_AUTHORITY",
    "tools": [
        {"name": name, "capability": capability, "description": name.replace("_", " "), "input_schema": {"type": "object", "properties": {}}}
        for name, capability in [
            ("inspect_release", "READ"),
            ("inspect_trust_boundary", "READ"),
            ("run_attack", "CHALLENGE"),
            ("run_attack_suite", "CHALLENGE"),
            ("inspect_coverage", "READ"),
            ("compare_gate_revisions", "READ"),
            ("find_counterexamples", "CHALLENGE"),
            ("minimize_counterexample", "CHALLENGE"),
            ("propose_remediation", "PROPOSE"),
            ("rebuild_candidate", "PROPOSE"),
            ("reverify_candidate", "PROPOSE"),
            ("verify_proof", "READ"),
        ]
    ],
}
release = {
    "release_id": "webmcp-demo-current",
    "source_sha256": "7a24aac070bfe201e8fb1bac9eaca2398dbdbf308152f7d76d437813e90c3a73",
    "policy_sha256": "a" * 64,
    "current_verdict": "NO_GO",
    "blocking_findings": [{"finding_id": "POL-1234", "severity": "HIGH", "title": "Cross-tenant authorization boundary"}],
    "proof_available": True,
    "authority": "DETERMINISTIC_GATEKEEPER",
    "webmcp_authority": "NO_RELEASE_AUTHORITY",
}
trust = {
    "repository_text_authority": "NONE",
    "model_authority": "ADVISORY_ONLY",
    "webmcp_authority": "NO_RELEASE_AUTHORITY",
    "blocking_authorities": ["PLATFORM", "ORGANIZATION_POLICY"],
    "decision_authority": "DETERMINISTIC_GATEKEEPER",
    "production_gatekeeper": "GO_A2A_SERVICE",
    "authority_chain": ["AI_AGENT", "WEBMCP_CAPABILITY", "RELEASE_SENTINEL_API", "SIGNED_EVIDENCE", "DETERMINISTIC_GATEKEEPER"],
}
comparisons = {
    "cross-tenant": {
        "challenge": "cross-tenant",
        "challenge_id": "cross-tenant-authorization",
        "oracle_qualified": True,
        "revisions": [
            {"revision": 1, "policy_sha256": "1" * 64, "escapes": 23, "overblocks": 0, "escape_rate": {"numerator": 23, "denominator": 30, "observed": 23 / 30}, "overblock_rate": {"numerator": 0, "denominator": 30, "observed": 0}},
            {"revision": 2, "policy_sha256": "2" * 64, "escapes": 3, "overblocks": 4, "escape_rate": {"numerator": 3, "denominator": 30, "observed": .1}, "overblock_rate": {"numerator": 4, "denominator": 30, "observed": 4 / 30}},
            {"revision": 3, "policy_sha256": "3" * 64, "escapes": 0, "overblocks": 21, "escape_rate": {"numerator": 0, "denominator": 30, "observed": 0}, "overblock_rate": {"numerator": 21, "denominator": 30, "observed": .7}},
        ],
        "comparison_receipt_verified": True,
        "scope_warning": "0 observed escapes is scoped to this fixed benchmark corpus.",
        "authority": "MEASUREMENT_ONLY",
    },
    "path-traversal": {
        "challenge": "path-traversal",
        "challenge_id": "path-traversal-containment",
        "oracle_qualified": True,
        "revisions": [
            {"revision": 1, "policy_sha256": "4" * 64, "escapes": 27, "overblocks": 0, "escape_rate": {"numerator": 27, "denominator": 30, "observed": .9}, "overblock_rate": {"numerator": 0, "denominator": 30, "observed": 0}},
            {"revision": 2, "policy_sha256": "5" * 64, "escapes": 6, "overblocks": 4, "escape_rate": {"numerator": 6, "denominator": 30, "observed": .2}, "overblock_rate": {"numerator": 4, "denominator": 30, "observed": 4 / 30}},
            {"revision": 3, "policy_sha256": "6" * 64, "escapes": 0, "overblocks": 14, "escape_rate": {"numerator": 0, "denominator": 30, "observed": 0}, "overblock_rate": {"numerator": 14, "denominator": 30, "observed": 14 / 30}},
        ],
        "comparison_receipt_verified": True,
        "scope_warning": "0 observed escapes is scoped to this fixed benchmark corpus.",
        "authority": "MEASUREMENT_ONLY",
    },
}
counterexamples = {
    "challenge": "cross-tenant",
    "revision": 1,
    "counterexamples": [{"candidate_id": "unsafe-prefix-01", "candidate_sha256": "b" * 64, "classification": "ESCAPE", "gate_decision": "GO", "oracle_verdict": "UNSAFE", "policy_revision": 1}],
    "source_exposure": "IDENTITY_ONLY",
    "authority": "MEASUREMENT_ONLY",
}
minimized = {
    "challenge": "cross-tenant",
    "candidate_id": "unsafe-prefix-01",
    "policy_revision": 1,
    "original_sha256": "b" * 64,
    "minimized_sha256": "c" * 64,
    "minimized_source": "def can_read(requester_tenant, resource_tenant):\n    return requester_tenant.startswith(resource_tenant)\n",
    "status": "MINIMAL_UNDER_CONFIGURED_GRANULARITY",
    "evaluations": 3,
    "removed_lines": 1,
    "verified_escape": True,
    "authority": "MEASUREMENT_ONLY",
}
proposal = {
    "proposal_id": "proposal-123",
    "demo_release_id": "demo-cross-tenant",
    "base_source_sha256": release["source_sha256"],
    "target_source_sha256": "d" * 64,
    "allowed_change_summary": "Replace only app.py with the package-owned fixed demo fixture.",
    "proposal_digest": "e" * 64,
    "authority": "PROPOSAL_ONLY",
    "approved": False,
}
rebuilt = {
    "candidate_id": "candidate-123",
    "proposal_id": proposal["proposal_id"],
    "demo_release_id": proposal["demo_release_id"],
    "old_source_sha256": proposal["base_source_sha256"],
    "new_source_sha256": proposal["target_source_sha256"],
    "build_status": "REBUILT_FROM_PACKAGE_OWNED_FIXTURE",
    "verdict": "NOT_YET_REVERIFIED",
    "inherited_verdict": False,
    "webmcp_authority": "NO_RELEASE_AUTHORITY",
}
reverified = {
    "candidate_id": rebuilt["candidate_id"],
    "demo_release_id": proposal["demo_release_id"],
    "proof_id": "demo-cross-tenant-fixed",
    "source_sha256": rebuilt["new_source_sha256"],
    "fresh_evidence_sha256": "f" * 64,
    "fresh_evaluation": True,
    "final_verdict": "GO",
    "authority": "DETERMINISTIC_GATEKEEPER",
    "webmcp_authority": "NO_RELEASE_AUTHORITY",
}
attack = {
    "attack": "force_agents_go",
    "mutation": "AGENT_OPINIONS_ONLY",
    "payload_reached_gatekeeper": True,
    "gatekeeper_accepted_evidence": True,
    "result_code": "VERDICT_UNCHANGED",
    "final_verdict": "NO_GO",
    "attack_blocked": True,
    "agent_influence": 0,
    "webmcp_authority": "NO_RELEASE_AUTHORITY",
}
proof = {
    "proof_id": "demo-cross-tenant-fixed",
    "source_sha256": rebuilt["new_source_sha256"],
    "context_bound": True,
    "evidence_integrity_verified": True,
    "verdict": "GO",
    "authority": "DETERMINISTIC_GATEKEEPER",
}

html = (STATIC / "arena.html").read_text(encoding="utf-8")
css = (STATIC / "arena.css").read_text(encoding="utf-8") if (STATIC / "arena.css").exists() else ""
js = (STATIC / "arena.js").read_text(encoding="utf-8") if (STATIC / "arena.js").exists() else ""
html = html.replace('<link rel="stylesheet" href="/static/arena.css">', f"<style>{css}</style>")
html = html.replace('<script src="/static/arena.js"></script>', "")


def install_stubs(page, proof_payload):
    stub_payload = [catalog, release, trust, comparisons, counterexamples, minimized, proposal, rebuilt, reverified, attack, proof_payload]
    page.evaluate(
        """
        ([catalog, release, trust, comparisons, counterexamples, minimized, proposal, rebuilt, reverified, attack, proof]) => {
          window.__registeredTools = [];
          document.modelContext = {
            registerTool: async tool => { window.__registeredTools.push(tool); return { ok: true }; }
          };
          window.fetch = async (url, options={}) => {
            url = String(url);
            let payload;
            if (url.endsWith('/v1/webmcp/tools')) payload = catalog;
            else if (url.endsWith('/v1/webmcp/release')) payload = release;
            else if (url.endsWith('/v1/webmcp/trust-boundary')) payload = trust;
            else if (url.includes('/compare')) payload = comparisons[url.includes('path-traversal') ? 'path-traversal' : 'cross-tenant'];
            else if (url.includes('/counterexamples/') && url.endsWith('/minimize')) payload = minimized;
            else if (url.includes('/counterexamples')) payload = counterexamples;
            else if (url.includes('/remediation/proposals')) payload = proposal;
            else if (url.includes('/remediation/rebuild')) payload = rebuilt;
            else if (url.includes('/remediation/reverify')) payload = reverified;
            else if (url.includes('/attack/')) payload = {...attack, attack: decodeURIComponent(url.split('/').pop())};
            else if (url.includes('/proof/verify')) payload = proof;
            else if (url.includes('/coverage/')) payload = comparisons['cross-tenant'];
            else throw new Error('unexpected fetch ' + url);
            return { ok: true, status: 200, json: async () => payload };
          };
        }
        """,
        stub_payload,
    )


def run_remediation(page):
    page.wait_for_function("document.querySelector('#webmcpStatus')?.textContent === 'REGISTERED'")
    page.wait_for_function("document.querySelector('#currentVerdict')?.textContent === 'NO_GO'")
    assert page.locator("#humanProofCard").get_attribute("hidden") is not None
    page.click("#createProposal")
    page.click("#rebuildCandidate")
    page.click("#reverifyCandidate")
    page.wait_for_function("document.querySelector('#remediationVerdict')?.textContent === 'GO'")
    page.wait_for_function("!document.querySelector('#humanProofCard').hidden")
    assert page.locator("#humanProofStatus").inner_text() == "UNVERIFIED BY HUMAN"


with sync_playwright() as playwright:
    launch_options = {'headless': True, 'args': ["--no-sandbox"]}
    executable = os.getenv("PLAYWRIGHT_CHROMIUM_EXECUTABLE", "").strip()
    if executable:
        launch_options["executable_path"] = executable
    browser = playwright.chromium.launch(**launch_options)

    page = browser.new_page(viewport={"width": 1440, "height": 900})
    page.set_content(html)
    install_stubs(page, proof)
    page.add_script_tag(content=js)
    page.wait_for_function("document.querySelector('#webmcpStatus')?.textContent === 'REGISTERED'")
    page.click("#compareCoverage")
    page.wait_for_function("document.querySelectorAll('#revisionGrid .revisionCard').length === 3")
    page.click("#findCounterexample")
    page.wait_for_function("document.querySelector('#candidateId')?.textContent.includes('unsafe-prefix-01')")
    page.click("#minimizeCounterexample")
    page.wait_for_function("document.querySelector('#minimizedSource')?.textContent.includes('def can_read')")
    run_remediation(page)
    page.click("#verifyHumanProof")
    page.wait_for_function("document.querySelector('#humanProofStatus')?.textContent === 'VERIFIED BY HUMAN'")
    assert page.locator("#currentVerdict").inner_text() == "NO_GO"

    metrics = page.evaluate(
        """
        () => ({
          registeredTools: window.__registeredTools.length,
          webmcpStatus: document.querySelector('#webmcpStatus').textContent,
          verdict: document.querySelector('#currentVerdict').textContent,
          humanProofStatus: document.querySelector('#humanProofStatus').textContent,
          authorityText: document.querySelector('#trustStrip').innerText,
          timelineEvents: document.querySelectorAll('#agentTimeline li').length,
          revisionCards: document.querySelectorAll('#revisionGrid .revisionCard').length,
          body: document.body.innerText,
          width: document.documentElement.scrollWidth,
          viewportWidth: innerWidth,
        })
        """
    )
    assert metrics["registeredTools"] == len(catalog["tools"]), metrics
    assert metrics["webmcpStatus"] == "REGISTERED", metrics
    assert metrics["verdict"] == "NO_GO", metrics
    assert metrics["humanProofStatus"] == "VERIFIED BY HUMAN", metrics
    assert "NO RELEASE AUTHORITY" in metrics["authorityText"], metrics
    assert metrics["revisionCards"] == 3, metrics
    assert metrics["timelineEvents"] >= 6, metrics
    assert "0 observed escapes is scoped" in metrics["body"], metrics
    assert metrics["width"] <= metrics["viewportWidth"], metrics
    page.screenshot(path=str(OUTPUT), full_page=True)

    mismatch = browser.new_page(viewport={"width": 1280, "height": 800})
    mismatch.set_content(html)
    install_stubs(mismatch, {**proof, "source_sha256": "0" * 64})
    mismatch.add_script_tag(content=js)
    run_remediation(mismatch)
    mismatch.click("#verifyHumanProof")
    mismatch.wait_for_function("document.querySelector('#humanProofStatus')?.textContent === 'VERIFICATION FAILED'")
    assert "source" in mismatch.locator("#humanProofDetail").inner_text().lower()
    assert mismatch.locator("#currentVerdict").inner_text() == "NO_GO"

    unavailable = browser.new_page(viewport={"width": 1280, "height": 800})
    unavailable.set_content(html)
    unavailable.evaluate(
        """
        ([catalog, release, trust, comparisons]) => {
          window.fetch = async (url) => {
            url=String(url);
            let payload = url.endsWith('/tools') ? catalog : url.endsWith('/release') ? release : url.endsWith('/trust-boundary') ? trust : comparisons['cross-tenant'];
            return {ok:true,status:200,json:async()=>payload};
          };
        }
        """,
        [catalog, release, trust, comparisons],
    )
    unavailable.add_script_tag(content=js)
    unavailable.wait_for_function("document.querySelector('#webmcpStatus')?.textContent === 'UNAVAILABLE'")
    assert unavailable.locator("#currentVerdict").inner_text() == "NO_GO"
    assert unavailable.locator("#humanProofCard").get_attribute("hidden") is not None
    assert "Human controls remain available" in unavailable.locator("body").inner_text()

    browser.close()

print(json.dumps({**metrics, "screenshot": str(OUTPUT)}))
