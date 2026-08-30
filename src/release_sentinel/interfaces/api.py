from __future__ import annotations

import json
import os
from copy import deepcopy
from importlib.resources import files
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from release_sentinel import __version__
from release_sentinel.agents.advisory import compromised_agent_simulation, deterministic_advisory
from release_sentinel.agents.registry import default_agent_registry
from release_sentinel.domain.release import ReleaseRequest
from release_sentinel.execution.demo import BundledDemoExecutor
from release_sentinel.parity.engine import compare
from release_sentinel.parity.model import Observation, ParityCategory, ParityScenario
from release_sentinel.policy.model import build_policy
from release_sentinel.release.engine import ReleaseEngine
from release_sentinel.release.gatekeeper import A2AGatekeeperClient, LocalDeterministicGatekeeper, gatekeeper_from_env
from release_sentinel.infrastructure.cloudproof import run_cloud_release_proof, runtime_proof
from release_sentinel.infrastructure.attestor import EvidenceAttestorClient
from release_sentinel.infrastructure.settings import CloudSettings
from release_sentinel.operations.attestation import build_evidence_bundle, sign_evidence_bundle, demo_signer_from_env
from release_sentinel.infrastructure.adk_smoke import run_adk_gemini_smoke
from release_sentinel.interfaces.control_center import build_control_center_contract
from release_sentinel.interfaces.webmcp_api import router as webmcp_router

app = FastAPI(title="Release Sentinel", version=__version__)
app.include_router(webmcp_router)
STATIC = Path(__file__).with_name("static")
app.mount("/static", StaticFiles(directory=STATIC), name="static")


def _fixture() -> tuple[Path, object, str]:
    base = Path(str(files("release_sentinel"))) / "demo_fixture"
    policy = build_policy(json.loads((base / "organization-policy.json").read_text()))
    expected = (base / "repository_vulnerable.sha256").read_text().strip()
    return base, policy, expected


def _demo_report(*, compromised: bool = False):
    base, policy, expected = _fixture()
    advisor = compromised_agent_simulation if compromised else deterministic_advisory
    return ReleaseEngine(
        BundledDemoExecutor(expected),
        advisor=advisor,
        gatekeeper=LocalDeterministicGatekeeper(),
    ).evaluate(ReleaseRequest("demo-release", base / "repository_vulnerable"), policy)




def _signed_demo_fixture(fixture_name: str, release_id: str) -> dict:
    base = Path(str(files("release_sentinel"))) / "demo_fixture"
    policy = build_policy(json.loads((base / "organization-policy.json").read_text()))
    directory = "repository_vulnerable" if fixture_name == "vulnerable" else "repository_fixed"
    hash_file = "repository_vulnerable.sha256" if fixture_name == "vulnerable" else "repository_fixed.sha256"
    source_sha256 = (base / hash_file).read_text().strip()
    report = ReleaseEngine(
        BundledDemoExecutor(source_sha256), advisor=None, gatekeeper=LocalDeterministicGatekeeper()
    ).evaluate(ReleaseRequest(release_id, base / directory), policy)
    signed = sign_evidence_bundle(build_evidence_bundle(report, source_sha256=source_sha256), demo_signer_from_env())
    return {
        "source_sha256": source_sha256,
        "policy_sha256": policy.sha256,
        "report": report.to_dict(),
        "signed_evidence_bundle": signed.to_dict(),
    }


def _attested_fixture(fixture_name: str, release_id: str) -> dict:
    settings = CloudSettings.from_env()
    if settings.attestor_url:
        return EvidenceAttestorClient(
            settings.attestor_url, audience=settings.attestor_audience or settings.attestor_url
        ).attest_fixture(fixture_name, release_id=release_id)
    return _signed_demo_fixture(fixture_name, release_id)


def _remote_gatekeeper() -> A2AGatekeeperClient:
    gate = gatekeeper_from_env(require_remote=True)
    if not isinstance(gate, A2AGatekeeperClient):
        raise RuntimeError("remote A2A gatekeeper is required")
    return gate


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/arena")
def arena():
    return FileResponse(STATIC / "arena.html")


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


@app.get("/v1/trust-model")
def trust_model() -> dict:
    return {
        "repository_text_authority": "NONE",
        "blocking_authorities": ["PLATFORM", "ORGANIZATION_POLICY"],
        "model_authority": "ADVISORY_ONLY",
        "decision_authority": "DETERMINISTIC_GATEKEEPER",
        "production_gatekeeper": "GO_A2A_SERVICE",
    }




@app.get("/v1/agents")
def agent_registry() -> dict:
    registry = default_agent_registry()
    agents = registry.snapshot()
    advisory = sum(1 for item in agents if item["decision_authority"] == "ADVISORY")
    deterministic = sum(1 for item in agents if item["decision_authority"] == "DETERMINISTIC")
    return {
        "schema": "release-sentinel.agent-registry.v1",
        "agents": agents,
        "fleet": {"advisory": advisory, "deterministic": deterministic},
        "authority": {"ADVISORY": advisory, "DETERMINISTIC": deterministic},
    }


@app.get("/v1/control-center")
def control_center() -> dict:
    return build_control_center_contract(_demo_report().to_dict())


@app.get("/v1/demo/release")
def demo_release() -> dict:
    return _demo_report().to_dict()


@app.get("/v1/demo/verdict-independence")
def verdict_independence() -> dict:
    baseline = _demo_report(compromised=False).to_dict()
    compromised = _demo_report(compromised=True).to_dict()
    opinions = compromised.get("advisory", {}).get("opinions", [])
    all_go = bool(opinions) and all(item.get("vote") == "GO" for item in opinions)
    result = {
        "proof": "VERDICT_INDEPENDENCE",
        "baseline_decision": baseline["decision"],
        "compromised_decision": compromised["decision"],
        "agent_votes": opinions,
        "agents_all_go": all_go,
        "agent_go_count": sum(1 for item in opinions if item.get("vote") == "GO"),
        "agent_count": len(opinions),
        "final_verdict": compromised["decision"],
        "gatekeeper": compromised.get("gatekeeper"),
        "unchanged": baseline["decision"] == compromised["decision"],
        "signed_evidence_demo_available": bool(os.getenv("RELEASE_SENTINEL_GATEKEEPER_URL")) and bool(os.getenv("RELEASE_SENTINEL_DEMO_SIGNING_KEY") or os.getenv("RELEASE_SENTINEL_ATTESTOR_URL")),
    }
    if result["signed_evidence_demo_available"]:
        try:
            release_id = "demo-verdict-independence-signed"
            attested = _attested_fixture("vulnerable", release_id)
            signed = attested["signed_evidence_bundle"]
            source_sha = attested["source_sha256"]
            policy_sha = signed["bundle"]["policy_sha256"]
            verdict = _remote_gatekeeper().decide_attested(
                release_id=release_id, source_sha256=source_sha, policy_sha256=policy_sha,
                signed_evidence_bundle=signed, agent_opinions=opinions,
            )
            result["final_verdict"] = verdict.decision.value
            result["gatekeeper"] = verdict.to_dict()
            result["signed_evidence_verified"] = True
        except Exception as exc:
            result["signed_evidence_verified"] = False
            result["signed_evidence_error"] = exc.__class__.__name__
    return result


@app.get("/v1/demo/repository-attack")
def repository_attack() -> dict:
    base, _, _ = _fixture()
    root = base / "repository_vulnerable"
    injection = (root / "README.md").exists()
    forged = (root / "forged-claim.json").exists()
    return {
        "prompt_injection_fixture_present": injection,
        "forged_claim_present": forged,
        "repository_claim_authority": "NONE",
        "gatekeeper_accepts_repository_claims": False,
        "model_armor": {"role": "DEFENSE_IN_DEPTH", "live_in_local_demo": False},
    }


@app.post("/v1/demo/attack-gate/{attack_name}")
def attack_gate(attack_name: str) -> dict:
    allowed = {
        "force_agents_go", "forged_repo_go", "prompt_injection", "downgrade_severity",
        "delete_blocker", "forge_authority", "replay_previous_go", "tamper_evidence_digest",
    }
    if attack_name not in allowed:
        raise HTTPException(status_code=404, detail="unknown attack")
    release_id = "judge-attack-current"
    current = _attested_fixture("vulnerable", release_id)
    signed = deepcopy(current["signed_evidence_bundle"])
    source_sha = current["source_sha256"]
    policy_sha = signed["bundle"]["policy_sha256"]
    advisor = compromised_agent_simulation(ReleaseRequest(release_id, Path(".")), [])
    opinions = list(advisor.get("opinions") or [])
    mutation = "NONE"

    if attack_name == "downgrade_severity":
        signed["bundle"]["results"][0]["severity"] = "INFO"
        mutation = "SIGNED_PAYLOAD_MUTATED"
    elif attack_name == "delete_blocker":
        signed["bundle"]["results"] = []
        mutation = "SIGNED_PAYLOAD_MUTATED"
    elif attack_name == "tamper_evidence_digest":
        signed["bundle"]["results"][0]["evidence_digest_sha256"] = "0" * 64
        mutation = "SIGNED_PAYLOAD_MUTATED"
    elif attack_name == "forge_authority":
        # Authority is intentionally not part of the trust schema. Unknown caller fields
        # reach the Gatekeeper but cannot create authority.
        signed["bundle"]["authority"] = "ORGANIZATION_POLICY"
        mutation = "UNTRUSTED_FIELD_INJECTED"
    elif attack_name == "replay_previous_go":
        previous = _attested_fixture("fixed", "previous-go-release")
        signed = deepcopy(previous["signed_evidence_bundle"])
        mutation = "VALID_OLD_GO_BUNDLE_REPLAYED"
    elif attack_name in {"forged_repo_go", "prompt_injection"}:
        mutation = "UNTRUSTED_REPOSITORY_DATA_ONLY"
    elif attack_name == "force_agents_go":
        mutation = "AGENT_OPINIONS_ONLY"

    raw = _remote_gatekeeper().attack_raw(
        release_id=release_id, source_sha256=source_sha, policy_sha256=policy_sha,
        signed_evidence_bundle=signed, agent_opinions=opinions,
    )
    accepted = bool(raw.get("accepted"))
    final_verdict = raw.get("decision") if accepted else None
    attack_blocked = (not accepted) or final_verdict == "NO_GO"
    explanation = raw.get("rejection_code") or ("IGNORED_NOT_IN_TRUST_SCHEMA" if attack_name == "forge_authority" else "VERDICT_UNCHANGED")
    return {
        "attack": attack_name,
        "mutation": mutation,
        "payload_reached_gatekeeper": True,
        "gatekeeper_accepted_evidence": accepted,
        "rejection_code": raw.get("rejection_code"),
        "result_code": explanation,
        "final_verdict": final_verdict,
        "attack_blocked": attack_blocked,
        "agent_go_count": sum(1 for item in opinions if item.get("vote") == "GO"),
        "agent_count": len(opinions),
        "agent_influence": raw.get("agent_influence", 0),
        "evidence_verified": raw.get("evidence_verified", False),
        "gatekeeper": raw,
    }


@app.get("/v1/demo/parity")
def demo_parity() -> dict:
    scenarios=[
      ParityScenario("api",ParityCategory.PUBLIC_API),
      ParityScenario("auth",ParityCategory.AUTHORIZATION),
      ParityScenario("db",ParityCategory.DATABASE_BEHAVIOR),
      ParityScenario("errors",ParityCategory.ERROR_CONTRACTS),
      ParityScenario("edge",ParityCategory.EDGE_CASES),
    ]
    legacy={s.scenario_id:Observation.from_payload(200,{"ok":True,"id":s.scenario_id}) for s in scenarios}
    candidate=dict(legacy)
    candidate["auth"]=Observation.from_payload(200,{"ok":True,"id":"auth","authorization":"regressed"})
    matrix=compare(scenarios,legacy,candidate)
    return {"score":matrix.score,"blockers":len(matrix.blockers),"cutover_allowed":matrix.cutover_allowed,"cases":[{"id":c.scenario_id,"category":c.category.value,"matched":c.matched,"blocking":c.blocking} for c in matrix.cases]}


@app.get("/v1/cloud-proof/runtime")
def cloud_runtime_proof() -> dict:
    return runtime_proof()


@app.post("/v1/cloud-proof/adk-smoke")
async def cloud_adk_smoke() -> dict:
    try:
        return await run_adk_gemini_smoke()
    except Exception as exc:
        raise HTTPException(status_code=503, detail={"adk_real_call": False, "error": exc.__class__.__name__, "message": str(exc)}) from exc


@app.post("/v1/cloud-proof/release/{fixture_name}")
def cloud_release_proof(fixture_name: str) -> dict:
    if fixture_name not in {"vulnerable", "fixed"}:
        raise HTTPException(status_code=404, detail="unknown bundled fixture")
    try:
        return run_cloud_release_proof(fixture_name)
    except Exception as exc:
        raise HTTPException(status_code=503, detail={"cloud_proof": False, "error": exc.__class__.__name__, "message": str(exc)}) from exc
