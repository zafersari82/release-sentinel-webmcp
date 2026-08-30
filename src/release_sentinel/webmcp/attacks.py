from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

from release_sentinel.agents.advisory import compromised_agent_simulation
from release_sentinel.domain.release import ReleaseRequest
from release_sentinel.release.gatekeeper import A2AGatekeeperClient, gatekeeper_from_env
from release_sentinel.webmcp.demo_runtime import signed_fixture


def run_remote_attack(attack_name: str) -> dict[str, Any]:
    release_id = "webmcp-judge-attack-current"
    current = signed_fixture("vulnerable", release_id)
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
        signed["bundle"]["authority"] = "ORGANIZATION_POLICY"
        mutation = "UNTRUSTED_FIELD_INJECTED"
    elif attack_name == "replay_previous_go":
        previous = signed_fixture("fixed", "webmcp-previous-go-release")
        signed = deepcopy(previous["signed_evidence_bundle"])
        mutation = "VALID_OLD_GO_BUNDLE_REPLAYED"
    elif attack_name in {"forged_repo_go", "prompt_injection"}:
        mutation = "UNTRUSTED_REPOSITORY_DATA_ONLY"
    elif attack_name == "force_agents_go":
        mutation = "AGENT_OPINIONS_ONLY"

    gate = gatekeeper_from_env(require_remote=True)
    if not isinstance(gate, A2AGatekeeperClient):
        raise RuntimeError("remote A2A Gatekeeper is required")
    raw = gate.attack_raw(
        release_id=release_id,
        source_sha256=source_sha,
        policy_sha256=policy_sha,
        signed_evidence_bundle=signed,
        agent_opinions=opinions,
    )
    accepted = bool(raw.get("accepted"))
    final_verdict = raw.get("decision") if accepted else None
    attack_blocked = (not accepted) or final_verdict == "NO_GO"
    result_code = raw.get("rejection_code") or (
        "IGNORED_NOT_IN_TRUST_SCHEMA" if attack_name == "forge_authority" else "VERDICT_UNCHANGED"
    )
    return {
        "attack": attack_name,
        "mutation": mutation,
        "payload_reached_gatekeeper": True,
        "gatekeeper_accepted_evidence": accepted,
        "rejection_code": raw.get("rejection_code"),
        "result_code": result_code,
        "final_verdict": final_verdict,
        "attack_blocked": attack_blocked,
        "agent_go_count": sum(1 for item in opinions if item.get("vote") == "GO"),
        "agent_count": len(opinions),
        "agent_influence": raw.get("agent_influence", 0),
        "evidence_verified": raw.get("evidence_verified", False),
        "gatekeeper": raw,
    }
