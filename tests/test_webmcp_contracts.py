from __future__ import annotations

import pytest
from pydantic import ValidationError

from release_sentinel.webmcp.contracts import (
    AttackName,
    AttackRequest,
    CapabilityClass,
    ChallengeId,
    CoverageRequest,
    PolicyRevision,
    TOOL_DEFINITIONS,
    tool_catalog,
)

EXPECTED = {
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

FORBIDDEN = {
    "set_verdict",
    "force_go",
    "override_gatekeeper",
    "disable_policy",
    "edit_signed_evidence",
    "replace_oracle_result",
    "approve_own_remediation",
    "reuse_old_go_for_new_source",
    "execute",
    "shell",
    "run_command",
}


def test_exact_webmcp_tool_inventory_has_no_authority_escape():
    names = {tool.name for tool in TOOL_DEFINITIONS}
    assert names == EXPECTED
    assert names.isdisjoint(FORBIDDEN)
    assert all(tool.capability in set(CapabilityClass) for tool in TOOL_DEFINITIONS)
    assert {row["name"] for row in tool_catalog()} == EXPECTED


def test_tool_catalog_is_machine_readable_and_bounded():
    rows = tool_catalog()
    assert all(row["input_schema"]["type"] == "object" for row in rows)
    assert all(row["capability"] in {"READ", "CHALLENGE", "PROPOSE"} for row in rows)
    assert not any("command" in row["input_schema"].get("properties", {}) for row in rows)
    assert not any("action" in row["input_schema"].get("properties", {}) for row in rows)


def test_attack_and_coverage_inputs_are_strict_bounded_enums():
    attack = AttackRequest(attack_name=AttackName.FORCE_AGENTS_GO)
    assert attack.attack_name.value == "force_agents_go"
    coverage = CoverageRequest(challenge=ChallengeId.CROSS_TENANT, revision=PolicyRevision.REV3)
    assert coverage.revision == 3

    with pytest.raises(ValidationError):
        AttackRequest(attack_name="force_go")
    with pytest.raises(ValidationError):
        CoverageRequest(challenge="arbitrary", revision=3)
    with pytest.raises(ValidationError):
        CoverageRequest(challenge="cross-tenant", revision=4)
    with pytest.raises(ValidationError):
        AttackRequest(attack_name="force_agents_go", command="rm -rf /")
