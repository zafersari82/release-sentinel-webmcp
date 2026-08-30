from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, IntEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from release_sentinel.webmcp.demo_scenarios import DemoReleaseId, ProofId


class CapabilityClass(str, Enum):
    READ = "READ"
    CHALLENGE = "CHALLENGE"
    PROPOSE = "PROPOSE"


class ChallengeId(str, Enum):
    CROSS_TENANT = "cross-tenant"
    PATH_TRAVERSAL = "path-traversal"


class PolicyRevision(IntEnum):
    REV1 = 1
    REV2 = 2
    REV3 = 3


class AttackName(str, Enum):
    FORCE_AGENTS_GO = "force_agents_go"
    FORGED_REPO_GO = "forged_repo_go"
    PROMPT_INJECTION = "prompt_injection"
    DOWNGRADE_SEVERITY = "downgrade_severity"
    DELETE_BLOCKER = "delete_blocker"
    FORGE_AUTHORITY = "forge_authority"
    REPLAY_PREVIOUS_GO = "replay_previous_go"
    TAMPER_EVIDENCE_DIGEST = "tamper_evidence_digest"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EmptyRequest(StrictModel):
    pass


class AttackRequest(StrictModel):
    attack_name: AttackName


class CoverageRequest(StrictModel):
    challenge: ChallengeId
    revision: PolicyRevision = PolicyRevision.REV3


class CompareRequest(StrictModel):
    challenge: ChallengeId


class CounterexampleRequest(StrictModel):
    challenge: ChallengeId
    revision: PolicyRevision = PolicyRevision.REV1


class MinimizeRequest(StrictModel):
    challenge: ChallengeId
    candidate_id: str = Field(min_length=1, max_length=128)


class ProposalRequest(StrictModel):
    demo_release_id: DemoReleaseId = DemoReleaseId.CROSS_TENANT


class RebuildRequest(StrictModel):
    proposal_id: str = Field(min_length=1, max_length=128)
    proposal_digest: str = Field(pattern=r"^[0-9a-f]{64}$")


class ReverifyRequest(StrictModel):
    candidate_id: str = Field(min_length=1, max_length=128)
    new_source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class VerifyProofRequest(StrictModel):
    proof_id: ProofId = ProofId.CURRENT


def _inline_local_refs(node: Any, defs: dict[str, Any]) -> Any:
    """Expand only Pydantic local definitions into a self-contained schema."""
    if isinstance(node, list):
        return [_inline_local_refs(item, defs) for item in node]
    if not isinstance(node, dict):
        return node

    ref = node.get("$ref")
    if ref is not None:
        prefix = "#/$defs/"
        if not isinstance(ref, str) or not ref.startswith(prefix):
            raise ValueError(f"unsupported JSON Schema reference: {ref!r}")
        definition_name = ref[len(prefix):]
        if definition_name not in defs:
            raise ValueError(f"missing JSON Schema definition: {definition_name}")
        resolved = _inline_local_refs(defs[definition_name], defs)
        siblings = {
            key: _inline_local_refs(value, defs)
            for key, value in node.items()
            if key != "$ref"
        }
        return {**resolved, **siblings}

    return {
        key: _inline_local_refs(value, defs)
        for key, value in node.items()
        if key != "$defs"
    }


def inline_json_schema(schema: dict[str, Any]) -> dict[str, Any]:
    """Inline local definitions so WebMCP clients see bounded values directly."""
    return _inline_local_refs(schema, schema.get("$defs", {}))


@dataclass(frozen=True)
class ToolDefinition:
    name: str
    capability: CapabilityClass
    description: str
    request_model: type[BaseModel]

    @property
    def input_schema(self) -> dict[str, Any]:
        return inline_json_schema(self.request_model.model_json_schema())


def _tool(name: str, capability: CapabilityClass, description: str, request_model: type[BaseModel]) -> ToolDefinition:
    return ToolDefinition(name=name, capability=capability, description=description, request_model=request_model)


TOOL_DEFINITIONS: tuple[ToolDefinition, ...] = (
    _tool(
        "inspect_release",
        CapabilityClass.READ,
        "START HERE. Inspect the release currently under review, including its verdict, source and policy hashes, and blocking findings.",
        EmptyRequest,
    ),
    _tool(
        "inspect_trust_boundary",
        CapabilityClass.READ,
        "Inspect which components are advisory and which deterministic component owns final release authority. WebMCP never receives approval authority.",
        EmptyRequest,
    ),
    _tool(
        "run_attack",
        CapabilityClass.CHALLENGE,
        "Run one predefined bounded attack against the release gate. Use it to test whether advisory votes, forgery, replay, or evidence tampering can create authority; then continue with find_counterexamples for the repair path.",
        AttackRequest,
    ),
    _tool(
        "run_attack_suite",
        CapabilityClass.CHALLENGE,
        "Run the complete bounded attack campaign through the existing deterministic Gatekeeper path. This capability reports containment evidence but cannot issue or override a verdict; continue with compare_gate_revisions or find_counterexamples for deeper analysis.",
        EmptyRequest,
    ),
    _tool(
        "inspect_coverage",
        CapabilityClass.READ,
        "Inspect one policy revision on a fixed benchmark corpus, including observed escapes and overblocks. Use compare_gate_revisions for the three-revision tradeoff in one call.",
        CoverageRequest,
    ),
    _tool(
        "compare_gate_revisions",
        CapabilityClass.READ,
        "Compare revisions 1, 2, and 3 on the same benchmark scope, with escapes and overblocks side by side. Zero observed escapes remains scoped to the named corpus.",
        CompareRequest,
    ),
    _tool(
        "find_counterexamples",
        CapabilityClass.CHALLENGE,
        "Repair step 1. List package-owned cases where the production gate passed an input that the reference oracle marked unsafe. Pass a returned candidate_id to minimize_counterexample.",
        CounterexampleRequest,
    ),
    _tool(
        "minimize_counterexample",
        CapabilityClass.CHALLENGE,
        "Repair step 2. Minimize a package-owned observed escape identified by find_counterexamples. After the reproducer is minimized, call propose_remediation.",
        MinimizeRequest,
    ),
    _tool(
        "propose_remediation",
        CapabilityClass.PROPOSE,
        "Repair step 3. Choose one package-owned demo release and request its bounded server-owned remediation proposal. It returns proposal_id and proposal_digest for rebuild_candidate and does not change any verdict.",
        ProposalRequest,
    ),
    _tool(
        "rebuild_candidate",
        CapabilityClass.PROPOSE,
        "Repair step 4. Rebuild from a server-generated proposal. The new source hash inherits no verdict and remains NOT_YET_REVERIFIED; pass candidate_id and new_source_sha256 to reverify_candidate.",
        RebuildRequest,
    ),
    _tool(
        "reverify_candidate",
        CapabilityClass.PROPOSE,
        "Repair step 5. Request fresh deterministic verification for a rebuilt candidate. The Gatekeeper computes the verdict from signed evidence; WebMCP requests the decision but never issues it.",
        ReverifyRequest,
    ),
    _tool(
        "verify_proof",
        CapabilityClass.READ,
        "Verify a supported proof identity by recomputing evidence integrity and source-context binding. Use this to show that a verdict is backed by proof rather than agent assertion.",
        VerifyProofRequest,
    ),
)


_FORBIDDEN_TOOL_NAMES = {
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

if {tool.name for tool in TOOL_DEFINITIONS} & _FORBIDDEN_TOOL_NAMES:
    raise RuntimeError("WebMCP tool inventory contains a forbidden authority capability")


def tool_catalog() -> list[dict[str, Any]]:
    return [
        {
            "name": tool.name,
            "capability": tool.capability.value,
            "description": tool.description,
            "input_schema": tool.input_schema,
        }
        for tool in TOOL_DEFINITIONS
    ]
