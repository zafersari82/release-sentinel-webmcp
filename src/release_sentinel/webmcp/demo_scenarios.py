from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class DemoReleaseId(str, Enum):
    CROSS_TENANT = "demo-cross-tenant"
    PATH_TRAVERSAL = "demo-path-traversal"
    EVIDENCE_TAMPER = "demo-evidence-tamper"


class ProofId(str, Enum):
    CURRENT = "demo-current"
    CROSS_TENANT_FIXED = "demo-cross-tenant-fixed"
    PATH_TRAVERSAL_FIXED = "demo-path-traversal-fixed"
    EVIDENCE_TAMPER_FIXED = "demo-evidence-tamper-fixed"


@dataclass(frozen=True)
class DemoScenario:
    release_id: DemoReleaseId
    label: str
    vulnerable_fixture: str
    fixed_fixture: str
    fixed_proof_id: ProofId


_SCENARIOS: dict[DemoReleaseId, DemoScenario] = {
    DemoReleaseId.CROSS_TENANT: DemoScenario(
        release_id=DemoReleaseId.CROSS_TENANT,
        label="Cross-tenant authorization",
        vulnerable_fixture="cross_tenant_vulnerable",
        fixed_fixture="cross_tenant_fixed",
        fixed_proof_id=ProofId.CROSS_TENANT_FIXED,
    ),
    DemoReleaseId.PATH_TRAVERSAL: DemoScenario(
        release_id=DemoReleaseId.PATH_TRAVERSAL,
        label="Path traversal containment",
        vulnerable_fixture="path_traversal_vulnerable",
        fixed_fixture="path_traversal_fixed",
        fixed_proof_id=ProofId.PATH_TRAVERSAL_FIXED,
    ),
    DemoReleaseId.EVIDENCE_TAMPER: DemoScenario(
        release_id=DemoReleaseId.EVIDENCE_TAMPER,
        label="Evidence digest binding",
        vulnerable_fixture="evidence_tamper_vulnerable",
        fixed_fixture="evidence_tamper_fixed",
        fixed_proof_id=ProofId.EVIDENCE_TAMPER_FIXED,
    ),
}

_PROOF_TO_SCENARIO: dict[ProofId, DemoScenario] = {
    scenario.fixed_proof_id: scenario for scenario in _SCENARIOS.values()
}


def supported_release_ids() -> tuple[str, ...]:
    return tuple(item.value for item in DemoReleaseId)


def supported_proof_ids() -> tuple[str, ...]:
    return tuple(item.value for item in ProofId)


def get_scenario(release_id: DemoReleaseId | str) -> DemoScenario:
    try:
        bounded_id = release_id if isinstance(release_id, DemoReleaseId) else DemoReleaseId(release_id)
    except ValueError as exc:
        raise KeyError(str(release_id)) from exc
    return _SCENARIOS[bounded_id]


def fixture_for_proof(proof_id: ProofId | str) -> tuple[str, DemoScenario | None]:
    try:
        bounded_id = proof_id if isinstance(proof_id, ProofId) else ProofId(proof_id)
    except ValueError as exc:
        raise KeyError(str(proof_id)) from exc
    if bounded_id is ProofId.CURRENT:
        return _SCENARIOS[DemoReleaseId.CROSS_TENANT].vulnerable_fixture, None
    scenario = _PROOF_TO_SCENARIO.get(bounded_id)
    if scenario is None:
        raise KeyError(bounded_id.value)
    return scenario.fixed_fixture, scenario
