from __future__ import annotations

from release_sentinel.parity.model import Observation, ParityCaseResult, ParityMatrix, ParityScenario


REQUIRED_CATEGORIES = {
    "PUBLIC_API", "AUTHORIZATION", "DATABASE_BEHAVIOR", "ERROR_CONTRACTS", "EDGE_CASES"
}


class ParityError(ValueError):
    pass


def compare(scenarios: list[ParityScenario], legacy: dict[str, Observation], candidate: dict[str, Observation]) -> ParityMatrix:
    categories = {s.category.value for s in scenarios}
    missing = REQUIRED_CATEGORIES - categories
    if missing:
        raise ParityError(f"parity spec missing required categories: {sorted(missing)}")
    cases: list[ParityCaseResult] = []
    for scenario in scenarios:
        if scenario.scenario_id not in legacy or scenario.scenario_id not in candidate:
            raise ParityError(f"missing observation for {scenario.scenario_id}")
        left, right = legacy[scenario.scenario_id], candidate[scenario.scenario_id]
        mismatch: list[str] = []
        if left.status != right.status:
            mismatch.append("status")
        if left.normalized_sha256 != right.normalized_sha256:
            mismatch.append("body_digest")
        cases.append(ParityCaseResult(
            scenario.scenario_id,
            scenario.category,
            scenario.blocking,
            not mismatch,
            left.normalized_sha256,
            right.normalized_sha256,
            tuple(mismatch),
        ))
    return ParityMatrix(tuple(cases))
