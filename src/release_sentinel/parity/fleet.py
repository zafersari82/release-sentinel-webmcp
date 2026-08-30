from __future__ import annotations

from dataclasses import dataclass

from release_sentinel.parity.model import ParityScenario


class FleetError(ValueError):
    pass


@dataclass(frozen=True)
class FleetBudget:
    max_scenarios: int = 2000
    max_tasks: int = 100
    max_network_requests: int = 4000


@dataclass(frozen=True)
class FleetPlan:
    tasks: tuple[tuple[str, ...], ...]
    scenario_count: int
    network_request_count: int


def plan_fleet(scenarios: list[ParityScenario], task_count: int, budget: FleetBudget = FleetBudget()) -> FleetPlan:
    if not scenarios:
        raise FleetError("fleet requires scenarios")
    if any(s.method.upper() not in {"GET", "HEAD", "OPTIONS"} for s in scenarios):
        raise FleetError("async parity fleet is read-only; mutation probes use the isolated synchronous path")
    if len(scenarios) > budget.max_scenarios:
        raise FleetError("scenario budget exceeded")
    task_count = min(task_count, len(scenarios))
    if task_count < 1 or task_count > budget.max_tasks:
        raise FleetError("task budget exceeded")
    requests = len(scenarios) * 2
    if requests > budget.max_network_requests:
        raise FleetError("network request budget exceeded")
    shards: list[list[str]] = [[] for _ in range(task_count)]
    for idx, scenario in enumerate(scenarios):
        shards[idx % task_count].append(scenario.scenario_id)
    flattened = [item for shard in shards for item in shard]
    if len(flattened) != len(set(flattened)) or set(flattened) != {s.scenario_id for s in scenarios}:
        raise FleetError("shard coverage invariant failed")
    return FleetPlan(tuple(tuple(s) for s in shards), len(scenarios), requests)
