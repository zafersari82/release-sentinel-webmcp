import pytest

from release_sentinel.parity.fleet import FleetBudget, FleetError, plan_fleet
from release_sentinel.parity.model import ParityCategory, ParityScenario


def scenarios(count=10, method="GET"):
    return [
        ParityScenario(f"s{index}", ParityCategory.PUBLIC_API, True, method, "/")
        for index in range(count)
    ]


def test_shards_cover_each_scenario_once():
    plan = plan_fleet(scenarios(), 3)
    assigned = [scenario_id for task in plan.tasks for scenario_id in task]

    assert len(assigned) == 10
    assert len(set(assigned)) == 10


def test_task_count_caps_at_scenario_count():
    assert len(plan_fleet(scenarios(3), 99).tasks) == 3


def test_mutation_rejected_from_async_fleet():
    with pytest.raises(FleetError):
        plan_fleet(scenarios(2, "POST"), 2)


def test_budget_rejects_large_suite():
    with pytest.raises(FleetError):
        plan_fleet(scenarios(5), 2, FleetBudget(max_scenarios=4))
