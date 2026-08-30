import pytest

from release_sentinel.parity.engine import ParityError, compare
from release_sentinel.parity.model import Observation, ParityCategory, ParityScenario


def scenarios():
    categories = (
        ParityCategory.PUBLIC_API,
        ParityCategory.AUTHORIZATION,
        ParityCategory.DATABASE_BEHAVIOR,
        ParityCategory.ERROR_CONTRACTS,
        ParityCategory.EDGE_CASES,
    )
    return [
        ParityScenario(chr(ord("a") + index), category)
        for index, category in enumerate(categories)
    ]


def observations(items):
    return {
        scenario.scenario_id: Observation.from_payload(200, {"id": scenario.scenario_id})
        for scenario in items
    }


def test_perfect_parity_allows_cutover():
    suite = scenarios()
    observed = observations(suite)

    result = compare(suite, observed, observed)

    assert result.score == 1
    assert result.cutover_allowed


def test_one_blocker_blocks_even_high_score():
    suite = scenarios()
    legacy = observations(suite)
    candidate = observations(suite)
    candidate["e"] = Observation.from_payload(200, {"id": "changed"})

    result = compare(suite, legacy, candidate)

    assert result.score == 0.8
    assert not result.cutover_allowed
    assert len(result.blockers) == 1


def test_missing_category_rejected():
    suite = scenarios()[:-1]
    observed = observations(suite)

    with pytest.raises(ParityError):
        compare(suite, observed, observed)


def test_raw_payload_not_present_in_result():
    suite = scenarios()
    observed = observations(suite)

    result = compare(suite, observed, observed)

    assert "body" not in str(result.cases[0]).lower()
