import pytest

from release_sentinel.parity.model import ParityCategory, ParityScenario
from release_sentinel.parity.probe import (
    ProbeError,
    TargetMode,
    TargetProfile,
    run_dual_probe,
    validate_target,
)


def scenarios(method="GET"):
    return [ParityScenario("x", ParityCategory.PUBLIC_API, True, method, "/x")]


def transport(profile, _scenario):
    return 200, {"profile": profile.profile_id}


def test_metadata_target_blocked():
    target = TargetProfile("x", "http://169.254.169.254", TargetMode.SANDBOX)

    with pytest.raises(ProbeError):
        validate_target(target, allow_local=True)


def test_mutation_requires_two_sandboxes():
    legacy = TargetProfile("a", "https://a.example", TargetMode.PRODUCTION_READONLY)
    candidate = TargetProfile("b", "https://b.example", TargetMode.SANDBOX)

    with pytest.raises(ProbeError):
        run_dual_probe(scenarios("POST"), legacy, candidate, transport)


def test_two_sandboxes_can_mutate():
    legacy = TargetProfile("a", "https://a.example", TargetMode.SANDBOX)
    candidate = TargetProfile("b", "https://b.example", TargetMode.SANDBOX)

    legacy_results, candidate_results = run_dual_probe(
        scenarios("POST"), legacy, candidate, transport
    )

    assert set(legacy_results) == {"x"}
    assert set(candidate_results) == {"x"}


def test_transport_failure_is_fail_closed():
    legacy = TargetProfile("a", "https://a.example", TargetMode.SANDBOX)
    candidate = TargetProfile("b", "https://b.example", TargetMode.SANDBOX)

    def failing_transport(*_):
        raise OSError("down")

    with pytest.raises(ProbeError):
        run_dual_probe(scenarios(), legacy, candidate, failing_transport)
