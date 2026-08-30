from release_sentinel.coverage.challenge import load_cross_tenant_challenge


def test_builtin_cross_tenant_challenge_is_versioned_and_scope_honest():
    challenge = load_cross_tenant_challenge()
    assert challenge.challenge_id == "cross-tenant-authorization"
    assert challenge.revision == 1
    assert challenge.payload["schema"] == "release-sentinel.coverage-challenge.v1"
    assert "tenant isolation" in challenge.payload["scope"]["tested"]
    assert "SQL injection" in challenge.payload["scope"]["not_tested"]
    assert len(challenge.sha256) == 64


def test_challenge_pins_the_narrow_production_approximation():
    challenge = load_cross_tenant_challenge()
    approximation = challenge.payload["production_approximation"]
    assert approximation == {
        "check": "auth-boundary",
        "requester_tenant": "tenant-a",
        "resource_tenant": "tenant-b",
        "expected": False,
    }
