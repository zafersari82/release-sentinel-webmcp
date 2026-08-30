from release_sentinel.coverage.models import OracleVerdict
from release_sentinel.coverage.oracle import CrossTenantOracle


def robust_fixed(requester_tenant, resource_tenant):
    if not isinstance(requester_tenant, str) or not isinstance(resource_tenant, str):
        return False
    if not requester_tenant or not resource_tenant:
        return False
    return requester_tenant == resource_tenant


def obvious_vulnerable(requester_tenant, resource_tenant):
    return True


def test_cross_tenant_oracle_accepts_qualified_fixed_implementation():
    result = CrossTenantOracle().evaluate_callable(robust_fixed)
    assert result.verdict is OracleVerdict.SAFE
    assert result.failed_vectors == ()
    assert result.total_vectors >= 10


def test_cross_tenant_oracle_rejects_obvious_vulnerable_implementation():
    result = CrossTenantOracle().evaluate_callable(obvious_vulnerable)
    assert result.verdict is OracleVerdict.UNSAFE
    assert result.failed_vectors
    assert any(item.category == "cross_tenant" for item in result.failed_vectors)


def test_oracle_distinguishes_case_whitespace_prefix_and_unicode_ids():
    oracle = CrossTenantOracle()
    categories = {item.category for item in oracle.vectors}
    assert {"case_distinct", "whitespace_distinct", "prefix_distinct", "unicode_distinct"} <= categories
    result = oracle.evaluate_callable(robust_fixed)
    assert result.verdict is OracleVerdict.SAFE


def test_oracle_requires_malformed_identifiers_to_be_denied():
    def accepts_empty(requester_tenant, resource_tenant):
        if requester_tenant == resource_tenant:
            return True
        return False

    result = CrossTenantOracle().evaluate_callable(accepts_empty)
    assert result.verdict is OracleVerdict.UNSAFE
    assert any(item.category == "malformed" for item in result.failed_vectors)


def test_oracle_qualification_requires_known_answers_and_kills_defined_mutants():
    result = CrossTenantOracle().qualify(
        fixed_callable=robust_fixed,
        vulnerable_callable=obvious_vulnerable,
    )
    assert result.passed is True
    assert result.fixed_verdict is OracleVerdict.SAFE
    assert result.vulnerable_verdict is OracleVerdict.UNSAFE
    assert result.mutation_total >= 4
    assert result.mutation_killed == result.mutation_total
    assert result.mutation_survived == 0
    assert len(result.manifest_sha256) == 64
    assert len(result.selftest_sha256) == 64


def test_oracle_qualification_fails_if_known_fixed_fixture_is_wrong():
    result = CrossTenantOracle().qualify(
        fixed_callable=obvious_vulnerable,
        vulnerable_callable=obvious_vulnerable,
    )
    assert result.passed is False
