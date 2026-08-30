from release_sentinel.coverage.minimizer import (
    MinimizationBudget,
    MinimizationStatus,
    minimize_lines,
)


def escape_predicate(source: str) -> bool:
    try:
        compile(source, "<candidate>", "exec")
    except SyntaxError:
        return False
    return "return True" in source and "def can_read" in source


def test_minimizer_removes_irrelevant_lines_but_preserves_escape_predicate():
    source = '''# noise one
# noise two
def can_read(a, b):
    marker = 1
    return True
# trailing noise
'''
    result = minimize_lines(source, escape_predicate, MinimizationBudget(max_evaluations=100, max_seconds=2.0))
    assert result.status is MinimizationStatus.MINIMAL_UNDER_CONFIGURED_GRANULARITY
    assert escape_predicate(result.source)
    assert len(result.source.splitlines()) < len(source.splitlines())
    assert "# noise one" not in result.source
    assert "# trailing noise" not in result.source


def test_invalid_or_nonbuilding_reductions_are_rejected_by_predicate():
    source = '''def can_read(a, b):
    if a:
        return True
    return True
'''
    result = minimize_lines(source, escape_predicate, MinimizationBudget(max_evaluations=100, max_seconds=2.0))
    compile(result.source, "<result>", "exec")
    assert escape_predicate(result.source)


def test_budget_exhaustion_is_never_labeled_minimal():
    source = '''# one
# two
# three
def can_read(a, b):
    return True
'''
    result = minimize_lines(source, escape_predicate, MinimizationBudget(max_evaluations=1, max_seconds=2.0))
    assert result.status is MinimizationStatus.REDUCED_COUNTEREXAMPLE
    assert result.budget_exhausted is True
    assert result.evaluations == 1


def test_original_source_must_satisfy_escape_predicate():
    source = '''def can_read(a, b):
    return a == b
'''
    try:
        minimize_lines(source, escape_predicate, MinimizationBudget(max_evaluations=10, max_seconds=2.0))
    except ValueError as exc:
        assert "original" in str(exc)
    else:
        raise AssertionError("non-escape source was minimized")


def test_budget_validation_rejects_nonsensical_limits():
    try:
        MinimizationBudget(max_evaluations=0, max_seconds=2.0)
    except ValueError as exc:
        assert "max_evaluations" in str(exc)
    else:
        raise AssertionError("zero evaluation budget accepted")
