from __future__ import annotations

import math
import time
from dataclasses import dataclass
from enum import Enum
from typing import Callable


class MinimizationStatus(str, Enum):
    MINIMAL_UNDER_CONFIGURED_GRANULARITY = "MINIMAL_UNDER_CONFIGURED_GRANULARITY"
    REDUCED_COUNTEREXAMPLE = "REDUCED_COUNTEREXAMPLE"


@dataclass(frozen=True)
class MinimizationBudget:
    max_evaluations: int
    max_seconds: float

    def __post_init__(self) -> None:
        if not isinstance(self.max_evaluations, int) or isinstance(self.max_evaluations, bool) or self.max_evaluations < 1:
            raise ValueError("max_evaluations must be a positive integer")
        if self.max_seconds <= 0:
            raise ValueError("max_seconds must be positive")


@dataclass(frozen=True)
class MinimizationResult:
    source: str
    status: MinimizationStatus
    evaluations: int
    removed_lines: int
    budget_exhausted: bool


def minimize_lines(
    source: str,
    predicate: Callable[[str], bool],
    budget: MinimizationBudget,
) -> MinimizationResult:
    """Bounded ddmin-style reduction at line granularity.

    `predicate` is the complete escape predicate. In production it must return
    true only when the candidate is build-valid, the gate returns GO, and the
    qualified oracle returns UNSAFE. Any build/infrastructure failure therefore
    rejects that reduction rather than becoming a false escape.
    """

    started = time.monotonic()
    evaluations = 0

    def within_budget() -> bool:
        return evaluations < budget.max_evaluations and (time.monotonic() - started) < budget.max_seconds

    def evaluate(candidate: str) -> bool:
        nonlocal evaluations
        if not within_budget():
            return False
        evaluations += 1
        return bool(predicate(candidate))

    if not evaluate(source):
        if evaluations == 0:
            raise ValueError("minimization budget expired before original predicate could be evaluated")
        raise ValueError("original source does not satisfy escape predicate")

    original_lines = source.splitlines(keepends=True)
    lines = list(original_lines)
    n = 2
    completed = True

    while len(lines) >= 2:
        if not within_budget():
            completed = False
            break
        chunk_size = max(1, math.ceil(len(lines) / n))
        reduced = False
        starts = list(range(0, len(lines), chunk_size))
        for start in starts:
            if not within_budget():
                completed = False
                break
            candidate_lines = lines[:start] + lines[start + chunk_size :]
            candidate = "".join(candidate_lines)
            if evaluate(candidate):
                lines = candidate_lines
                n = max(2, n - 1)
                reduced = True
                break
        if not completed:
            break
        if reduced:
            continue
        if n >= len(lines):
            break
        n = min(len(lines), n * 2)

    budget_exhausted = not completed or not within_budget()
    status = (
        MinimizationStatus.REDUCED_COUNTEREXAMPLE
        if budget_exhausted
        else MinimizationStatus.MINIMAL_UNDER_CONFIGURED_GRANULARITY
    )
    reduced_source = "".join(lines)
    return MinimizationResult(
        source=reduced_source,
        status=status,
        evaluations=evaluations,
        removed_lines=len(original_lines) - len(lines),
        budget_exhausted=budget_exhausted,
    )
