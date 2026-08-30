from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from release_sentinel.coverage.models import CandidateValidity, CoverageClassification, OracleVerdict
from release_sentinel.domain.evidence import Decision


@dataclass(frozen=True)
class CoverageObservation:
    candidate_id: str
    validity: CandidateValidity
    gate_decision: Decision | None
    oracle_verdict: OracleVerdict | None

    @property
    def classification(self) -> CoverageClassification:
        return classify_observation(self.validity, self.gate_decision, self.oracle_verdict)


@dataclass(frozen=True)
class CoverageCounts:
    confirmed_safe: int
    confirmed_unsafe: int
    correct_accepts: int
    overblocks: int
    correct_blocks: int
    escapes: int
    invalid_candidates: int

    @property
    def valid_candidates(self) -> int:
        return self.confirmed_safe + self.confirmed_unsafe

    @property
    def total_candidates(self) -> int:
        return self.valid_candidates + self.invalid_candidates

    @staticmethod
    def _rate_payload(numerator: int, denominator: int) -> dict[str, Any]:
        interval = wilson_interval(numerator, denominator)
        return {
            "numerator": numerator,
            "denominator": denominator,
            "observed": None if denominator == 0 else numerator / denominator,
            "wilson_95": None if interval is None else [interval[0], interval[1]],
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "confirmed_safe": self.confirmed_safe,
            "confirmed_unsafe": self.confirmed_unsafe,
            "correct_accepts": self.correct_accepts,
            "overblocks": self.overblocks,
            "correct_blocks": self.correct_blocks,
            "escapes": self.escapes,
            "invalid_candidates": self.invalid_candidates,
            "valid_candidates": self.valid_candidates,
            "total_candidates": self.total_candidates,
            "unsafe_catch_rate": self._rate_payload(self.correct_blocks, self.confirmed_unsafe),
            "escape_rate": self._rate_payload(self.escapes, self.confirmed_unsafe),
            "overblock_rate": self._rate_payload(self.overblocks, self.confirmed_safe),
        }


def classify_observation(
    validity: CandidateValidity,
    gate_decision: Decision | None,
    oracle_verdict: OracleVerdict | None,
) -> CoverageClassification:
    if validity is CandidateValidity.INVALID:
        return CoverageClassification.INVALID_CANDIDATE
    if gate_decision is None or oracle_verdict is None:
        raise ValueError("valid candidate requires gate and oracle results")
    if gate_decision is Decision.GO and oracle_verdict is OracleVerdict.SAFE:
        return CoverageClassification.CORRECT_ACCEPT
    if gate_decision is Decision.GO and oracle_verdict is OracleVerdict.UNSAFE:
        return CoverageClassification.ESCAPE
    if gate_decision is Decision.NO_GO and oracle_verdict is OracleVerdict.SAFE:
        return CoverageClassification.OVERBLOCK
    if gate_decision is Decision.NO_GO and oracle_verdict is OracleVerdict.UNSAFE:
        return CoverageClassification.CORRECT_BLOCK
    raise ValueError(f"unsupported gate/oracle combination: {gate_decision}/{oracle_verdict}")


def wilson_interval(successes: int, total: int, *, z: float = 1.959963984540054) -> tuple[float, float] | None:
    if successes < 0 or total < 0 or successes > total:
        raise ValueError("Wilson interval requires 0 <= successes <= total")
    if total == 0:
        return None
    p_hat = successes / total
    z2 = z * z
    denominator = 1.0 + z2 / total
    center = (p_hat + z2 / (2.0 * total)) / denominator
    margin = z * math.sqrt((p_hat * (1.0 - p_hat) / total) + (z2 / (4.0 * total * total))) / denominator
    return max(0.0, center - margin), min(1.0, center + margin)



def paired_mcnemar_exact(first: Mapping[str, bool], second: Mapping[str, bool]) -> dict[str, Any]:
    """Exact two-sided McNemar comparison for hash-bound paired candidates.

    The two mappings must describe the same candidate ids.  The p-value is the
    exact two-sided binomial test over discordant pairs under p=0.5, avoiding a
    SciPy/runtime dependency in the deterministic reference measurement path.
    """

    if set(first) != set(second):
        raise ValueError("paired McNemar requires identical candidate ids")
    candidate_ids = sorted(first)
    only_first = sum(bool(first[candidate_id]) and not bool(second[candidate_id]) for candidate_id in candidate_ids)
    only_second = sum(bool(second[candidate_id]) and not bool(first[candidate_id]) for candidate_id in candidate_ids)
    discordant = only_first + only_second
    if discordant == 0:
        p_value = 1.0
    else:
        tail = sum(math.comb(discordant, i) for i in range(min(only_first, only_second) + 1))
        p_value = min(1.0, (2.0 * tail) / (2 ** discordant))
    return {
        "total_pairs": len(candidate_ids),
        "only_first": only_first,
        "only_second": only_second,
        "discordant_pairs": discordant,
        "exact_p_value": p_value,
    }

def holm_bonferroni(p_values: Iterable[float], *, alpha: float = 0.05) -> list[dict[str, Any]]:
    """Apply Holm-Bonferroni step-down family-wise error correction.

    Results are returned in the same order as the input values so callers can
    attach the correction metadata to already-identified comparisons.
    """

    values = [float(value) for value in p_values]
    if not 0.0 < alpha <= 1.0:
        raise ValueError("Holm-Bonferroni alpha must satisfy 0 < alpha <= 1")
    if any(value < 0.0 or value > 1.0 for value in values):
        raise ValueError("Holm-Bonferroni p-values must satisfy 0 <= p <= 1")
    family_size = len(values)
    if family_size == 0:
        return []

    ranked = sorted(enumerate(values), key=lambda item: (item[1], item[0]))
    results: list[dict[str, Any] | None] = [None] * family_size
    continue_rejecting = True
    for zero_based_rank, (original_index, p_value) in enumerate(ranked):
        rank = zero_based_rank + 1
        adjusted_alpha = alpha / (family_size - zero_based_rank)
        reject = continue_rejecting and p_value <= adjusted_alpha
        if not reject:
            continue_rejecting = False
        results[original_index] = {
            "raw_p_value": p_value,
            "holm_rank": rank,
            "adjusted_alpha": adjusted_alpha,
            "reject_null_after_correction": reject,
        }

    return [item for item in results if item is not None]


def aggregate_observations(observations: Iterable[CoverageObservation]) -> CoverageCounts:
    correct_accepts = overblocks = correct_blocks = escapes = invalid = 0
    for observation in observations:
        classification = observation.classification
        if classification is CoverageClassification.CORRECT_ACCEPT:
            correct_accepts += 1
        elif classification is CoverageClassification.OVERBLOCK:
            overblocks += 1
        elif classification is CoverageClassification.CORRECT_BLOCK:
            correct_blocks += 1
        elif classification is CoverageClassification.ESCAPE:
            escapes += 1
        else:
            invalid += 1
    return CoverageCounts(
        confirmed_safe=correct_accepts + overblocks,
        confirmed_unsafe=correct_blocks + escapes,
        correct_accepts=correct_accepts,
        overblocks=overblocks,
        correct_blocks=correct_blocks,
        escapes=escapes,
        invalid_candidates=invalid,
    )
