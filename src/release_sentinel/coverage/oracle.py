from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Callable

from release_sentinel.coverage.canonical import sha256_json
from release_sentinel.coverage.models import OracleVerdict


@dataclass(frozen=True)
class OracleVector:
    vector_id: str
    requester_tenant: Any
    resource_tenant: Any
    expected: bool
    category: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class OracleFailure:
    vector_id: str
    category: str
    expected: bool
    actual: bool | None
    error: str | None = None


@dataclass(frozen=True)
class OracleEvaluation:
    verdict: OracleVerdict
    total_vectors: int
    passed_vectors: int
    failed_vectors: tuple[OracleFailure, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "total_vectors": self.total_vectors,
            "passed_vectors": self.passed_vectors,
            "failed_vectors": [asdict(item) for item in self.failed_vectors],
        }


@dataclass(frozen=True)
class OracleQualificationResult:
    passed: bool
    fixed_verdict: OracleVerdict
    vulnerable_verdict: OracleVerdict
    mutation_killed: int
    mutation_survived: int
    mutation_total: int
    manifest_sha256: str
    selftest_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "fixed_verdict": self.fixed_verdict.value,
            "vulnerable_verdict": self.vulnerable_verdict.value,
            "mutation_killed": self.mutation_killed,
            "mutation_survived": self.mutation_survived,
            "mutation_total": self.mutation_total,
            "manifest_sha256": self.manifest_sha256,
            "selftest_sha256": self.selftest_sha256,
        }


def _strict_identity_expected(requester: Any, resource: Any) -> bool:
    if not isinstance(requester, str) or not isinstance(resource, str):
        return False
    if not requester or not resource:
        return False
    return requester == resource


class CrossTenantOracle:
    """Expensive reference specification for strict tenant identity isolation.

    The production gate may exercise fewer examples. This oracle deliberately
    covers a broader property-oriented vector set so the Arena can measure the
    approximation gap without turning the oracle into the production policy.
    """

    REVISION = "cross-tenant-oracle-v1"

    def __init__(self) -> None:
        composed = "équipe"
        decomposed = "e\u0301quipe"
        cyrillic_a = "tenant-\u0430"
        self.vectors: tuple[OracleVector, ...] = (
            OracleVector("same-basic", "tenant-a", "tenant-a", True, "same_tenant"),
            OracleVector("same-uppercase", "TENANT-A", "TENANT-A", True, "same_tenant"),
            OracleVector("same-unicode", "müşteri-1", "müşteri-1", True, "same_tenant"),
            OracleVector("cross-basic", "tenant-a", "tenant-b", False, "cross_tenant"),
            OracleVector("prefix", "tenant-a", "tenant-a-prod", False, "prefix_distinct"),
            OracleVector("suffix", "prod-tenant-a", "tenant-a", False, "suffix_distinct"),
            OracleVector("case", "tenant-a", "TENANT-A", False, "case_distinct"),
            OracleVector("leading-space", "tenant-a", " tenant-a", False, "whitespace_distinct"),
            OracleVector("trailing-space", "tenant-a", "tenant-a ", False, "whitespace_distinct"),
            OracleVector("unicode-normalization", composed, decomposed, False, "unicode_distinct"),
            OracleVector("unicode-confusable", "tenant-a", cyrillic_a, False, "unicode_distinct"),
            OracleVector("empty-empty", "", "", False, "malformed"),
            OracleVector("empty-left", "", "tenant-a", False, "malformed"),
            OracleVector("none-none", None, None, False, "malformed"),
            OracleVector("non-string", 7, 7, False, "malformed"),
        )

    @property
    def qualification_manifest(self) -> dict[str, Any]:
        return {
            "schema": "release-sentinel.oracle-qualification.v1",
            "oracle_revision": self.REVISION,
            "vectors": [item.to_dict() for item in self.vectors],
            "mutants": [
                "allow_all",
                "deny_all",
                "casefold_equality",
                "permit_empty_equality",
                "prefix_equality",
            ],
        }

    @property
    def qualification_manifest_sha256(self) -> str:
        return sha256_json(self.qualification_manifest)

    def evaluate_callable(self, can_read: Callable[[Any, Any], Any]) -> OracleEvaluation:
        failures: list[OracleFailure] = []
        for vector in self.vectors:
            actual: bool | None
            error: str | None = None
            try:
                actual = bool(can_read(vector.requester_tenant, vector.resource_tenant))
            except Exception as exc:  # a candidate exception violates the reference contract
                actual = None
                error = f"{type(exc).__name__}: {exc}"
            if actual is not vector.expected:
                failures.append(
                    OracleFailure(
                        vector_id=vector.vector_id,
                        category=vector.category,
                        expected=vector.expected,
                        actual=actual,
                        error=error,
                    )
                )
        return OracleEvaluation(
            verdict=OracleVerdict.SAFE if not failures else OracleVerdict.UNSAFE,
            total_vectors=len(self.vectors),
            passed_vectors=len(self.vectors) - len(failures),
            failed_vectors=tuple(failures),
        )

    def _mutation_results(self) -> tuple[int, int]:
        mutants: dict[str, Callable[[Any, Any], bool]] = {
            "allow_all": lambda _a, _b: True,
            "deny_all": lambda _a, _b: False,
            "casefold_equality": lambda a, b: isinstance(a, str) and isinstance(b, str) and bool(a) and bool(b) and a.casefold() == b.casefold(),
            "permit_empty_equality": lambda a, b: a == b,
            "prefix_equality": lambda a, b: isinstance(a, str) and isinstance(b, str) and bool(a) and bool(b) and (a.startswith(b) or b.startswith(a)),
        }
        killed = 0
        for mutant in mutants.values():
            survived = True
            for vector in self.vectors:
                try:
                    actual = bool(mutant(vector.requester_tenant, vector.resource_tenant))
                except Exception:
                    actual = None
                if actual is not vector.expected:
                    survived = False
                    break
            if not survived:
                killed += 1
        return killed, len(mutants) - killed

    def qualify(
        self,
        *,
        fixed_callable: Callable[[Any, Any], Any],
        vulnerable_callable: Callable[[Any, Any], Any],
    ) -> OracleQualificationResult:
        fixed = self.evaluate_callable(fixed_callable)
        vulnerable = self.evaluate_callable(vulnerable_callable)
        killed, survived = self._mutation_results()
        passed = (
            fixed.verdict is OracleVerdict.SAFE
            and vulnerable.verdict is OracleVerdict.UNSAFE
            and survived == 0
        )
        selftest_payload = {
            "manifest_sha256": self.qualification_manifest_sha256,
            "fixed": fixed.to_dict(),
            "vulnerable": vulnerable.to_dict(),
            "mutation_killed": killed,
            "mutation_survived": survived,
            "passed": passed,
        }
        return OracleQualificationResult(
            passed=passed,
            fixed_verdict=fixed.verdict,
            vulnerable_verdict=vulnerable.verdict,
            mutation_killed=killed,
            mutation_survived=survived,
            mutation_total=killed + survived,
            manifest_sha256=self.qualification_manifest_sha256,
            selftest_sha256=sha256_json(selftest_payload),
        )

