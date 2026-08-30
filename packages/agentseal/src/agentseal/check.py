"""Differential attestation: show a stage cannot affect what you sign.

The checker substitutes hostile stages for the real agent and compares the
artifact that would be signed against a baseline. A hostile stage either:

* produces the exact same artifact (SEALED),
* is stopped by a fail-closed seal before any artifact exists (BLOCKED),
* changes the artifact (INFLUENCED), or
* crashes the harness unexpectedly (ERROR / inconclusive).

Only SEALED and BLOCKED are successful outcomes. Unexpected exceptions are not
silently counted as proof.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Sequence

from .hostile import Baseline, HostileVariant, default_variants
from .seal import SealBroken, fingerprint

__all__ = ["InfluenceReport", "VariantResult", "check_no_influence", "assert_no_influence"]


@dataclass(frozen=True)
class VariantResult:
    name: str
    description: str
    digest: str | None
    influenced: bool
    error: str | None = None
    blocked: bool = False

    @property
    def status(self) -> str:
        if self.influenced:
            return "INFLUENCED"
        if self.blocked:
            return "BLOCKED"
        if self.error:
            return "ERROR"
        return "SEALED"

    @property
    def successful(self) -> bool:
        return self.status in {"SEALED", "BLOCKED"}


@dataclass(frozen=True)
class InfluenceReport:
    baseline_digest: str
    results: tuple[VariantResult, ...] = field(default_factory=tuple)

    @property
    def influenced(self) -> tuple[VariantResult, ...]:
        return tuple(r for r in self.results if r.influenced)

    @property
    def errors(self) -> tuple[VariantResult, ...]:
        return tuple(r for r in self.results if r.status == "ERROR")

    @property
    def blocked(self) -> tuple[VariantResult, ...]:
        return tuple(r for r in self.results if r.blocked)

    @property
    def sealed(self) -> bool:
        return bool(self.results) and all(result.successful for result in self.results)

    def __str__(self) -> str:
        lines = [f"baseline artifact digest: {self.baseline_digest}", ""]
        width = max((len(r.name) for r in self.results), default=0)
        for result in self.results:
            marker = "ok" if result.successful else "FAIL"
            digest = result.digest[:16] if result.digest else "-"
            lines.append(f"  {marker:<4}  {result.name:<{width}}  {digest}  {result.status}")
        lines.append("")
        if self.sealed:
            lines.append(
                f"SEALED: {len(self.results)} hostile variants; "
                f"{len(self.blocked)} blocked fail-closed, artifact otherwise unchanged."
            )
        else:
            failures = ", ".join(r.name for r in self.results if not r.successful)
            lines.append(f"NOT SEALED: challenge failed or was inconclusive under [{failures}].")
        return "\n".join(lines)


def check_no_influence(
    pipeline: Callable[[Callable[..., Any]], Any],
    *,
    variants: Sequence[HostileVariant] | None = None,
    baseline: Callable[..., Any] = Baseline,
    repeat: int = 1,
) -> InfluenceReport:
    """Run ``pipeline`` under hostile substitution and report what moved.

    Unexpected pipeline exceptions are treated as inconclusive errors rather
    than as a successful seal. A deliberate ``SealBroken`` is successful
    fail-closed behavior because no artifact was produced.
    """
    variants = tuple(variants) if variants is not None else default_variants()
    baseline_digest = fingerprint(pipeline(baseline))

    results: list[VariantResult] = []
    for variant in variants:
        digest: str | None = None
        error: str | None = None
        influenced = False
        blocked = False
        completed = False
        for _ in range(max(1, repeat)):
            try:
                digest = fingerprint(pipeline(variant))
                completed = True
            except SealBroken as exc:
                error = f"{type(exc).__name__}: {exc}"
                digest = None
                blocked = True
                completed = True
                break
            except Exception as exc:
                error = f"{type(exc).__name__}: {exc}"
                digest = None
                # Retry timing-sensitive probes, but if every run errors the
                # result remains ERROR and therefore cannot certify a seal.
                continue
            if digest != baseline_digest:
                influenced = True
                break
            # One successful byte-identical run is enough for deterministic
            # variants; repeat still gives deferred/concurrent attacks chances
            # to land on subsequent iterations.
        if not completed and error is None:
            error = "agentseal: hostile variant never completed"
        results.append(
            VariantResult(variant.name, variant.description, digest, influenced, error, blocked)
        )

    return InfluenceReport(baseline_digest, tuple(results))


def assert_no_influence(
    pipeline: Callable[[Callable[..., Any]], Any],
    *,
    variants: Sequence[HostileVariant] | None = None,
    baseline: Callable[..., Any] = Baseline,
    repeat: int = 1,
) -> InfluenceReport:
    """``check_no_influence`` that raises when proof fails or is inconclusive."""
    report = check_no_influence(pipeline, variants=variants, baseline=baseline, repeat=repeat)
    if not report.sealed:
        raise AssertionError("agent non-influence not established\n\n" + str(report))
    return report
