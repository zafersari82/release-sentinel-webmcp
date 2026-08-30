from __future__ import annotations

import hashlib
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Mapping, Sequence

from release_sentinel.domain.evidence import (
    Evidence, EvidenceAuthority, EvidenceIntegrityError, EvidenceKind, Finding, finding_set_sha256,
)
from release_sentinel.domain.release import ReleaseReport, ReleaseRequest
from release_sentinel.execution.base import SandboxExecutor
from release_sentinel.policy.model import ReleasePolicy
from release_sentinel.release.gatekeeper import Gatekeeper, LocalDeterministicGatekeeper
from release_sentinel.release.scanners import scan_platform_rules
from release_sentinel.observability.tracing import safe_span, set_safe_attributes


EvidenceTamperError = EvidenceIntegrityError


def evidence_fingerprint(findings: Sequence[Finding]) -> str:
    """Compatibility name for the canonical authoritative evidence-set seal."""
    return finding_set_sha256(findings)


def advisory_projection(findings: Sequence[Finding]) -> tuple[Mapping[str, Any], ...]:
    """Read-only, redacted view handed to advisory components.

    Advisory agents receive plain data behind ``MappingProxyType``, never domain
    objects and never the live sequence. Raw command output digests, policy
    identifiers and the evidence records themselves are withheld: an advisor
    can see *that* a check failed and how severe it is, which is all it needs
    to challenge coverage, but it holds no reference that reaches the bytes
    that will later be signed.
    """
    return tuple(
        MappingProxyType(
            {
                "finding_id": item.finding_id,
                "title": item.title,
                "severity": item.severity.value,
                "source": item.source,
                "claim": item.claim,
                "blocking_eligible": bool(item.blocking_evidence()),
            }
        )
        for item in findings
    )


class ReleaseEngine:
    """Evidence collection pipeline with an explicit external decision boundary.

    Ordering is load-bearing. Evidence is collected and sealed *before* any
    advisory component runs, and the seal is re-checked afterwards. Agent
    opinions may cross the gatekeeper boundary for the verdict-independence
    proof, but the deterministic gatekeeper intentionally ignores them.
    """

    def __init__(
        self,
        executor: SandboxExecutor,
        advisor: Callable[[ReleaseRequest, tuple[Mapping[str, Any], ...]], dict] | None = None,
        gatekeeper: Gatekeeper | None = None,
    ) -> None:
        self.executor = executor
        self.advisor = advisor
        self.gatekeeper = gatekeeper or LocalDeterministicGatekeeper()

    def evaluate(self, request: ReleaseRequest, policy: ReleasePolicy) -> ReleaseReport:
        with safe_span(
            "release_verdict_pipeline",
            {
                "component": "release-sentinel-python",
                "decision_authority": "DETERMINISTIC",
                "evidence_authority": "ORGANIZATION_POLICY",
                "agent_influence": 0,
                "llm_present": False,
            },
        ) as root_span:
            return self._evaluate(request, policy, root_span)

    def _evaluate(self, request: ReleaseRequest, policy: ReleasePolicy, root_span) -> ReleaseReport:
        root = Path(request.repository_path).resolve()
        findings = scan_platform_rules(root)
        executions = 0
        for command in policy.commands:
            result = self.executor.execute(root, command)
            executions += 1
            if result.passed:
                continue
            reproducible = not result.timed_out
            ev_payload = f"{policy.sha256}:{command.command_id}:{result.return_code}:{result.stdout_sha256}:{result.stderr_sha256}"
            evidence = Evidence(
                evidence_id="ev-exec-" + hashlib.sha256(ev_payload.encode()).hexdigest()[:12],
                kind=EvidenceKind.EXECUTION_RESULT,
                authority=EvidenceAuthority.ORGANIZATION_POLICY,
                source=f"policy:{policy.policy_id}:{command.command_id}",
                summary="Organization-owned release check failed in isolated execution.",
                reproducible=reproducible,
                blocking_eligible=command.blocking_on_failure,
                details={
                    "command_id": command.command_id,
                    "return_code": result.return_code,
                    "timed_out": result.timed_out,
                    "stdout_sha256": result.stdout_sha256,
                    "stderr_sha256": result.stderr_sha256,
                    "duration_ms": result.duration_ms,
                    "expected_exit_code": 0,
                },
                policy_id=policy.policy_id,
                policy_revision=policy.revision,
                policy_sha256=policy.sha256,
            )
            findings.append(Finding(
                finding_id="POL-" + hashlib.sha256(f"{policy.policy_id}:{policy.revision}:{command.command_id}".encode()).hexdigest()[:8],
                title=command.title,
                severity=command.severity,
                source="organization_policy",
                claim="A required organization-owned release check failed.",
                evidence=[evidence],
            ))

        # ------------------------------------------------------------------
        # EVIDENCE SEAL. Nothing below this line may change what was observed.
        # The advisory stage runs strictly downstream of a fixed evidence set.
        # ------------------------------------------------------------------
        sealed_findings = tuple(findings)
        sealed_fingerprint = evidence_fingerprint(sealed_findings)
        set_safe_attributes(root_span, {"evidence_sha256": sealed_fingerprint})

        advisory = self._collect_advisory(request, sealed_findings)

        if evidence_fingerprint(sealed_findings) != sealed_fingerprint:
            raise EvidenceTamperError(
                "advisory stage mutated sealed evidence; no verdict was issued"
            )

        opinions = list((advisory or {}).get("opinions") or [])
        verdict = self.gatekeeper.decide(request.release_id, list(sealed_findings), opinions)
        if verdict.llm_present or verdict.agent_influence != 0:
            raise RuntimeError("gatekeeper violated deterministic authority contract")
        set_safe_attributes(
            root_span,
            {
                "verdict": verdict.decision.value,
                "agent_influence": verdict.agent_influence,
                "llm_present": verdict.llm_present,
            },
        )

        return ReleaseReport(
            release_id=request.release_id,
            decision=verdict.decision,
            findings=sealed_findings,
            rationale=tuple(verdict.rationale),
            policy_id=policy.policy_id,
            policy_revision=policy.revision,
            policy_sha256=policy.sha256,
            execution_count=executions,
            evidence_sha256=sealed_fingerprint,
            advisory=advisory,
            gatekeeper=verdict.to_dict(),
        )

    def _collect_advisory(
        self, request: ReleaseRequest, findings: Sequence[Finding]
    ) -> dict[str, Any] | None:
        """Run the advisory stage against a redacted, read-only projection.

        Advisor failures degrade to an explicit UNAVAILABLE record rather than
        aborting the release: an advisory component has no decision authority,
        so its absence must not change the verdict. EvidenceTamperError is
        deliberately not swallowed.
        """
        if self.advisor is None:
            return None
        projection = advisory_projection(findings)
        try:
            return self.advisor(request, projection)
        except EvidenceTamperError:
            raise
        except Exception:
            return {
                "role": "advisory_fleet",
                "authority": "ADVISORY",
                "status": "UNAVAILABLE",
                "opinions": [],
            }
