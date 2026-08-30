from __future__ import annotations

from release_sentinel.domain.evidence import Decision, Finding, Severity


class DeterministicJudge:
    def decide(self, findings: list[Finding]) -> tuple[Decision, list[str]]:
        blockers = [
            f for f in findings
            if f.severity in {Severity.HIGH, Severity.CRITICAL} and f.blocking_evidence()
        ]
        medium = [f for f in findings if f.severity == Severity.MEDIUM and f.blocking_evidence()]
        if blockers:
            return Decision.NO_GO, [
                f"{len(blockers)} high/critical finding(s) have authoritative blocking evidence.",
                "Model output is not part of release authority.",
            ]
        if medium:
            return Decision.CONDITIONAL_GO, [f"{len(medium)} authoritative medium-severity finding(s) remain."]
        return Decision.GO, ["No authoritative blocking evidence remains."]
