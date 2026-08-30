#!/usr/bin/env python3
from __future__ import annotations

import json
from importlib.resources import files
from pathlib import Path

from release_sentinel.domain.release import ReleaseRequest
from release_sentinel.execution.demo import BundledDemoExecutor
from release_sentinel.policy.model import build_policy
from release_sentinel.release.engine import ReleaseEngine
from release_sentinel.release.gatekeeper import LocalDeterministicGatekeeper
from release_sentinel.remediation import RemediationCoordinator, repository_sha256


def evaluator(request: ReleaseRequest):
    root = request.repository_path
    actual_fixture_sha = BundledDemoExecutor.fixture_digest(root)
    source = (root / "app.py").read_text(encoding="utf-8")
    auth_fixed = "requester_tenant == resource_tenant" in source
    executor = BundledDemoExecutor(
        actual_fixture_sha,
        expected_return_code=0 if auth_fixed else 1,
    )
    base = Path(str(files("release_sentinel"))) / "demo_fixture"
    policy = build_policy(json.loads((base / "organization-policy.json").read_text()))
    return ReleaseEngine(
        executor,
        advisor=None,
        gatekeeper=LocalDeterministicGatekeeper(),
    ).evaluate(request, policy)


def main() -> int:
    base = Path(str(files("release_sentinel"))) / "demo_fixture"
    vulnerable = base / "repository_vulnerable"
    fixed_text = (base / "repository_fixed" / "app.py").read_text(encoding="utf-8")

    def proposal_only_remediator(context):
        # Offline deterministic stand-in for the real Gemini adapter in
        # release_sentinel.agents.remediation.run_real_gemini_remediator.
        assert context.findings, "demo fixture must begin with a blocking finding"
        return {"app.py": fixed_text}

    outcome = RemediationCoordinator(
        evaluator,
        proposal_only_remediator,
        producer_agent_id="gemini-remediator-demo",
        allowed_paths={"app.py"},
    ).run(ReleaseRequest("autonomous-repair-demo", vulnerable))

    print("AUTONOMY WITHOUT AUTHORITY")
    print(f"before decision : {outcome.before.decision.value}")
    print(f"before source   : {outcome.original_source_sha256}")
    print(f"proposal auth   : {outcome.proposal.authority if outcome.proposal else '-'}")
    print(f"proposal sha256 : {outcome.proposal.proposal_sha256 if outcome.proposal else '-'}")
    print(f"after source    : {outcome.repaired_source_sha256}")
    print(f"fresh evaluation: {outcome.reevaluated_from_scratch}")
    print(f"after decision  : {outcome.after.decision.value if outcome.after else '-'}")
    print("original intact :", repository_sha256(vulnerable) == outcome.original_source_sha256)

    ok = (
        outcome.before.decision.value == "NO_GO"
        and outcome.after is not None
        and outcome.after.decision.value == "GO"
        and outcome.reevaluated_from_scratch
        and outcome.proposal is not None
        and outcome.proposal.authority == "PROPOSAL_ONLY"
        and repository_sha256(vulnerable) == outcome.original_source_sha256
    )
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
