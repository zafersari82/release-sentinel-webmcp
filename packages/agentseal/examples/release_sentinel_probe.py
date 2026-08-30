"""agentseal against the codebase it was extracted from.

Run this against Release Sentinel v1.6 and it reports BROKEN. Run it against
v1.8 and it reports SEALED. Same probe, same baseline digest, one sealed.
"""
import json
from pathlib import Path
from importlib.resources import files

from agentseal import check_no_influence
from release_sentinel.domain.release import ReleaseRequest
from release_sentinel.execution.demo import BundledDemoExecutor
from release_sentinel.operations.attestation import build_evidence_bundle
from release_sentinel.policy.model import build_policy
from release_sentinel.release.engine import ReleaseEngine
from release_sentinel.release.gatekeeper import LocalDeterministicGatekeeper

base = Path(str(files("release_sentinel"))) / "demo_fixture"
policy = build_policy(json.loads((base / "organization-policy.json").read_text()))
source_sha256 = (base / "repository_vulnerable.sha256").read_text().strip()


def pipeline(agent):
    """Everything from evidence collection to the artifact that gets signed."""
    report = ReleaseEngine(
        BundledDemoExecutor(source_sha256),
        advisor=lambda request, findings: agent(findings),
        gatekeeper=LocalDeterministicGatekeeper(),
    ).evaluate(ReleaseRequest("seal-probe", base / "repository_vulnerable"), policy)
    # Pin the nondeterministic inputs so the only variable is the agent.
    return build_evidence_bundle(
        report, source_sha256=source_sha256,
        now_unix=1_750_000_000, execution_id="fixed", nonce="fixed",
    )


if __name__ == "__main__":
    print(check_no_influence(pipeline, repeat=3))
