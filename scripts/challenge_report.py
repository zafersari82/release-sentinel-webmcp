#!/usr/bin/env python3
from __future__ import annotations

import json
from importlib.resources import files
from pathlib import Path

import agentseal

from release_sentinel import __version__
from release_sentinel.domain.release import ReleaseRequest
from release_sentinel.execution.demo import BundledDemoExecutor
from release_sentinel.operations.attestation import build_evidence_bundle
from release_sentinel.policy.model import build_policy
from release_sentinel.release.engine import ReleaseEngine
from release_sentinel.release.gatekeeper import LocalDeterministicGatekeeper


FIXED_NOW = 1_750_000_000
FIXED_EXECUTION_ID = "challenge-fixed-execution"
FIXED_NONCE = "challenge-fixed-nonce"


def pipeline(agent):
    base = Path(str(files("release_sentinel"))) / "demo_fixture"
    policy = build_policy(json.loads((base / "organization-policy.json").read_text()))
    source_sha256 = (base / "repository_vulnerable.sha256").read_text().strip()
    report = ReleaseEngine(
        BundledDemoExecutor(source_sha256),
        advisor=lambda request, findings: agent(findings),
        gatekeeper=LocalDeterministicGatekeeper(),
    ).evaluate(ReleaseRequest("dare-you-challenge", base / "repository_vulnerable"), policy)
    return build_evidence_bundle(
        report,
        source_sha256=source_sha256,
        now_unix=FIXED_NOW,
        execution_id=FIXED_EXECUTION_ID,
        nonce=FIXED_NONCE,
    )


def main() -> int:
    report = agentseal.check_no_influence(pipeline, repeat=5)
    cert = agentseal.build_certificate(
        report,
        subject=f"release-sentinel-v{__version__}",
        artifact_kind="canonical-evidence-bundle-before-signing",
        now_unix=FIXED_NOW,
    )
    print(report)
    print("\nCOUNTERFACTUAL NON-INFLUENCE CERTIFICATE\n")
    print(json.dumps(cert.to_dict(), indent=2, sort_keys=True))
    return 0 if report.sealed and agentseal.verify_certificate(cert) else 2


if __name__ == "__main__":
    raise SystemExit(main())
