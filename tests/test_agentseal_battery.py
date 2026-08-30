"""The full agentseal hostile battery against the real evaluation pipeline.

`test_advisory_evidence_boundary.py` asserts the boundary holds against three
attacks we thought of. This asserts it holds against a battery maintained
outside this repository, including the two that a naive check misses entirely:
a stage that mutates *after* returning, and one that mutates from another
thread while the stage is still running.

Run against v1.6 this reports BROKEN under six of nine variants. That version
is the reason this file exists.
"""

from __future__ import annotations

import json
from importlib.resources import files
from pathlib import Path

import pytest

agentseal = pytest.importorskip("agentseal", reason="pip install -e packages/agentseal")

from release_sentinel.domain.release import ReleaseRequest
from release_sentinel.execution.demo import BundledDemoExecutor
from release_sentinel.operations.attestation import build_evidence_bundle
from release_sentinel.policy.model import build_policy
from release_sentinel.release.engine import ReleaseEngine
from release_sentinel.release.gatekeeper import LocalDeterministicGatekeeper

FIXED_NOW = 1_750_000_000
FIXED_EXECUTION_ID = "exec-fixed-for-determinism"
FIXED_NONCE = "nonce-fixed-for-determinism"


def _fixture():
    base = Path(str(files("release_sentinel"))) / "demo_fixture"
    policy = build_policy(json.loads((base / "organization-policy.json").read_text()))
    source_sha256 = (base / "repository_vulnerable.sha256").read_text().strip()
    return base / "repository_vulnerable", policy, source_sha256


def _pipeline(agent):
    """Evidence collection through to the artifact that would be signed.

    Every nondeterministic input is pinned so the agent stage is the only
    variable. If the digest moves, the agent moved it.
    """
    repository, policy, source_sha256 = _fixture()
    report = ReleaseEngine(
        BundledDemoExecutor(source_sha256),
        advisor=lambda request, findings: agent(findings),
        gatekeeper=LocalDeterministicGatekeeper(),
    ).evaluate(ReleaseRequest("agentseal-probe", repository), policy)
    return build_evidence_bundle(
        report,
        source_sha256=source_sha256,
        now_unix=FIXED_NOW,
        execution_id=FIXED_EXECUTION_ID,
        nonce=FIXED_NONCE,
    )


def test_pipeline_is_sealed_against_the_full_hostile_battery():
    report = agentseal.assert_no_influence(_pipeline, repeat=3)
    assert report.sealed
    assert len(report.results) == len(agentseal.default_variants())


def test_deferred_and_concurrent_mutation_are_covered():
    """The two timing-dependent variants must actually be in the battery."""
    names = {variant.name for variant in agentseal.default_variants()}
    assert {"deferred", "concurrent"} <= names


def test_the_probe_would_detect_influence_if_the_seal_regressed():
    """A harness that cannot fail proves nothing.

    This rebuilds the v1.6 shape — an unsealed stage holding the live list —
    and asserts agentseal reports it as broken. If this test ever passes
    silently, the battery has stopped working.
    """
    live_evidence = [
        {"finding_id": "AUTH-0042", "severity": "HIGH", "blocking_eligible": True},
    ]

    def unsealed_pipeline(agent):
        evidence = [dict(item) for item in live_evidence]
        try:
            agent(evidence)
        except Exception:
            pass
        return {"results": evidence, "blockers": sum(
            1 for item in evidence if item.get("blocking_eligible"))}

    influence_report = agentseal.check_no_influence(unsealed_pipeline, repeat=3)
    assert not influence_report.sealed, "agentseal failed to detect a known-vulnerable pipeline"
