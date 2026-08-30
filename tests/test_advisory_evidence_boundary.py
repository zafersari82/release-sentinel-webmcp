"""Advisory components must not be able to reach signed evidence.

These tests close the v1.6 finding in which the advisory callable received the
live, mutable ``findings`` list *before* the evidence bundle was constructed and
signed. A hostile advisor could erase evidence and the resulting bundle carried
a valid signature over the erased set: the Gatekeeper reported
``evidence_verified: true`` while returning GO on a release with a blocking
authorization failure.

The invariant asserted here is deliberately stronger than verdict equality.
Verdict equality would still pass if evidence were altered in a way that
happened not to change the outcome. ``bundle_sha256`` equality asserts that the
signed bytes themselves are identical, which is what the security claim
actually requires.
"""

from __future__ import annotations

import json
from importlib.resources import files
from pathlib import Path

import pytest

from release_sentinel.domain.evidence import Finding
from release_sentinel.domain.release import ReleaseRequest
from release_sentinel.execution.demo import BundledDemoExecutor
from release_sentinel.operations.attestation import (
    build_evidence_bundle,
    canonical_bytes,
    sign_evidence_bundle,
)
from release_sentinel.policy.model import build_policy
from release_sentinel.release.engine import (
    EvidenceTamperError,
    ReleaseEngine,
    advisory_projection,
    evidence_fingerprint,
)
from release_sentinel.release.gatekeeper import LocalDeterministicGatekeeper


FIXED_NOW = 1_750_000_000
FIXED_EXECUTION_ID = "exec-fixed-for-determinism"
FIXED_NONCE = "nonce-fixed-for-determinism"


def _fixture():
    base = Path(str(files("release_sentinel"))) / "demo_fixture"
    policy = build_policy(json.loads((base / "organization-policy.json").read_text()))
    source_sha256 = (base / "repository_vulnerable.sha256").read_text().strip()
    return base / "repository_vulnerable", policy, source_sha256


class _StubSigner:
    """Deterministic stand-in for KMS. Signs the digest it is handed."""

    def sign_payload(self, payload: bytes) -> tuple[bytes, str]:
        return b"stub-signature", "stub-key"


def _signed_bundle_for(advisor):
    repository, policy, source_sha256 = _fixture()
    report = ReleaseEngine(
        BundledDemoExecutor(source_sha256),
        advisor=advisor,
        gatekeeper=LocalDeterministicGatekeeper(),
    ).evaluate(ReleaseRequest("boundary-test", repository), policy)
    bundle = build_evidence_bundle(
        report,
        source_sha256=source_sha256,
        now_unix=FIXED_NOW,
        execution_id=FIXED_EXECUTION_ID,
        nonce=FIXED_NONCE,
    )
    return report, sign_evidence_bundle(bundle, _StubSigner())


def _hostile_clear(request, findings):
    """Attempt the v1.6 attack: erase evidence before it is signed."""
    try:
        findings.clear()  # type: ignore[attr-defined]
    except AttributeError:
        pass
    return {"role": "advisory_fleet", "authority": "NONE",
            "opinions": [{"agent": "evil", "vote": "GO"}]}


def _hostile_downgrade(request, findings):
    """Attempt to rewrite severity on whatever the advisor is handed."""
    for item in findings:
        try:
            item["severity"] = "INFO"  # type: ignore[index]
        except (TypeError, AttributeError):
            pass
        try:
            object.__setattr__(item, "severity", "INFO")
        except (AttributeError, TypeError):
            pass
    return {"role": "advisory_fleet", "authority": "NONE",
            "opinions": [{"agent": "evil", "vote": "GO"}]}


def _hostile_silent(request, findings):
    """Mutate and then raise, to check the failure path does not hide it."""
    try:
        findings.clear()  # type: ignore[attr-defined]
    except AttributeError:
        pass
    raise RuntimeError("advisor crashed after tampering")


HOSTILE_ADVISORS = [
    pytest.param(_hostile_clear, id="erase-evidence"),
    pytest.param(_hostile_downgrade, id="downgrade-severity"),
    pytest.param(_hostile_silent, id="mutate-then-crash"),
]


@pytest.mark.parametrize("hostile", HOSTILE_ADVISORS)
def test_hostile_advisor_cannot_change_signed_evidence(hostile):
    """The signed bytes must be identical with and without a hostile advisor."""
    clean_report, clean_signed = _signed_bundle_for(None)
    attack_report, attack_signed = _signed_bundle_for(hostile)

    assert attack_signed.bundle_sha256 == clean_signed.bundle_sha256
    assert canonical_bytes(attack_signed.bundle) == canonical_bytes(clean_signed.bundle)
    assert attack_report.decision == clean_report.decision
    assert len(attack_signed.bundle["results"]) == len(clean_signed.bundle["results"])


def test_vulnerable_fixture_still_blocks_under_attack():
    """Sanity anchor: the baseline this test protects is a real NO_GO."""
    _, clean_signed = _signed_bundle_for(None)
    assert clean_signed.bundle["results"], "fixture must produce blocking evidence"
    _, attack_signed = _signed_bundle_for(_hostile_clear)
    assert attack_signed.bundle["results"], "hostile advisor erased signed evidence"


def test_advisor_never_receives_domain_objects():
    """Advisory components see redacted mappings, never Finding instances."""
    captured: list = []

    def capturing_advisor(request, findings):
        captured.extend(findings)
        return {"opinions": []}

    _signed_bundle_for(capturing_advisor)

    assert captured, "advisor should have received the projection"
    for item in captured:
        assert not isinstance(item, Finding)
        with pytest.raises(TypeError):
            item["severity"] = "INFO"
        assert "evidence" not in item, "raw evidence records must not be exposed"
        assert "policy_sha256" not in item


def test_projection_is_decoupled_from_source_findings():
    """Mutating the projection cannot affect the underlying evidence."""
    repository, policy, source_sha256 = _fixture()
    report = ReleaseEngine(
        BundledDemoExecutor(source_sha256),
        advisor=None,
        gatekeeper=LocalDeterministicGatekeeper(),
    ).evaluate(ReleaseRequest("projection-test", repository), policy)

    before = evidence_fingerprint(report.findings)
    projection = list(advisory_projection(report.findings))
    projection.clear()
    assert evidence_fingerprint(report.findings) == before


def test_tamper_detector_is_wired_and_fails_closed():
    """If evidence ever changes across the advisory stage, no verdict is issued."""
    repository, policy, source_sha256 = _fixture()

    class TamperingEngine(ReleaseEngine):
        def _collect_advisory(self, request, findings):
            # Simulate a future refactor that hands live objects to an advisor
            # and lets that advisor mutate them.
            object.__setattr__(findings[0], "severity", type(findings[0].severity)("LOW"))
            return {"opinions": []}

    engine = TamperingEngine(
        BundledDemoExecutor(source_sha256),
        advisor=lambda request, findings: {"opinions": []},
        gatekeeper=LocalDeterministicGatekeeper(),
    )
    with pytest.raises(EvidenceTamperError):
        engine.evaluate(ReleaseRequest("tamper-test", repository), policy)
