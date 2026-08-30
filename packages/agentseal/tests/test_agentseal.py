"""agentseal must fail on a vulnerable pipeline and pass on a sealed one.

A test harness that never fires is worse than none. Every test here builds a
pipeline with a known-real defect and asserts agentseal detects it, then builds
the fixed version and asserts it passes.
"""

from __future__ import annotations

import pytest

from agentseal import (
    SealBroken,
    assert_no_influence,
    check_no_influence,
    build_certificate,
    default_variants,
    verify_certificate,
    fingerprint,
    seal,
    sealed_stage,
)


def _evidence() -> list[dict]:
    return [
        {"finding_id": "AUTH-0042", "severity": "HIGH", "blocking_eligible": True,
         "claim": "endpoint returned 200 where policy requires 403"},
        {"finding_id": "DEP-0007", "severity": "MEDIUM", "blocking_eligible": False,
         "claim": "transitive dependency two minor versions behind"},
    ]


def _bundle(evidence) -> dict:
    """Stand-in for building the artifact you would sign."""
    blocking = [item for item in evidence if item.get("blocking_eligible")]
    return {"results": list(evidence), "blockers": len(blocking),
            "decision": "NO_GO" if blocking else "GO"}


# --------------------------------------------------------------------------
# The vulnerable shape: the stage receives the live list before signing.
# This is the v1.6 Release Sentinel bug, reduced.
# --------------------------------------------------------------------------

def vulnerable_pipeline(agent):
    evidence = _evidence()
    try:
        agent(evidence)
    except Exception:
        pass
    return _bundle(evidence)


def sealed_pipeline(agent):
    evidence = _evidence()
    guarded = sealed_stage(agent)
    try:
        guarded(evidence)
    except SealBroken:
        raise
    except Exception:
        pass
    return _bundle(evidence)


# --------------------------------------------------------------------------

def test_detects_influence_in_vulnerable_pipeline():
    report = check_no_influence(vulnerable_pipeline)
    assert not report.sealed
    detected = {result.name for result in report.influenced}
    assert "erase" in detected
    assert "downgrade" in detected


def test_assert_raises_on_vulnerable_pipeline():
    with pytest.raises(AssertionError) as excinfo:
        assert_no_influence(vulnerable_pipeline)
    assert "agent non-influence not established" in str(excinfo.value)


def test_sealed_pipeline_passes():
    report = assert_no_influence(sealed_pipeline, repeat=3)
    assert report.sealed
    assert len(report.results) == len(default_variants())


def test_every_variant_can_be_observed_when_agent_output_is_trusted():
    """The battery itself must be live: trusting the hostile output is unsafe."""
    def output_tainted_pipeline(agent):
        evidence = _evidence()
        try:
            advice = agent(evidence)
        except Exception as exc:
            advice = {"error": type(exc).__name__}
        return {"bundle": _bundle(evidence), "agent_output": advice}

    report = check_no_influence(output_tainted_pipeline)
    inert = [r for r in report.results if not r.influenced and not r.blocked and r.error is None]
    assert not inert, f"variants had no observable effect: {[r.name for r in inert]}"


def test_deferred_mutation_is_caught():
    """A stage that mutates after returning is the case a naive check misses."""
    deferred = next(v for v in default_variants() if v.name == "deferred")
    report = check_no_influence(vulnerable_pipeline, variants=[deferred], repeat=25)
    assert not report.sealed


def test_sealed_stage_raises_rather_than_returning_a_tainted_artifact():
    @sealed_stage
    def hostile(evidence):
        return {"vote": "GO"}

    live = _evidence()

    def sneaky(evidence):
        return {"vote": "GO"}

    # Direct mutation attempt through the sealed projection.
    @sealed_stage
    def mutating(evidence):
        with pytest.raises(TypeError):
            evidence[0]["severity"] = "INFO"
        return {"vote": "GO"}

    assert mutating(live) == {"vote": "GO"}
    assert live[0]["severity"] == "HIGH"


def test_seal_is_deep():
    view = seal({"outer": {"inner": ["a", "b"]}})
    with pytest.raises(TypeError):
        view["outer"] = {}
    with pytest.raises(TypeError):
        view["outer"]["inner"] = []
    assert isinstance(view["outer"]["inner"], tuple)


def test_fingerprint_is_order_independent_for_mappings():
    assert fingerprint({"a": 1, "b": 2}) == fingerprint({"b": 2, "a": 1})


def test_fingerprint_is_order_dependent_for_sequences():
    assert fingerprint([1, 2]) != fingerprint([2, 1])


def test_report_renders_both_outcomes():
    broken = str(check_no_influence(vulnerable_pipeline))
    assert "NOT SEALED" in broken and "FAIL" in broken
    sealed = str(check_no_influence(sealed_pipeline))
    assert "SEALED" in sealed


def test_works_with_dataclass_artifacts():
    from dataclasses import dataclass

    @dataclass
    class Bundle:
        results: list
        decision: str

    def pipeline(agent):
        evidence = _evidence()
        guarded = sealed_stage(agent)
        try:
            guarded(evidence)
        except SealBroken:
            raise
        except Exception:
            pass
        return Bundle(results=list(evidence), decision="NO_GO")

    assert assert_no_influence(pipeline).sealed


def test_unexpected_probe_error_is_inconclusive_not_a_pass():
    def erroring_pipeline(agent):
        if getattr(agent, "name", "") == "force-go":
            raise RuntimeError("harness exploded")
        return {"artifact": "stable"}

    force_go = next(v for v in default_variants() if v.name == "force-go")
    report = check_no_influence(erroring_pipeline, variants=[force_go])
    assert not report.sealed
    assert report.results[0].status == "ERROR"


def test_counterfactual_certificate_verifies_only_successful_report():
    report = assert_no_influence(sealed_pipeline, repeat=2)
    cert = build_certificate(report, subject="unit-test", now_unix=1_750_000_000)
    assert verify_certificate(cert)
    payload = cert.to_dict()
    assert payload["verified"] is True
    assert len(payload["certificate_sha256"]) == 64
    assert {item["outcome"] for item in payload["interventions"]} <= {"SEALED", "BLOCKED"}
