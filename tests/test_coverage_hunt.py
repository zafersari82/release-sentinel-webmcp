import pytest

from release_sentinel.coverage.hunt import (
    HuntProposal,
    record_hunt_attempt,
    summarize_hunt,
)
from release_sentinel.coverage.models import CoverageClassification


def test_model_payload_can_only_create_candidate_proposal_not_authoritative_result():
    proposal = HuntProposal.from_model_payload(
        {
            "source": "def can_read(a, b):\n    return a == b\n",
            "rationale": "try an equivalent-looking boundary change",
        },
        proposer_id="gemini-hunter",
    )
    assert proposal.proposer_id == "gemini-hunter"
    assert proposal.authority == "NONE"
    assert len(proposal.proposal_sha256) == 64


@pytest.mark.parametrize("forbidden", ["oracle_verdict", "classification", "gate_decision", "receipt", "authority"])
def test_model_payload_cannot_smuggle_authoritative_fields(forbidden):
    payload = {
        "source": "def can_read(a, b):\n    return True\n",
        "rationale": "attack",
        forbidden: "ESCAPE",
    }
    with pytest.raises(ValueError, match="authoritative"):
        HuntProposal.from_model_payload(payload, proposer_id="gemini-hunter")


def test_hunt_summary_counts_attempts_and_new_escapes_only():
    p1 = HuntProposal.from_model_payload(
        {"source": "def can_read(a,b):\n    return True\n", "rationale": "a"}, proposer_id="hunter"
    )
    p2 = HuntProposal.from_model_payload(
        {"source": "def can_read(a,b):\n    return a == b\n", "rationale": "b"}, proposer_id="hunter"
    )
    attempts = [
        record_hunt_attempt(p1, CoverageClassification.ESCAPE),
        record_hunt_attempt(p2, CoverageClassification.CORRECT_ACCEPT),
    ]
    summary = summarize_hunt(attempts)
    assert summary.attempts == 2
    assert summary.new_escapes == 1
    assert summary.to_dict() == {
        "attempts": 2,
        "new_escapes": 1,
        "invalid": 0,
        "lane": "ADAPTIVE_NON_STATISTICAL",
        "agent_authority": "NONE",
    }
