import json

import pytest

from release_sentinel.coverage.corpus import (
    EscapeCorpus,
    EscapeRecord,
    escape_id_for,
    replay_corpus,
)
from release_sentinel.coverage.models import CoverageClassification


def record(candidate="a" * 64, policy="b" * 64):
    escape_id = escape_id_for(
        candidate_sha256=candidate,
        policy_sha256=policy,
        challenge_sha256="c" * 64,
        fixture_sha256="d" * 64,
        oracle_result_sha256="e" * 64,
    )
    return EscapeRecord(
        escape_id=escape_id,
        candidate_sha256=candidate,
        policy_sha256=policy,
        challenge_sha256="c" * 64,
        fixture_sha256="d" * 64,
        oracle_result_sha256="e" * 64,
        counterexample_sha256="f" * 64,
        first_seen_receipt_sha256="1" * 64,
    )


def test_escape_id_is_context_bound_and_deterministic():
    first = record()
    second = record()
    changed_policy = record(policy="9" * 64)
    assert first.escape_id == second.escape_id
    assert first.escape_id != changed_policy.escape_id
    assert len(first.escape_id) == 64


def test_escape_corpus_persists_deduplicated_immutable_records(tmp_path):
    path = tmp_path / "escape-corpus.json"
    corpus = EscapeCorpus(path)
    item = record()
    assert corpus.add(item) is True
    assert corpus.add(item) is False
    loaded = EscapeCorpus(path).records()
    assert loaded == (item,)
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["schema"] == "release-sentinel.escape-corpus.v1"
    assert len(payload["records"]) == 1


def test_escape_corpus_refuses_conflicting_record_with_same_id(tmp_path):
    corpus = EscapeCorpus(tmp_path / "escape-corpus.json")
    item = record()
    corpus.add(item)
    conflicting = EscapeRecord(
        **{**item.to_dict(), "counterexample_sha256": "8" * 64}
    )
    with pytest.raises(ValueError, match="conflicting"):
        corpus.add(conflicting)


def test_replay_detects_historical_escape_regression():
    records = (record("a" * 64), record("2" * 64))

    def evaluator(item):
        if item.candidate_sha256 == "a" * 64:
            return CoverageClassification.CORRECT_BLOCK
        return CoverageClassification.ESCAPE

    summary = replay_corpus(records, evaluator)
    assert summary.tested == 2
    assert summary.blocked == 1
    assert summary.regressions == 1
    assert summary.other == 0
    assert summary.to_dict()["status"] == "COVERAGE_REGRESSION"


def test_replay_without_escape_regression_reports_clean(tmp_path):
    item = record()
    summary = replay_corpus((item,), lambda _item: CoverageClassification.CORRECT_BLOCK)
    assert summary.regressions == 0
    assert summary.to_dict()["status"] == "CLEAN"
