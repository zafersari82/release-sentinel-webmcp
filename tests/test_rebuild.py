import pytest

from release_sentinel.rebuild.model import FileProposal, ProposalBundle, RebuildBaseline
from release_sentinel.rebuild.service import CandidateWriter, RebuildError


BASELINE = RebuildBaseline("a" * 64, "b" * 64)


def proposal_bundle():
    return ProposalBundle.build([FileProposal("backend", "src/app.py", "print(1)", "app")])


def pins(bundle):
    return {
        "pinned_source_sha256": "a" * 64,
        "pinned_reference_sha256": "b" * 64,
        "pinned_bundle_sha256": bundle.sha256,
    }


def test_writer_requires_empty_workspace(tmp_path):
    (tmp_path / "x").write_text("x", encoding="utf-8")
    bundle = proposal_bundle()

    with pytest.raises(RebuildError):
        CandidateWriter().apply(tmp_path, bundle, BASELINE, **pins(bundle))


def test_writer_requires_three_external_pins(tmp_path):
    bundle = proposal_bundle()
    expected_pins = pins(bundle)
    expected_pins["pinned_bundle_sha256"] = "0" * 64

    with pytest.raises(RebuildError):
        CandidateWriter().apply(tmp_path, bundle, BASELINE, **expected_pins)


def test_writer_commits_after_pins(tmp_path):
    bundle = proposal_bundle()

    written = CandidateWriter().apply(tmp_path, bundle, BASELINE, **pins(bundle))

    assert written == 1
    assert (tmp_path / "src/app.py").read_text(encoding="utf-8") == "print(1)"


@pytest.mark.parametrize("path", ["../x", "/tmp/x", ".release-sentinel/control.json"])
def test_writer_rejects_control_or_escape_paths(tmp_path, path):
    bundle = ProposalBundle.build([FileProposal("x", path, "x", "x")])

    with pytest.raises(RebuildError):
        CandidateWriter().apply(tmp_path, bundle, BASELINE, **pins(bundle))
