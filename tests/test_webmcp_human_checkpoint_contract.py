from pathlib import Path

ROOT = Path(__file__).parents[1]
HTML = ROOT / "src/release_sentinel/interfaces/static/arena.html"
JS = ROOT / "src/release_sentinel/interfaces/static/arena.js"


def test_human_checkpoint_is_explicit_and_non_authoritative():
    html = HTML.read_text(encoding="utf-8")
    js = JS.read_text(encoding="utf-8")

    assert 'id="humanProofCard"' in html
    assert 'id="verifyHumanProof"' in html
    assert 'id="humanProofStatus"' in html
    assert 'id="humanOldHash"' in html
    assert 'id="humanNewHash"' in html
    assert 'id="humanGateVerdict"' in html
    assert 'id="humanGateAuthority"' in html
    assert html.index('id="agentTimeline"') < html.index('id="humanProofCard"')
    assert "Agent work is complete. Don’t trust it — verify it." in html
    assert "UNVERIFIED BY HUMAN" in html

    assert "state.reverify" in js
    assert "state.candidate.new_source_sha256" in js
    assert "proof.source_sha256" in js
    assert "evidence_integrity_verified" in js
    assert "context_bound" in js
    assert "proof.authority" in js
    assert "DETERMINISTIC_" in js
    assert "VERIFIED BY HUMAN" in js
    assert "VERIFICATION FAILED" in js

    # A human verification state is evidence UX, never a release-authority API.
    assert "set_verdict" not in js
    assert "approve_release" not in js
    assert "override_gatekeeper" not in js
