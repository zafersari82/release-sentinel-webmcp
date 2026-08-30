"""Contract tests for the guided demo.

The guided demo is a first-visit narration layer. It must replay the bounded
agent workflow through the SAME registered tool handlers a WebMCP agent uses,
and it must never introduce a capability, endpoint, or authority path that the
agent does not already have.
"""

from pathlib import Path

ROOT = Path(__file__).parents[1]
HTML = ROOT / "src/release_sentinel/interfaces/static/arena.html"
JS = ROOT / "src/release_sentinel/interfaces/static/arena.js"
CSS = ROOT / "src/release_sentinel/interfaces/static/arena.css"


def test_guided_demo_entry_point_is_present_and_prominent():
    html = HTML.read_text(encoding="utf-8")

    assert 'id="guidedDemo"' in html
    assert 'id="runGuidedDemo"' in html
    assert 'id="stopGuidedDemo"' in html
    assert 'id="guidedNarration"' in html
    assert 'id="guidedStepLabel"' in html
    assert 'id="guidedHeadline"' in html
    assert 'id="guidedPlain"' in html
    assert 'id="guidedTech"' in html

    # The guided entry point must sit above the workflow it narrates, so a
    # first-time judge meets it before any jargon-heavy panel.
    assert html.index('id="guidedDemo"') < html.index('id="attackPanel"')
    assert html.index('id="guidedDemo"') < html.index('id="coveragePanel"')
    assert html.index('id="guidedDemo"') < html.index('id="remediationPanel"')

    # The narration region must be announced for assistive technology.
    assert 'aria-live="polite"' in html


def test_guided_demo_drives_only_registered_bounded_tools():
    js = JS.read_text(encoding="utf-8")
    guided = js[js.index("function guidedSteps()"):js.index("function setGuidedRunning")]

    # Every capability the guided demo exercises must go through invokeTool,
    # which is the same path document.modelContext.registerTool() executes.
    driven = {
        "inspect_release",
        "inspect_trust_boundary",
        "run_attack_suite",
        "compare_gate_revisions",
        "find_counterexamples",
        "minimize_counterexample",
        "propose_remediation",
        "rebuild_candidate",
        "reverify_candidate",
    }
    for tool in driven:
        assert f"invokeTool('{tool}'" in guided, f"guided demo must drive {tool} through invokeTool"

    # No direct network access: the guided demo may not bypass the tool layer.
    assert "fetch(" not in guided
    assert "request(" not in guided
    assert "XMLHttpRequest" not in guided


def test_guided_demo_creates_no_authority_surface():
    js = JS.read_text(encoding="utf-8")

    for forbidden in (
        "set_verdict",
        "force_go",
        "approve_release",
        "override_gatekeeper",
        "disable_policy",
        "edit_evidence",
    ):
        assert forbidden not in js, f"arena must not expose {forbidden}"

    # The closing narration must restate the invariant rather than imply the
    # agent achieved authority.
    assert "0 of them authoritative" in js
    assert "It never approved anything." in js


def test_guided_demo_is_interruptible_and_degrades_closed():
    js = JS.read_text(encoding="utf-8")

    assert "guided.aborted" in js
    assert "setGuidedRunning(false)" in js
    # A guided run must survive a fail-closed dependency without claiming success.
    assert "gate stayed closed" in js
    assert "step failed" in js


def test_plain_language_layer_explains_jargon_terms():
    html = HTML.read_text(encoding="utf-8")
    css = CSS.read_text(encoding="utf-8")

    assert 'class="plain"' in html
    assert ".plain{" in css

    # The three terms most likely to lose a first-time reader.
    assert "<b>Escapes</b>" in html
    assert "<b>Overblocks</b>" in html
    assert "fingerprint" in html


def test_arena_declares_icon_and_description_metadata():
    html = HTML.read_text(encoding="utf-8")

    assert 'rel="icon"' in html
    assert 'name="description"' in html
