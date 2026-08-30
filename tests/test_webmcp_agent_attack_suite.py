"""Regression tests for the agent-only bounded WebMCP attack suite."""

from __future__ import annotations

from pathlib import Path

from release_sentinel.webmcp.contracts import AttackName, CapabilityClass, TOOL_DEFINITIONS, tool_catalog

ROOT = Path(__file__).parents[1]
ARENA_JS = ROOT / "src/release_sentinel/interfaces/static/arena.js"
ARENA_HTML = ROOT / "src/release_sentinel/interfaces/static/arena.html"


def _tool(name: str):
    return next(item for item in TOOL_DEFINITIONS if item.name == name)


def test_attack_suite_is_the_twelfth_agent_facing_challenge_tool():
    tools = tool_catalog()
    assert len(tools) == 12

    suite = _tool("run_attack_suite")
    assert suite.capability is CapabilityClass.CHALLENGE
    assert suite.request_model.model_fields == {}
    assert suite.input_schema.get("properties", {}) == {}
    assert "complete bounded" in suite.description.lower()
    assert "verdict" in suite.description.lower()


def test_attack_suite_reuses_authoritative_run_attack_enum():
    run_attack = _tool("run_attack")
    schema_names = run_attack.input_schema["properties"]["attack_name"]["enum"]
    authoritative_names = [item.value for item in AttackName]
    assert schema_names == authoritative_names
    assert len(authoritative_names) == 8


def test_attack_suite_is_agent_only_with_no_human_control():
    arena_html = ARENA_HTML.read_text(encoding="utf-8")
    arena_js = ARENA_JS.read_text(encoding="utf-8")

    assert "data-attack-suite" not in arena_html
    assert "#runAttackSuite" not in arena_js
    assert "data-attack-suite" not in arena_js


def test_browser_orchestration_derives_attacks_from_registered_schema():
    arena_js = ARENA_JS.read_text(encoding="utf-8")

    assert "run_attack_suite:" in arena_js
    assert "properties?.attack_name?.enum" in arena_js
    assert "state.catalog?.tools?.find" in arena_js
    assert "for (const attackName of attackNames)" in arena_js
    assert "await toolHandlers.run_attack" in arena_js

    # JavaScript must not duplicate the authoritative Python attack inventory.
    for attack_name in AttackName:
        assert f"'{attack_name.value}'" not in arena_js
        assert f'"{attack_name.value}"' not in arena_js


def test_browser_orchestration_exposes_deterministic_aggregate_fields():
    arena_js = ARENA_JS.read_text(encoding="utf-8")

    for field in (
        "attacks_requested",
        "attacks_executed",
        "contained_count",
        "all_contained",
        "unexpected_authority_gains",
        "max_agent_influence",
        "final_verdicts",
        "MIXED_AUTHORITY",
        "NO_RELEASE_AUTHORITY",
    ):
        assert field in arena_js

    assert "8/8 attacks contained" not in arena_js
    assert "max agent influence" in arena_js
