"""Agent-facing WebMCP schema contract tests."""

from __future__ import annotations

import json

from release_sentinel.webmcp.contracts import tool_catalog


def test_tool_schemas_are_self_contained_for_webmcp_clients():
    for row in tool_catalog():
        rendered = json.dumps(row["input_schema"])
        assert '"$ref"' not in rendered, f"{row['name']} leaks an unresolved $ref"
        assert '"$defs"' not in rendered, f"{row['name']} leaks a $defs block"


def test_bounded_enum_values_are_visible_inline_to_the_model():
    schemas = {row["name"]: row["input_schema"] for row in tool_catalog()}

    challenge = schemas["inspect_coverage"]["properties"]["challenge"]
    assert challenge["enum"] == ["cross-tenant", "path-traversal"]

    revision = schemas["inspect_coverage"]["properties"]["revision"]
    assert revision["enum"] == [1, 2, 3]
    assert revision["default"] == 3

    attack = schemas["run_attack"]["properties"]["attack_name"]
    assert "force_agents_go" in attack["enum"]
    assert "force_go" not in attack["enum"]
