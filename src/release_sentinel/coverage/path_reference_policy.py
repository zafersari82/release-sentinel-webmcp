from __future__ import annotations

import ast
from typing import Any, Callable

from release_sentinel.coverage.canonical import sha256_json
from release_sentinel.coverage.path_oracle import PathTraversalOracle
from release_sentinel.domain.evidence import Decision


def path_reference_policy_document(policy_revision: int) -> dict[str, Any]:
    behavior = {
        1: "single-dotdot-probe",
        2: "multi-probe-plus-approved-containment-shape",
        3: "oracle-vector-probes-plus-commonpath-shape",
    }.get(policy_revision)
    if behavior is None:
        raise ValueError("path reference policy revision must be 1, 2, or 3")
    return {
        "id": "reference-path-containment-approximation",
        "revision": policy_revision,
        "behavior": behavior,
    }


def _path_signature_ok(source: str) -> bool:
    tree = ast.parse(source)
    functions = [node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
    targets = [node for node in functions if node.name == "can_open_path"]
    if len(targets) != 1:
        return False
    return [arg.arg for arg in targets[0].args.args] == ["base_dir", "requested_path", "resolved_target"]


def _called_attributes(source: str) -> set[str]:
    tree = ast.parse(source)
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            names.add(node.func.attr)
    return names


def _assigned_names(source: str) -> set[str]:
    tree = ast.parse(source)
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            names.add(node.id)
    return names


def _approved_rev2_shape(source: str) -> bool:
    if not _path_signature_ok(source):
        return False
    calls = _called_attributes(source)
    # The local demo deliberately treats a hand-written deny set as an approved
    # cheap policy shape so the balanced revision can still have residual escapes.
    return bool({"commonpath", "relpath"} & calls) or "blocked" in _assigned_names(source)


def _strict_rev3_shape(source: str) -> bool:
    if not _path_signature_ok(source):
        return False
    calls = _called_attributes(source)
    return "commonpath" in calls and "unquote" in source


def _rev1_probes() -> tuple[tuple[Any, Any, Any, bool], ...]:
    return (("/srv/assets", "../secret.txt", "/srv/secret.txt", False),)


def _rev2_probes() -> tuple[tuple[Any, Any, Any, bool], ...]:
    base = "/srv/assets"
    return (
        (base, "images/logo.png", f"{base}/images/logo.png", True),
        (base, "../secret.txt", "/srv/secret.txt", False),
        (base, "%2e%2e/secret.txt", "/srv/secret.txt", False),
        (base, "..\\secret.txt", "/srv/secret.txt", False),
        (base, "/etc/passwd", "/etc/passwd", False),
        (base, "link/passwd", "/etc/passwd", False),
        (base, "file.txt", "/srv/assets_evil/file.txt", False),
        (base, "", base, False),
    )


def _rev3_probes() -> tuple[tuple[Any, Any, Any, bool], ...]:
    return tuple(
        (vector.base_dir, vector.requested_path, vector.resolved_target, vector.expected)
        for vector in PathTraversalOracle().vectors
    )


def evaluate_path_reference_gate(
    can_open_path: Callable[..., Any],
    source: str,
    *,
    policy_revision: int,
) -> tuple[Decision, str]:
    if policy_revision == 1:
        probes = _rev1_probes()
        shape_required = "NONE"
        shape_ok = True
    elif policy_revision == 2:
        probes = _rev2_probes()
        shape_required = "APPROVED_CONTAINMENT"
        try:
            shape_ok = _approved_rev2_shape(source)
        except (SyntaxError, TypeError, ValueError):
            shape_ok = False
    elif policy_revision == 3:
        probes = _rev3_probes()
        shape_required = "COMMONPATH_PLUS_UNQUOTE"
        try:
            shape_ok = _strict_rev3_shape(source)
        except (SyntaxError, TypeError, ValueError):
            shape_ok = False
    else:
        raise ValueError("path reference policy revision must be 1, 2, or 3")

    outcomes: list[dict[str, Any]] = []
    blocked = not shape_ok
    for base, request, resolved, expected in probes:
        try:
            actual = bool(can_open_path(base, request, resolved))
            outcomes.append(
                {
                    "base_dir": base,
                    "requested_path": request,
                    "resolved_target": resolved,
                    "expected": expected,
                    "actual": actual,
                }
            )
            if actual is not expected:
                blocked = True
        except Exception as exc:
            outcomes.append(
                {
                    "base_dir": base,
                    "requested_path": request,
                    "resolved_target": resolved,
                    "expected": expected,
                    "error": type(exc).__name__,
                }
            )
            blocked = True

    payload = {
        "check": "path-containment-reference-policy",
        "policy_revision": policy_revision,
        "probes": outcomes,
        "shape_required": shape_required,
        "shape_ok": shape_ok,
    }
    return (Decision.NO_GO if blocked else Decision.GO), sha256_json(payload)
