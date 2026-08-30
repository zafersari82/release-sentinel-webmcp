from __future__ import annotations

import ast
from typing import Any, Callable

from release_sentinel.coverage.canonical import sha256_json
from release_sentinel.domain.evidence import Decision


def reference_policy_document(policy_revision: int) -> dict[str, Any]:
    if policy_revision == 1:
        behavior = "single-cross-tenant-probe"
    elif policy_revision == 2:
        behavior = "multi-probe-plus-canonical-shape"
    elif policy_revision == 3:
        behavior = "expanded-probes-plus-direct-identity-shape"
    else:
        raise ValueError("reference policy revision must be 1, 2, or 3")
    return {
        "id": "reference-auth-boundary-approximation",
        "revision": policy_revision,
        "behavior": behavior,
    }


def _canonical_auth_shape(source: str) -> bool:
    tree = ast.parse(source)
    functions = [node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
    if len(functions) != 1:
        return False
    target = functions[0]
    return target.name == "can_read" and [arg.arg for arg in target.args.args] == [
        "requester_tenant",
        "resource_tenant",
    ]


def _strict_identity_compare_shape(source: str) -> bool:
    """Require a direct exact-identity comparison in canonical form."""

    if not _canonical_auth_shape(source):
        return False
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare) or len(node.ops) != 1 or not isinstance(node.ops[0], ast.Eq):
            continue
        if len(node.comparators) != 1:
            continue
        left, right = node.left, node.comparators[0]
        if not isinstance(left, ast.Name) or not isinstance(right, ast.Name):
            continue
        if {left.id, right.id} == {"requester_tenant", "resource_tenant"}:
            return True
    return False


def _probes(policy_revision: int) -> tuple[tuple[Any, Any, bool], ...]:
    if policy_revision == 1:
        return (("tenant-a", "tenant-b", False),)
    if policy_revision == 2:
        return (
            ("tenant-a", "tenant-b", False),
            ("tenant-a", "tenant-a", True),
            ("Tenant-A", "tenant-a", False),
            ("tenant-a ", "tenant-a", False),
            ("tenant-a", "tenant", False),
            ("x-tenant", "tenant", False),
            ("alpha", "amber", False),
            ("aa", "bb", False),
            ("", "", False),
        )
    if policy_revision == 3:
        return (
            ("tenant-a", "tenant-b", False),
            ("tenant-a", "tenant-a", True),
            ("Tenant-A", "tenant-a", False),
            ("tenant-a ", "tenant-a", False),
            (" tenant-a", "tenant-a", False),
            ("tenant-a", "tenant", False),
            ("x-tenant", "tenant", False),
            ("alpha", "amber", False),
            ("aa", "bb", False),
            ("", "", False),
            ("équipe", "e\u0301quipe", False),
        )
    raise ValueError("reference policy revision must be 1, 2, or 3")


def evaluate_reference_gate(
    can_read: Callable[[Any, Any], Any],
    source: str,
    *,
    policy_revision: int,
) -> tuple[Decision, str]:
    """Cheap reference policies used only to expose measurable trade-offs."""

    probes = _probes(policy_revision)
    require_canonical_shape = policy_revision >= 2
    strict_identity_shape_required = policy_revision == 3
    outcomes: list[dict[str, Any]] = []
    blocked = False

    for requester, resource, expected in probes:
        try:
            actual = bool(can_read(requester, resource))
            outcomes.append({
                "requester": requester,
                "resource": resource,
                "expected": expected,
                "actual": actual,
            })
            if actual is not expected:
                blocked = True
        except Exception as exc:
            outcomes.append({
                "requester": requester,
                "resource": resource,
                "expected": expected,
                "error": type(exc).__name__,
            })
            blocked = True

    shape_ok = True
    if require_canonical_shape:
        try:
            shape_ok = _canonical_auth_shape(source)
        except (SyntaxError, ValueError, TypeError):
            shape_ok = False
        blocked = blocked or not shape_ok

    strict_identity_shape_ok = True
    if strict_identity_shape_required:
        try:
            strict_identity_shape_ok = _strict_identity_compare_shape(source)
        except (SyntaxError, ValueError, TypeError):
            strict_identity_shape_ok = False
        blocked = blocked or not strict_identity_shape_ok

    payload = {
        "check": "auth-boundary-reference-policy",
        "policy_revision": policy_revision,
        "probes": outcomes,
        "canonical_shape_required": require_canonical_shape,
        "canonical_shape_ok": shape_ok,
        "strict_identity_shape_required": strict_identity_shape_required,
        "strict_identity_shape_ok": strict_identity_shape_ok,
    }
    return (Decision.NO_GO if blocked else Decision.GO), sha256_json(payload)
