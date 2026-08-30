from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Any

_JSON_SCALARS = (str, int, float, bool, type(None))


def freeze_json(value: Any) -> Any:
    """Deep-freeze JSON-shaped data without changing scalar values.

    Mappings become read-only mapping proxies and sequences become tuples.
    This is deliberately strict: trust-plane metadata must remain JSON-shaped
    so it can be canonicalized deterministically later.
    """
    if isinstance(value, _JSON_SCALARS):
        return value
    if isinstance(value, Mapping):
        frozen: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("JSON object keys must be strings")
            frozen[key] = freeze_json(item)
        return MappingProxyType(frozen)
    if isinstance(value, (list, tuple)):
        return tuple(freeze_json(item) for item in value)
    raise TypeError(f"value is not JSON-shaped: {type(value).__name__}")


def thaw_json(value: Any) -> Any:
    """Return a detached, mutable JSON representation of frozen data."""
    if isinstance(value, Mapping):
        return {str(key): thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [thaw_json(item) for item in value]
    return value
