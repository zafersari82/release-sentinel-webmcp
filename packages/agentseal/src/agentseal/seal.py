"""Sealing primitives: deep immutability and canonical fingerprinting."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence, Set
from dataclasses import fields, is_dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any

__all__ = ["seal", "fingerprint", "canonical_bytes", "SealBroken"]


class SealBroken(RuntimeError):
    """Raised when sealed data changed across a stage that must not affect it."""


_SCALARS = (str, int, float, bool, type(None))


def _plain(value: Any) -> Any:
    """Reduce arbitrary Python data to JSON-shaped primitives.

    Handles the shapes real pipelines actually carry: dataclasses, enums,
    mappings, sequences, sets, and objects exposing to_dict().

    Dataclass fields are walked manually rather than via ``dataclasses.asdict``,
    which deep-copies and therefore fails on exactly the deeply-frozen
    structures a well-sealed pipeline produces (``mappingproxy`` cannot be
    pickled). Reading a value must never require the ability to copy it.
    """
    if isinstance(value, _SCALARS):
        return value
    if isinstance(value, Enum):
        return _plain(value.value)
    to_dict = getattr(value, "to_dict", None)
    if callable(to_dict):
        return _plain(to_dict())
    if is_dataclass(value) and not isinstance(value, type):
        return {f.name: _plain(getattr(value, f.name)) for f in fields(value)}
    if isinstance(value, Mapping):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, Set):
        return sorted(_plain(v) for v in value)
    if isinstance(value, (bytes, bytearray)):
        return value.hex()
    if isinstance(value, Sequence):
        return [_plain(v) for v in value]
    return repr(value)


def _freeze(value: Any) -> Any:
    if isinstance(value, _SCALARS):
        return value
    if isinstance(value, Mapping):
        return MappingProxyType({k: _freeze(v) for k, v in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(v) for v in value)
    return value


def seal(data: Any) -> Any:
    """Return a deeply immutable, JSON-shaped projection of ``data``.

    This is what an untrusted stage should receive instead of your live
    objects. Mappings become read-only proxies, sequences become tuples, and
    domain objects are flattened, so a reference held by that stage reaches
    nothing your pipeline will later sign.

    >>> view = seal({"severity": "HIGH", "evidence": [{"id": "E1"}]})
    >>> view["severity"] = "INFO"
    Traceback (most recent call last):
    TypeError: ...
    """
    return _freeze(_plain(data))


def canonical_bytes(data: Any) -> bytes:
    """Deterministic byte encoding, stable across dict ordering."""
    return json.dumps(
        _plain(data), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def fingerprint(data: Any) -> str:
    """SHA-256 over the canonical encoding of ``data``."""
    return hashlib.sha256(canonical_bytes(data)).hexdigest()
