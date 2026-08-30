"""The one-line fix: enforce the boundary where the untrusted stage is called."""

from __future__ import annotations

import functools
from typing import Any, Callable, TypeVar

from .seal import SealBroken, fingerprint, seal

__all__ = ["sealed_stage"]

F = TypeVar("F", bound=Callable[..., Any])


def sealed_stage(func: F) -> F:
    """Hand a sealed projection to ``func`` and verify nothing moved.

    Two defences, because either alone has been enough to fail in practice:

    1. Every argument is replaced by a deeply immutable projection, so the
       stage holds no reference that reaches your live objects.
    2. The originals are fingerprinted before and after. If anything moved
       anyway — through a path the projection missed, a deferred mutation, or
       another thread — ``SealBroken`` is raised and no artifact is produced.

    Fail-closed on purpose: a pipeline that cannot prove its evidence survived
    the stage unchanged should not produce a signed artifact at all.

        @sealed_stage
        def advisory(evidence):
            return llm.review(evidence)
    """

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        before = fingerprint([args, kwargs])
        sealed_args = tuple(seal(arg) for arg in args)
        sealed_kwargs = {key: seal(value) for key, value in kwargs.items()}
        try:
            return func(*sealed_args, **sealed_kwargs)
        finally:
            if fingerprint([args, kwargs]) != before:
                raise SealBroken(
                    f"{func.__qualname__} altered sealed input; no artifact was produced"
                )

    return wrapper  # type: ignore[return-value]
