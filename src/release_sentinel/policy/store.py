from __future__ import annotations

from copy import deepcopy
from threading import RLock

from release_sentinel.policy.model import PolicyError, ReleasePolicy


class InMemoryPolicyStore:
    def __init__(self) -> None:
        self._lock = RLock()
        self._items: dict[tuple[str, int], ReleasePolicy] = {}

    def create(self, policy: ReleasePolicy) -> None:
        key = (policy.policy_id, policy.revision)
        with self._lock:
            if key in self._items:
                raise PolicyError("policy revision already exists and is immutable")
            self._items[key] = deepcopy(policy)

    def get(self, policy_id: str, revision: int) -> ReleasePolicy:
        with self._lock:
            item = self._items.get((policy_id, revision))
        if item is None:
            raise PolicyError("policy revision not found")
        return deepcopy(item)
