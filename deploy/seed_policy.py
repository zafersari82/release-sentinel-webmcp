#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from release_sentinel.infrastructure.firestore import FirestorePolicyStore
from release_sentinel.policy.model import PolicyError, build_policy


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", required=True)
    parser.add_argument("--database", default="release-sentinel-policy")
    parser.add_argument("--policy", type=Path, required=True)
    args = parser.parse_args()
    policy = build_policy(json.loads(args.policy.read_text(encoding="utf-8")))
    store = FirestorePolicyStore(args.project, args.database)
    try:
        store.create(policy)
        disposition = "created"
    except PolicyError as exc:
        existing = store.get(policy.policy_id, policy.revision)
        if existing.sha256 != policy.sha256:
            raise SystemExit("policy revision exists with a different SHA-256") from exc
        disposition = "already-exists-same-sha"
    print(json.dumps({"policy_id": policy.policy_id, "revision": policy.revision, "sha256": policy.sha256, "disposition": disposition}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
