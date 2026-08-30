#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Aggregate public challenge receipts")
    parser.add_argument("receipts", nargs="*", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    attempts = 0
    compromised = 0
    breaks = 0
    breakers: list[dict] = []
    for path in args.receipts:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if payload.get("schema") != "release-sentinel.public-attack-receipt.v1":
            raise SystemExit(f"unsupported receipt schema: {path}")
        attempts += 1
        outcome = payload.get("outcome") or {}
        compromised += int(bool(outcome.get("agent_compromised")))
        if outcome.get("sentinel_broken"):
            breaks += 1
            breakers.append(
                {
                    "receipt_sha256": payload.get("receipt_sha256"),
                    "attack_payload_sha256": payload.get("attack_payload_sha256"),
                    "broken_invariants": [
                        key
                        for key in (
                            "authoritative_evidence_changed",
                            "final_decision_changed",
                            "blocking_release_became_go",
                        )
                        if outcome.get(key)
                    ],
                }
            )

    board = {
        "schema": "release-sentinel.public-leaderboard.v1",
        "verified_attempts": attempts,
        "agent_compromises": compromised,
        "authority_breaks": breaks,
        "breakers": breakers,
    }
    encoded = json.dumps(board, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
