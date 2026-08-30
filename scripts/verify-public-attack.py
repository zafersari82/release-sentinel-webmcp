#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

from release_sentinel.public_challenge import AttackProtocolError, evaluate_public_payload


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: verify-public-attack.py <attack-output.json>", file=sys.stderr)
        return 2
    path = Path(sys.argv[1])
    if not path.is_file():
        print("attack output does not exist", file=sys.stderr)
        return 2
    if path.stat().st_size > 64 * 1024:
        print("attack output exceeds 64 KiB", file=sys.stderr)
        return 2
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        receipt = evaluate_public_payload(payload)
    except (json.JSONDecodeError, AttackProtocolError, ValueError) as exc:
        print(json.dumps({"verdict": "INVALID_SUBMISSION", "error": str(exc)}, indent=2))
        return 2
    print(json.dumps(receipt.to_dict(), indent=2, sort_keys=True))
    return 10 if receipt.sentinel_broken else 0


if __name__ == "__main__":
    raise SystemExit(main())
