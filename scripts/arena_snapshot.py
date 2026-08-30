#!/usr/bin/env python3
from __future__ import annotations
import json
from release_sentinel.public_challenge.evaluator import public_snapshot
print(json.dumps(public_snapshot(), indent=2, sort_keys=True))
