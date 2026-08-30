from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def canonical_json_bytes(payload: Any) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_json(payload: Any) -> str:
    return sha256_bytes(canonical_json_bytes(payload))


def repository_sha256(repository: Path) -> str:
    root = Path(repository).resolve()
    if not root.is_dir():
        raise ValueError("repository must be an existing directory")
    digest = hashlib.sha256()
    for path in sorted(
        p
        for p in root.rglob("*")
        if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc"
    ):
        rel = path.relative_to(root).as_posix().encode("utf-8")
        digest.update(rel + b"\0" + path.read_bytes() + b"\0")
    return digest.hexdigest()
