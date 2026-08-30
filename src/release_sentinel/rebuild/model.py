from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True)
class FileProposal:
    agent: str
    path: str
    content: str
    purpose: str


@dataclass(frozen=True)
class ProposalBundle:
    proposals: tuple[FileProposal, ...]
    sha256: str

    @classmethod
    def build(cls, proposals: list[FileProposal]) -> "ProposalBundle":
        payload = [p.__dict__ for p in sorted(proposals, key=lambda p: (p.path, p.agent))]
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        return cls(tuple(proposals), _sha(raw))


@dataclass(frozen=True)
class RebuildBaseline:
    source_sha256: str
    reference_sha256: str


def fingerprint_tree(root: Path) -> str:
    h = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*") if p.is_file() and ".git" not in p.parts):
        h.update(path.relative_to(root).as_posix().encode() + b"\0" + path.read_bytes() + b"\0")
    return h.hexdigest()
