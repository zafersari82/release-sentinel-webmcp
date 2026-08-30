from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Protocol


class Signer(Protocol):
    def sign(self, digest: bytes) -> tuple[bytes, str]: ...


@dataclass(frozen=True)
class SignedProvenance:
    manifest: dict[str, Any]
    manifest_sha256: str
    signature_hex: str | None
    key_version: str | None


def build_provenance(manifest: dict[str, Any], signer: Signer | None = None, *, signing_required: bool = False) -> SignedProvenance:
    raw = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    digest = hashlib.sha256(raw).digest()
    if signer is None:
        if signing_required:
            raise RuntimeError("provenance signing is required")
        return SignedProvenance(manifest, digest.hex(), None, None)
    signature, key_version = signer.sign(digest)
    return SignedProvenance(manifest, digest.hex(), signature.hex(), key_version)
