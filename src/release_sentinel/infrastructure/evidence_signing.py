from __future__ import annotations

import hashlib

from release_sentinel.infrastructure.kms import CloudKmsSigner


class CloudKmsEvidenceSigner:
    """Signs canonical evidence payloads using a dedicated Cloud KMS asymmetric key."""

    def __init__(self, key_version: str) -> None:
        self._signer = CloudKmsSigner(key_version)

    def sign_payload(self, payload: bytes) -> tuple[bytes, str]:
        return self._signer.sign(hashlib.sha256(payload).digest())
