from __future__ import annotations

import base64
import hashlib
import hmac
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from release_sentinel.coverage.canonical import canonical_json_bytes, sha256_bytes
from release_sentinel.infrastructure.kms import CloudKmsSigner


class Signer(Protocol):
    @property
    def key_id(self) -> str: ...

    @property
    def algorithm(self) -> str: ...

    def sign(self, payload: bytes) -> bytes: ...


class Verifier(Protocol):
    def verify(self, payload: bytes, signature: bytes, *, key_id: str, algorithm: str) -> bool: ...


@dataclass(frozen=True)
class SignatureEnvelope:
    payload_sha256: str
    signature_b64: str
    key_id: str
    algorithm: str

    def signature_bytes(self) -> bytes:
        return base64.b64decode(self.signature_b64.encode("ascii"), validate=True)

    def to_dict(self) -> dict[str, str]:
        return {
            "payload_sha256": self.payload_sha256,
            "signature_b64": self.signature_b64,
            "key_id": self.key_id,
            "algorithm": self.algorithm,
        }


def sign_json(payload: dict, signer: Signer) -> SignatureEnvelope:
    raw = canonical_json_bytes(payload)
    signature = signer.sign(raw)
    return SignatureEnvelope(
        payload_sha256=sha256_bytes(raw),
        signature_b64=base64.b64encode(signature).decode("ascii"),
        key_id=signer.key_id,
        algorithm=signer.algorithm,
    )


def verify_json(payload: dict, envelope: SignatureEnvelope, verifier: Verifier) -> bool:
    raw = canonical_json_bytes(payload)
    if not hmac.compare_digest(sha256_bytes(raw), envelope.payload_sha256):
        return False
    try:
        signature = envelope.signature_bytes()
    except Exception:
        return False
    return verifier.verify(
        raw,
        signature,
        key_id=envelope.key_id,
        algorithm=envelope.algorithm,
    )


class HmacSha256Authority:
    """Deterministic test authority; never used as the production trust anchor."""

    def __init__(self, secret: bytes, key_id: str) -> None:
        if not secret:
            raise ValueError("HMAC test secret must be non-empty")
        if not key_id:
            raise ValueError("key_id must be non-empty")
        self._secret = bytes(secret)
        self._key_id = key_id

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def algorithm(self) -> str:
        return "HMAC_SHA256_TEST_ONLY"

    def sign(self, payload: bytes) -> bytes:
        return hmac.new(self._secret, payload, hashlib.sha256).digest()

    def verify(self, payload: bytes, signature: bytes, *, key_id: str, algorithm: str) -> bool:
        if key_id != self.key_id or algorithm != self.algorithm:
            return False
        return hmac.compare_digest(self.sign(payload), signature)


class CloudKmsCoverageSigner:
    """Production asymmetric signer backed by a purpose-specific Cloud KMS key."""

    def __init__(self, key_version: str) -> None:
        self._kms = CloudKmsSigner(key_version)
        self._key_id = key_version

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def algorithm(self) -> str:
        return "EC_SIGN_P256_SHA256"

    def sign(self, payload: bytes) -> bytes:
        signature, _ = self._kms.sign(hashlib.sha256(payload).digest())
        return signature


class OpenSslSha256Verifier:
    """Verify Cloud KMS SHA-256 asymmetric signatures without private-key access."""

    def __init__(self, public_key_pem: str, *, key_id: str, algorithm: str = "EC_SIGN_P256_SHA256") -> None:
        if "BEGIN PUBLIC KEY" not in public_key_pem:
            raise ValueError("public_key_pem must contain a PEM public key")
        self._public_key_pem = public_key_pem
        self._key_id = key_id
        self._algorithm = algorithm

    def verify(self, payload: bytes, signature: bytes, *, key_id: str, algorithm: str) -> bool:
        if key_id != self._key_id or algorithm != self._algorithm:
            return False
        with tempfile.TemporaryDirectory(prefix="rs-coverage-verify-") as tmp:
            root = Path(tmp)
            public_key = root / "public.pem"
            payload_path = root / "payload.bin"
            signature_path = root / "signature.bin"
            public_key.write_text(self._public_key_pem, encoding="utf-8")
            payload_path.write_bytes(payload)
            signature_path.write_bytes(signature)
            proc = subprocess.run(
                [
                    "openssl",
                    "dgst",
                    "-sha256",
                    "-verify",
                    str(public_key),
                    "-signature",
                    str(signature_path),
                    str(payload_path),
                ],
                capture_output=True,
                check=False,
                timeout=5,
            )
            return proc.returncode == 0
