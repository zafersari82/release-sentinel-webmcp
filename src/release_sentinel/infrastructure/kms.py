from __future__ import annotations


class CloudKmsSigner:
    """Asymmetric SHA-256 signer. Private key material never enters the service."""

    def __init__(self, key_version: str) -> None:
        if "/cryptoKeyVersions/" not in key_version:
            raise ValueError("KMS key version must be a full CryptoKeyVersion resource name")
        from google.cloud import kms
        self._client = kms.KeyManagementServiceClient()
        self._key_version = key_version

    def sign(self, digest: bytes) -> tuple[bytes, str]:
        if len(digest) != 32:
            raise ValueError("CloudKmsSigner expects a SHA-256 digest")
        response = self._client.asymmetric_sign(
            request={"name": self._key_version, "digest": {"sha256": digest}}
        )
        return bytes(response.signature), self._key_version
