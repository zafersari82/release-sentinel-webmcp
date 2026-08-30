from __future__ import annotations

import atexit
import base64
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol
from uuid import uuid4

from release_sentinel.domain.evidence import EvidenceIntegrityError, finding_set_sha256
from release_sentinel.domain.immutable import freeze_json, thaw_json
from release_sentinel.domain.release import ReleaseReport


SCHEMA = "release-sentinel.evidence-bundle.v1"
DEFAULT_TTL_SECONDS = 300
_EPHEMERAL_KEY_ID = "ephemeral-offline-demo-key-not-for-verification"
_EPHEMERAL_KEY_PATH: Path | None = None
_EPHEMERAL_KEY_DIR: Path | None = None


class EvidenceSigner(Protocol):
    def sign_payload(self, payload: bytes) -> tuple[bytes, str]: ...


@dataclass(frozen=True)
class EvidenceBundle:
    schema: str
    release_id: str
    source_sha256: str
    execution_id: str
    nonce: str
    issued_at_unix: int
    expires_at_unix: int
    policy_id: str
    policy_revision: int
    policy_sha256: str
    execution_count: int
    results: tuple[Mapping[str, Any], ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "results", tuple(freeze_json(item) for item in self.results))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "release_id": self.release_id,
            "source_sha256": self.source_sha256,
            "execution_id": self.execution_id,
            "nonce": self.nonce,
            "issued_at_unix": self.issued_at_unix,
            "expires_at_unix": self.expires_at_unix,
            "policy_id": self.policy_id,
            "policy_revision": self.policy_revision,
            "policy_sha256": self.policy_sha256,
            "execution_count": self.execution_count,
            "results": [thaw_json(item) for item in self.results],
        }


@dataclass(frozen=True)
class SignedEvidenceBundle:
    bundle: Mapping[str, Any]
    bundle_sha256: str
    signature_base64: str
    key_id: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "bundle", freeze_json(self.bundle))

    def to_dict(self) -> dict[str, Any]:
        return {
            "bundle": thaw_json(self.bundle),
            "bundle_sha256": self.bundle_sha256,
            "signature_base64": self.signature_base64,
            "key_id": self.key_id,
        }


def canonical_bytes(bundle: Mapping[str, Any]) -> bytes:
    return json.dumps(thaw_json(bundle), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _evidence_digest(finding: Any) -> str:
    raw = json.dumps(finding.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def build_evidence_bundle(
    report: ReleaseReport,
    *,
    source_sha256: str,
    now_unix: int | None = None,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    execution_id: str | None = None,
    nonce: str | None = None,
) -> EvidenceBundle:
    if len(source_sha256) != 64:
        raise ValueError("source_sha256 must be a SHA-256 hex digest")
    if ttl_seconds < 30 or ttl_seconds > 900:
        raise ValueError("evidence TTL must be between 30 and 900 seconds")
    now = int(time.time()) if now_unix is None else int(now_unix)
    actual_evidence_sha256 = finding_set_sha256(report.findings)
    if actual_evidence_sha256 != report.evidence_sha256:
        raise EvidenceIntegrityError("release report evidence changed after evaluation")
    results: list[dict[str, Any]] = []
    for finding in sorted(report.findings, key=lambda item: item.finding_id):
        blocking = bool(finding.blocking_evidence())
        results.append({
            "finding_id": finding.finding_id,
            "severity": finding.severity.value,
            "failed": True,
            "blocking_eligible": blocking,
            "evidence_digest_sha256": _evidence_digest(finding),
        })
    return EvidenceBundle(
        schema=SCHEMA,
        release_id=report.release_id,
        source_sha256=source_sha256,
        execution_id=execution_id or "exec-" + uuid4().hex,
        nonce=nonce or "nonce-" + uuid4().hex,
        issued_at_unix=now,
        expires_at_unix=now + ttl_seconds,
        policy_id=report.policy_id,
        policy_revision=report.policy_revision,
        policy_sha256=report.policy_sha256,
        execution_count=report.execution_count,
        results=tuple(results),
    )


def sign_evidence_bundle(bundle: EvidenceBundle, signer: EvidenceSigner) -> SignedEvidenceBundle:
    raw = canonical_bytes(bundle.to_dict())
    digest = hashlib.sha256(raw).digest()
    signature, key_id = signer.sign_payload(raw)
    return SignedEvidenceBundle(
        bundle=bundle.to_dict(),
        bundle_sha256=digest.hex(),
        signature_base64=base64.b64encode(signature).decode("ascii"),
        key_id=key_id,
    )


def _cleanup_ephemeral_demo_key() -> None:
    global _EPHEMERAL_KEY_PATH, _EPHEMERAL_KEY_DIR
    if _EPHEMERAL_KEY_DIR is not None:
        shutil.rmtree(_EPHEMERAL_KEY_DIR, ignore_errors=True)
    _EPHEMERAL_KEY_PATH = None
    _EPHEMERAL_KEY_DIR = None


def _ephemeral_demo_key() -> Path:
    """Create one process-local P-256 key for offline demonstrations.

    The key is intentionally non-authoritative: it is never used by the cloud
    attestor, is stored under a mode-0700 temporary directory, and is removed
    on normal process exit. Reusing one key within a process keeps multi-step
    local demos internally consistent without persisting trust across runs.
    """
    global _EPHEMERAL_KEY_PATH, _EPHEMERAL_KEY_DIR
    if _EPHEMERAL_KEY_PATH is not None and _EPHEMERAL_KEY_PATH.is_file():
        return _EPHEMERAL_KEY_PATH

    openssl = shutil.which("openssl")
    if not openssl:
        raise RuntimeError("OpenSSL is required to generate the offline demo signing key")

    directory = Path(tempfile.mkdtemp(prefix="release-sentinel-demo-key-"))
    directory.chmod(0o700)
    key_path = directory / "evidence-private.pem"
    proc = subprocess.run(
        [openssl, "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(key_path)],
        capture_output=True,
        text=True,
        timeout=5,
    )
    if proc.returncode != 0:
        shutil.rmtree(directory, ignore_errors=True)
        raise RuntimeError("OpenSSL failed to generate the offline demo signing key")
    key_path.chmod(0o600)
    _EPHEMERAL_KEY_DIR = directory
    _EPHEMERAL_KEY_PATH = key_path
    return key_path


atexit.register(_cleanup_ephemeral_demo_key)


class OpenSSLDemoSigner:
    """Local-only ECDSA signer used by the jury demo.

    The private key is generated into a temporary directory by the demo launcher and
    never committed to the repository. Production uses Cloud KMS instead.
    """

    def __init__(self, private_key_path: str | Path, *, key_id: str = "local-demo-ephemeral-key") -> None:
        self.private_key_path = Path(private_key_path)
        if not self.private_key_path.is_file():
            raise ValueError("demo signing key does not exist")
        self.key_id = key_id

    def sign_payload(self, payload: bytes) -> tuple[bytes, str]:
        with tempfile.TemporaryDirectory(prefix="rs-sign-") as tmp:
            payload_path = Path(tmp) / "payload.json"
            signature_path = Path(tmp) / "signature.bin"
            payload_path.write_bytes(payload)
            proc = subprocess.run(
                [
                    "openssl", "dgst", "-sha256", "-sign", str(self.private_key_path),
                    "-out", str(signature_path), str(payload_path),
                ],
                capture_output=True, text=True, timeout=5,
            )
            if proc.returncode != 0:
                raise RuntimeError("OpenSSL demo signing failed")
            return signature_path.read_bytes(), self.key_id


def demo_signer_from_env() -> OpenSSLDemoSigner:
    """Resolve the demo signing key, generating an ephemeral one if unset.

    An explicit key always wins, so scripts and the cloud proof keep full
    control. When nothing is configured, a throwaway P-256 key is generated in
    a private temporary directory rather than raising: the offline demo exists
    to be run by someone who just cloned the repository, and a traceback on
    their first command is a worse outcome than an ephemeral key.

    This key is deliberately unsuitable for anything real. It is created fresh
    per process, never persisted beyond the process temp directory, and its
    key_id says so — nothing downstream can mistake it for the Cloud KMS key
    that signs authoritative evidence.
    """
    path = os.getenv("RELEASE_SENTINEL_DEMO_SIGNING_KEY", "").strip()
    if path:
        return OpenSSLDemoSigner(path)
    return OpenSSLDemoSigner(_ephemeral_demo_key(), key_id=_EPHEMERAL_KEY_ID)
