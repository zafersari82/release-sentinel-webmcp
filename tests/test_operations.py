import stat
import subprocess

import pytest

from release_sentinel.operations import attestation
from release_sentinel.operations.checkpoint import InMemoryCheckpointStore
from release_sentinel.operations.provenance import build_provenance


class StaticSigner:
    def sign(self, _digest):
        return b"sig", "kms/key/1"


def test_checkpoint_is_idempotent():
    store = InMemoryCheckpointStore()
    store.mark_complete("r", "a")
    store.mark_complete("r", "a")

    assert store.get_or_create("r").completed_scenarios == {"a"}


def test_cancel_flag_persists():
    store = InMemoryCheckpointStore()
    store.request_cancel("r")

    assert store.get_or_create("r").cancelled


def test_signing_required_fails_without_signer():
    with pytest.raises(RuntimeError):
        build_provenance({"x": 1}, signing_required=True)


def test_unsigned_provenance_has_digest():
    provenance = build_provenance({"x": 1})

    assert len(provenance.manifest_sha256) == 64
    assert provenance.signature_hex is None


def test_signed_provenance_records_key_version():
    provenance = build_provenance({"x": 1}, StaticSigner(), signing_required=True)

    assert provenance.signature_hex == b"sig".hex()
    assert provenance.key_version.endswith("/1")


def test_demo_signer_generates_process_local_ephemeral_key_when_unset(monkeypatch):
    monkeypatch.delenv("RELEASE_SENTINEL_DEMO_SIGNING_KEY", raising=False)
    attestation._cleanup_ephemeral_demo_key()

    signer = attestation.demo_signer_from_env()

    assert signer.key_id == "ephemeral-offline-demo-key-not-for-verification"
    assert signer.private_key_path.is_file()
    assert stat.S_IMODE(signer.private_key_path.stat().st_mode) == 0o600

    signature, key_id = signer.sign_payload(b"offline-demo-proof")
    assert signature
    assert key_id == signer.key_id
    assert attestation.demo_signer_from_env().private_key_path == signer.private_key_path

    attestation._cleanup_ephemeral_demo_key()


def test_explicit_demo_signing_key_takes_precedence(monkeypatch, tmp_path):
    key = tmp_path / "explicit.pem"
    subprocess.run(
        ["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(key)],
        check=True,
        capture_output=True,
        text=True,
    )
    monkeypatch.setenv("RELEASE_SENTINEL_DEMO_SIGNING_KEY", str(key))

    signer = attestation.demo_signer_from_env()

    assert signer.private_key_path == key
    assert signer.key_id == "local-demo-ephemeral-key"
