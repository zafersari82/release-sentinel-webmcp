import pytest

from release_sentinel.infrastructure.cloudproof import _fixture, runtime_proof
from release_sentinel.infrastructure.kms import CloudKmsSigner
from release_sentinel.infrastructure.settings import CloudSettings


def test_cloud_settings_fail_closed_without_project(monkeypatch):
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
    monkeypatch.delenv("RELEASE_SENTINEL_CLOUD_PROJECT", raising=False)

    settings = CloudSettings.from_env()

    with pytest.raises(RuntimeError):
        settings.require_cloud_proof()


def test_signing_required_requires_key(monkeypatch):
    monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "p")
    monkeypatch.setenv("RELEASE_SENTINEL_PROVENANCE_SIGNING_REQUIRED", "true")
    monkeypatch.delenv("RELEASE_SENTINEL_KMS_KEY_VERSION", raising=False)

    with pytest.raises(RuntimeError):
        CloudSettings.from_env().require_cloud_proof()


def test_kms_signer_rejects_non_version_resource_before_import():
    with pytest.raises(ValueError):
        CloudKmsSigner("not-a-version")


def test_bundled_fixtures_are_integrity_pinned():
    vulnerable, vulnerable_hash = _fixture("vulnerable")
    fixed, fixed_hash = _fixture("fixed")

    assert vulnerable.name == "repository_vulnerable"
    assert fixed.name == "repository_fixed"
    assert vulnerable_hash != fixed_hash


def test_runtime_proof_never_claims_sandbox_if_absent(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _: None)

    proof = runtime_proof()

    assert proof["sandbox_available"] is False


def test_runtime_proof_requires_real_adk_smoke(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _: None)

    proof = runtime_proof()

    assert proof["adk_smoke_required"] is True
