from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class CloudSettings:
    project_id: str
    location: str
    policy_database: str
    ledger_database: str
    policy_id: str
    policy_revision: int
    policy_sha256: str | None
    kms_key_version: str | None
    signing_required: bool
    gatekeeper_url: str | None
    gatekeeper_audience: str | None
    attestor_url: str | None
    attestor_audience: str | None
    evidence_kms_key_version: str | None

    @classmethod
    def from_env(cls) -> "CloudSettings":
        project = os.getenv("GOOGLE_CLOUD_PROJECT") or os.getenv("RELEASE_SENTINEL_CLOUD_PROJECT") or ""
        location = os.getenv("GOOGLE_CLOUD_LOCATION", "us-central1")
        revision_raw = os.getenv("RELEASE_SENTINEL_POLICY_REVISION", "1")
        try:
            revision = int(revision_raw)
        except ValueError as exc:
            raise RuntimeError("RELEASE_SENTINEL_POLICY_REVISION must be an integer") from exc
        return cls(
            project_id=project,
            location=location,
            policy_database=os.getenv("RELEASE_SENTINEL_POLICY_DATABASE", "release-sentinel-policy"),
            ledger_database=os.getenv("RELEASE_SENTINEL_LEDGER_DATABASE", "(default)"),
            policy_id=os.getenv("RELEASE_SENTINEL_POLICY_ID", "demo-release-policy"),
            policy_revision=revision,
            policy_sha256=os.getenv("RELEASE_SENTINEL_POLICY_SHA256") or None,
            kms_key_version=os.getenv("RELEASE_SENTINEL_KMS_KEY_VERSION") or None,
            signing_required=os.getenv("RELEASE_SENTINEL_PROVENANCE_SIGNING_REQUIRED", "false").lower() == "true",
            gatekeeper_url=os.getenv("RELEASE_SENTINEL_GATEKEEPER_URL") or None,
            gatekeeper_audience=os.getenv("RELEASE_SENTINEL_GATEKEEPER_AUDIENCE") or None,
            attestor_url=os.getenv("RELEASE_SENTINEL_ATTESTOR_URL") or None,
            attestor_audience=os.getenv("RELEASE_SENTINEL_ATTESTOR_AUDIENCE") or None,
            evidence_kms_key_version=os.getenv("RELEASE_SENTINEL_EVIDENCE_KMS_KEY_VERSION") or None,
        )

    def require_cloud_proof(self) -> None:
        if not self.project_id:
            raise RuntimeError("GOOGLE_CLOUD_PROJECT is required for cloud proof")
        if self.policy_revision < 1:
            raise RuntimeError("policy revision must be positive")
        if self.signing_required and not self.kms_key_version:
            raise RuntimeError("KMS key version is required when provenance signing is mandatory")
        if not self.gatekeeper_url:
            raise RuntimeError("RELEASE_SENTINEL_GATEKEEPER_URL is required for cloud proof")
        if not self.attestor_url:
            raise RuntimeError("RELEASE_SENTINEL_ATTESTOR_URL is required for cloud proof")
