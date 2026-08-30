from __future__ import annotations

from release_sentinel import __version__

from importlib.resources import files
import shutil
from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from release_sentinel.domain.release import ReleaseRequest
from release_sentinel.execution.cloudrun import CloudRunSandboxExecutor
from release_sentinel.execution.demo import BundledDemoExecutor
from release_sentinel.infrastructure.firestore import FirestorePolicyStore
from release_sentinel.infrastructure.evidence_signing import CloudKmsEvidenceSigner
from release_sentinel.infrastructure.settings import CloudSettings
from release_sentinel.operations.attestation import build_evidence_bundle, sign_evidence_bundle
from release_sentinel.release.engine import ReleaseEngine
from release_sentinel.release.gatekeeper import LocalDeterministicGatekeeper

app = FastAPI(title="Release Sentinel Evidence Attestor", version=__version__)

_FIXTURES = {
    "vulnerable": ("repository_vulnerable", "repository_vulnerable.sha256"),
    "fixed": ("repository_fixed", "repository_fixed.sha256"),
}


class AttestBody(BaseModel):
    release_id: str


def _fixture(name: str) -> tuple[Path, str]:
    try:
        directory, hash_file = _FIXTURES[name]
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="unknown bundled fixture") from exc
    base = Path(str(files("release_sentinel"))) / "demo_fixture"
    repository = base / directory
    expected = (base / hash_file).read_text(encoding="utf-8").strip()
    if BundledDemoExecutor.fixture_digest(repository) != expected:
        raise RuntimeError("bundled fixture integrity mismatch")
    return repository, expected


@app.get("/healthz")
def healthz() -> dict:
    settings = CloudSettings.from_env()
    return {
        "status": "ok",
        "component": "evidence-attestor",
        "llm_present": False,
        "policy_read_only": True,
        "evidence_signer_configured": bool(settings.evidence_kms_key_version),
    }


@app.post("/v1/attest/release/{fixture_name}")
def attest_release(fixture_name: str, body: AttestBody) -> dict:
    settings = CloudSettings.from_env()
    if not settings.project_id or not settings.policy_sha256 or not settings.evidence_kms_key_version:
        raise HTTPException(status_code=503, detail="attestor trust-plane settings are incomplete")
    repository, source_sha256 = _fixture(fixture_name)
    policy = FirestorePolicyStore(settings.project_id, settings.policy_database).get(settings.policy_id, settings.policy_revision)
    if policy.sha256 != settings.policy_sha256:
        raise HTTPException(status_code=503, detail="external policy pin mismatch")

    # This service owns trusted execution + attestation. It has no Gemini/ADK dependency in the flow.
    report = ReleaseEngine(
        CloudRunSandboxExecutor(),
        advisor=None,
        gatekeeper=LocalDeterministicGatekeeper(),
    ).evaluate(ReleaseRequest(body.release_id, repository), policy)
    bundle = build_evidence_bundle(report, source_sha256=source_sha256)
    signed = sign_evidence_bundle(bundle, CloudKmsEvidenceSigner(settings.evidence_kms_key_version))
    return {
        "attested": True,
        "fixture": fixture_name,
        "source_sha256": source_sha256,
        "report": report.to_dict(),
        "signed_evidence_bundle": signed.to_dict(),
        "attestor": {
            "component": "release-sentinel-evidence-attestor",
            "llm_present": False,
            "policy_sha256": policy.sha256,
            "key_id": signed.key_id,
            "sandbox_available": bool(shutil.which("/usr/local/gcp/bin/sandbox")),
        },
    }
