from pathlib import Path

ROOT = Path(__file__).parents[1]


def text(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_evidence_signing_key_is_granted_to_attestor_not_runtime():
    s = text("deploy/evidence-key.sh")
    assert 'ATTESTOR_SA_NAME' in s
    assert '--member="serviceAccount:$ATTESTOR_SA" --role="roles/cloudkms.signer"' in s
    assert 'serviceAccount:$RUNTIME_SA' not in s


def test_only_attestor_deploy_owns_untrusted_sandbox_execution():
    attestor = text("deploy/attestor.sh")
    runtime = text("deploy/cloudrun.sh")
    assert '--sandbox-launcher' in attestor
    assert '--sandbox-launcher' not in runtime


def test_gatekeeper_receives_public_key_not_signing_permission():
    s = text("deploy/gatekeeper.sh")
    assert 'get-public-key' in s
    assert 'RELEASE_SENTINEL_EVIDENCE_PUBLIC_KEY_B64' in s
    assert 'roles/cloudkms.signer' not in s


def test_cloud_proof_requires_live_tamper_and_replay_rejection():
    s = text("deploy/cloud-proof.sh")
    assert '/v1/demo/attack-gate/downgrade_severity' in s
    assert "tamper['rejection_code']=='DIGEST_MISMATCH'" in s
    assert '/v1/demo/attack-gate/replay_previous_go' in s
    assert "replay['rejection_code']=='CONTEXT_MISMATCH'" in s


def test_attestor_has_no_model_runtime_in_attestation_api():
    s = text("src/release_sentinel/interfaces/attestor_api.py")
    assert 'google.adk' not in s
    assert 'from google.adk' not in s
    assert 'RELEASE_SENTINEL_MODEL' not in s
    assert 'CloudRunSandboxExecutor' in s
    assert 'CloudKmsEvidenceSigner' in s
