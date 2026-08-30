from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_bootstrap_enables_resource_manager_and_marks_unconditional_iam_bindings():
    script = _text("deploy/bootstrap-gcp.sh")
    assert "cloudresourcemanager.googleapis.com" in script
    for role in [
        "roles/run.builder",
        "roles/aiplatform.user",
        "roles/telemetry.tracesWriter",
        "roles/serviceusage.serviceUsageConsumer",
    ]:
        match = re.search(re.escape(role) + r'"(?:(?!gcloud projects add-iam-policy-binding).){0,120}--condition=None', script, re.S)
        assert match, f"{role} must be explicitly unconditional"


def test_gatekeeper_url_update_preserves_existing_trust_env():
    script = _text("deploy/gatekeeper.sh")
    assert '--update-env-vars="GATEKEEPER_PUBLIC_URL=$URL"' in script
    assert '--set-env-vars="GATEKEEPER_PUBLIC_URL=$URL"' not in script


def test_runtime_separates_cloud_run_region_from_vertex_model_location():
    script = _text("deploy/cloudrun.sh")
    assert ': "${VERTEX_LOCATION:=global}"' in script
    assert "GOOGLE_CLOUD_LOCATION=$VERTEX_LOCATION" in script
    assert "GOOGLE_CLOUD_LOCATION=$REGION" not in script


def test_adk_standalone_runner_roots_use_chat_mode():
    smoke = _text("src/release_sentinel/infrastructure/adk_smoke.py")
    workflow = _text("src/release_sentinel/agents/workflow.py")
    remediation = _text("src/release_sentinel/agents/remediation.py")
    assert 'name="cloud_smoke_agent",\n        model=model,\n        mode="chat",' in smoke
    assert 'agent = Agent(name=agent_id, model=MODEL, mode="chat", instruction=instruction)' in workflow
    assert 'name="remediation_agent",\n        model=model,\n        mode="chat",' in remediation
    # Agents that are nodes inside the workflow graph remain single-turn nodes.
    assert workflow.count('mode="single_turn"') == 4


def test_gatekeeper_collector_flushes_one_span_without_waiting_for_large_batch():
    config = _text("deploy/otel-collector-config.yaml")
    assert "send_batch_size: 1" in config


def test_cloud_trace_read_uses_quota_project_and_file_backed_json():
    script = _text("deploy/cloud-proof.sh")
    assert '-H "x-goog-user-project: $PROJECT_ID"' in script
    assert '-o "$trace_file"' in script
    assert 'python3 - "$trace_file"' in script
    assert 'python3 - "$response"' not in script


def test_cloud_proof_retries_transient_post_deploy_http_failures():
    script = _text("deploy/cloud-proof.sh")
    assert "request_json()" in script
    assert "for attempt in $(seq 1 12)" in script
    assert "--connect-timeout 10" in script
    assert "CLOUD PROOF HTTP FAIL" in script
