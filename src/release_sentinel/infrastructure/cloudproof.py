from __future__ import annotations

import asyncio
import os
import shutil
from dataclasses import asdict
from typing import Any

from release_sentinel.agents.advisory import compromised_agent_simulation
from release_sentinel.agents.memory import MemoryAwareAdvisor
from release_sentinel.agents.registry import default_agent_registry
from release_sentinel.agents.workflow import run_real_advisory_fleet
from release_sentinel.domain.release import ReleaseRequest
from release_sentinel.infrastructure.attestor import EvidenceAttestorClient
from release_sentinel.infrastructure.firestore import FirestoreReportLedger
from release_sentinel.infrastructure.kms import CloudKmsSigner
from release_sentinel.infrastructure.settings import CloudSettings
from release_sentinel.observability.tracing import safe_span, set_safe_attributes
from release_sentinel.operations.provenance import build_provenance
from release_sentinel.release.gatekeeper import A2AGatekeeperClient


def _fixture(name: str):
    """Compatibility helper for fixture-integrity tests; cloud execution is owned by the attestor."""
    from importlib.resources import files
    from pathlib import Path
    from release_sentinel.execution.demo import BundledDemoExecutor

    mapping = {
        "vulnerable": ("repository_vulnerable", "repository_vulnerable.sha256"),
        "fixed": ("repository_fixed", "repository_fixed.sha256"),
    }
    try:
        directory, hash_file = mapping[name]
    except KeyError as exc:
        raise ValueError("unknown bundled fixture") from exc
    base = Path(str(files("release_sentinel"))) / "demo_fixture"
    repository = base / directory
    expected = (base / hash_file).read_text(encoding="utf-8").strip()
    if BundledDemoExecutor.fixture_digest(repository) != expected:
        raise RuntimeError("bundled fixture integrity mismatch")
    return repository, expected


def runtime_proof() -> dict[str, Any]:
    settings = CloudSettings.from_env()
    sandbox = shutil.which("/usr/local/gcp/bin/sandbox")
    trace_endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT") or os.getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
    registry = default_agent_registry()
    return {
        "project_configured": bool(settings.project_id),
        "location": settings.location,
        "model": os.getenv("RELEASE_SENTINEL_MODEL", "gemini-3.6-flash"),
        "vertex_ai_mode": os.getenv("GOOGLE_GENAI_USE_ENTERPRISE", "").upper() == "TRUE",
        "policy_database": settings.policy_database,
        "ledger_database": settings.ledger_database,
        "policy_hash_pinned": bool(settings.policy_sha256),
        "kms_signing_required": settings.signing_required,
        "kms_key_configured": bool(settings.kms_key_version),
        "sandbox_binary": sandbox or None,
        "sandbox_available": bool(sandbox),
        "gatekeeper_configured": bool(settings.gatekeeper_url),
        "gatekeeper_transport": "A2A_JSONRPC" if settings.gatekeeper_url else None,
        "attestor_configured": bool(settings.attestor_url),
        "evidence_key_configured": bool(settings.evidence_kms_key_version),
        "signed_evidence_required": True,
        "gatekeeper_llm_present": False,
        "adk_smoke_required": True,
        "agent_registry_records": len(registry.list()),
        "advisory_agents": len(registry.advisory_agents()),
        "deterministic_agents": len(registry.deterministic_agents()),
        "memory_backend": "FIRESTORE_RELEASE_REPORT_LEDGER",
        "distributed_trace_configured": bool(trace_endpoint),
        "trace_export_contract": "OTLP_TO_GOOGLE_BUILT_COLLECTOR_TO_TELEMETRY_API",
    }


def run_cloud_release_proof(fixture_name: str) -> dict[str, Any]:
    if fixture_name not in {"vulnerable", "fixed"}:
        raise ValueError("unknown bundled fixture")
    with safe_span(
        "release_verdict_pipeline",
        {
            "component": "release-sentinel-python",
            "decision_authority": "DETERMINISTIC",
            "evidence_authority": "ORGANIZATION_POLICY",
            "agent_influence": 0,
            "llm_present": True,
        },
    ) as root_span:
        return _run_cloud_release_proof(fixture_name, root_span)


def _run_cloud_release_proof(fixture_name: str, root_span) -> dict[str, Any]:
    settings = CloudSettings.from_env()
    settings.require_cloud_proof()
    if not settings.evidence_kms_key_version:
        raise RuntimeError("evidence signing key is required for cloud proof")

    release_id = "cloud-proof-release"
    attestor = EvidenceAttestorClient(
        settings.attestor_url,
        audience=settings.attestor_audience or settings.attestor_url,
    )
    attested = attestor.attest_fixture(fixture_name, release_id=release_id)
    source_sha256 = str(attested["source_sha256"])
    source_report = dict(attested["report"])
    signed_bundle = dict(attested["signed_evidence_bundle"])
    if settings.policy_sha256 and signed_bundle["bundle"]["policy_sha256"] != settings.policy_sha256:
        raise RuntimeError("attested evidence policy hash does not match external pin")
    if signed_bundle["key_id"] != settings.evidence_kms_key_version:
        raise RuntimeError("attested evidence key id does not match configured trust root")

    ledger = FirestoreReportLedger(settings.project_id, settings.ledger_database)
    try:
        prior_release_context = ledger.recent_for_release(release_id, limit=5)
        memory_status = "AVAILABLE"
    except Exception:
        prior_release_context = []
        memory_status = "UNAVAILABLE"

    # Real production proof executes the four registered ADK agents. Their output
    # is advisory-only. If the model plane fails, the deterministic gate still runs.
    try:
        real_advisory = asyncio.run(
            run_real_advisory_fleet(
                ReleaseRequest(release_id, __import__("pathlib").Path(".")),
                list(source_report.get("findings") or []),
                prior_release_context,
            )
        )
        advisory_runtime = "REAL_ADK"
    except Exception:
        real_advisory = {
            "role": "advisory_fleet",
            "authority": "ADVISORY",
            "llm_present": False,
            "safe_prior_release_context": prior_release_context,
            "outputs": {},
            "opinions": [],
        }
        advisory_runtime = "UNAVAILABLE"

    # Counterfactual resilience proof: all advisory opinions are forced to GO.
    # This is transported to the Go Gatekeeper but never enters signed evidence.
    compromised = MemoryAwareAdvisor(ledger, compromised_agent_simulation)(
        ReleaseRequest(release_id, __import__("pathlib").Path(".")), []
    )
    opinions = list(compromised.get("opinions") or [])
    gatekeeper = A2AGatekeeperClient(
        settings.gatekeeper_url,
        audience=settings.gatekeeper_audience or settings.gatekeeper_url,
    )
    verdict = gatekeeper.decide_attested(
        release_id=release_id,
        source_sha256=source_sha256,
        policy_sha256=str(signed_bundle["bundle"]["policy_sha256"]),
        signed_evidence_bundle=signed_bundle,
        agent_opinions=opinions,
    )
    if verdict.llm_present or verdict.agent_influence != 0:
        raise RuntimeError("gatekeeper violated deterministic authority contract")
    set_safe_attributes(root_span, {"verdict": verdict.decision.value, "agent_influence": 0, "llm_present": True})

    report = dict(source_report)
    report["decision"] = verdict.decision.value
    report["rationale"] = list(verdict.rationale)
    report["advisory"] = real_advisory
    report["resilience_advisory"] = compromised
    report["gatekeeper"] = verdict.to_dict()

    manifest = {
        "schema": "release-sentinel.cloud-proof.v4",
        "release_id": release_id,
        "report_id": report["report_id"],
        "decision": verdict.decision.value,
        "source_fixture": fixture_name,
        "source_sha256": source_sha256,
        "policy_id": signed_bundle["bundle"]["policy_id"],
        "policy_revision": signed_bundle["bundle"]["policy_revision"],
        "policy_sha256": signed_bundle["bundle"]["policy_sha256"],
        "execution_count": signed_bundle["bundle"]["execution_count"],
        "evidence_bundle_sha256": signed_bundle["bundle_sha256"],
        "evidence_key_id": signed_bundle["key_id"],
        "gatekeeper_component": verdict.component,
        "gatekeeper_transport": verdict.transport,
        "trace_id": verdict.trace_id,
        "agent_influence": verdict.agent_influence,
    }
    signer = CloudKmsSigner(settings.kms_key_version) if settings.kms_key_version else None
    signed = build_provenance(manifest, signer, signing_required=settings.signing_required)
    provenance = asdict(signed)
    ledger.append_payload(report["report_id"], report, provenance=provenance)

    source_authorities = sorted({
        evidence.get("authority")
        for finding in source_report.get("findings", [])
        for evidence in finding.get("evidence", [])
        if evidence.get("authority")
    })
    return {
        "cloud_proof": True,
        "fixture": fixture_name,
        "source_sha256": source_sha256,
        "report": report,
        "source_evidence_authorities": source_authorities,
        "signed_evidence": {
            "bundle_sha256": signed_bundle["bundle_sha256"],
            "key_id": signed_bundle["key_id"],
            "execution_id": signed_bundle["bundle"]["execution_id"],
            "nonce": signed_bundle["bundle"]["nonce"],
            "expires_at_unix": signed_bundle["bundle"]["expires_at_unix"],
            "verified_by_gatekeeper": True,
        },
        "provenance": provenance,
        "ledger_persisted": True,
        "persistent_memory": {
            "backend": "FIRESTORE_RELEASE_REPORT_LEDGER",
            "status": memory_status,
            "prior_release_count": len(prior_release_context),
            "dissent_context_safe_summary_only": True,
        },
        "distributed_trace": {
            "trace_id": verdict.trace_id,
            "propagation": "W3C_TRACE_CONTEXT",
            "python_root": "release_verdict_pipeline",
            "a2a_client_span": "gatekeeper.a2a_call",
            "go_server_span": "gatekeeper.verdict_decide",
            "export": "OTLP_TO_GOOGLE_BUILT_COLLECTOR_TO_TELEMETRY_API",
        },
        "advisory_runtime": advisory_runtime,
        "verdict_independence": {
            "gatekeeper_component": verdict.component,
            "transport": verdict.transport,
            "llm_present": verdict.llm_present,
            "agent_influence": verdict.agent_influence,
            "agents_all_go": all(item.get("vote") == "GO" for item in opinions),
            "ignored_agent_opinions": verdict.ignored_agent_opinions,
        },
        "trust_plane": {
            "attestor": attested["attestor"]["component"],
            "attestor_sandbox_available": bool(attested["attestor"].get("sandbox_available")),
            "evidence_signer": "CLOUD_KMS_DEDICATED_KEY",
            "orchestrator_can_sign_evidence": False,
        },
    }
