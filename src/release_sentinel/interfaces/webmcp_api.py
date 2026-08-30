from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query

from release_sentinel.webmcp.contracts import (
    ChallengeId,
    PolicyRevision,
    ProposalRequest,
    RebuildRequest,
    ReverifyRequest,
    VerifyProofRequest,
    tool_catalog,
)
from release_sentinel.webmcp.service import WebMCPChallengeService, WebMCPServiceError

router = APIRouter(prefix="/v1/webmcp", tags=["webmcp"])
service = WebMCPChallengeService()


def _raise(exc: WebMCPServiceError) -> None:
    raise HTTPException(status_code=exc.status_code, detail=exc.to_payload()) from exc


@router.get("/tools")
def tools() -> dict[str, Any]:
    return {
        "schema": "release-sentinel.webmcp-tools.v1",
        "authority": "NO_RELEASE_AUTHORITY",
        "tools": tool_catalog(),
    }


@router.get("/release")
def inspect_release() -> dict[str, Any]:
    return service.inspect_release()


@router.get("/trust-boundary")
def inspect_trust_boundary() -> dict[str, Any]:
    return service.inspect_trust_boundary()


@router.post("/attack/{attack_name}")
def run_attack(attack_name: str) -> dict[str, Any]:
    try:
        return service.run_attack(attack_name)
    except WebMCPServiceError as exc:
        _raise(exc)


@router.get("/coverage/{challenge}")
def inspect_coverage(
    challenge: ChallengeId,
    revision: PolicyRevision = Query(default=PolicyRevision.REV3),
) -> dict[str, Any]:
    try:
        return service.inspect_coverage(challenge.value, int(revision))
    except WebMCPServiceError as exc:
        _raise(exc)


@router.get("/coverage/{challenge}/compare")
def compare_gate_revisions(challenge: ChallengeId) -> dict[str, Any]:
    try:
        return service.compare_gate_revisions(challenge.value)
    except WebMCPServiceError as exc:
        _raise(exc)


@router.get("/coverage/{challenge}/counterexamples")
def find_counterexamples(
    challenge: ChallengeId,
    revision: PolicyRevision = Query(default=PolicyRevision.REV1),
) -> dict[str, Any]:
    try:
        return service.find_counterexamples(challenge.value, int(revision))
    except WebMCPServiceError as exc:
        _raise(exc)


@router.post("/coverage/{challenge}/counterexamples/{candidate_id}/minimize")
def minimize_counterexample(challenge: ChallengeId, candidate_id: str) -> dict[str, Any]:
    try:
        return service.minimize_counterexample(challenge.value, candidate_id)
    except WebMCPServiceError as exc:
        _raise(exc)


@router.post("/remediation/proposals")
def propose_remediation(request: ProposalRequest) -> dict[str, Any]:
    try:
        return service.propose_remediation(request.demo_release_id.value)
    except WebMCPServiceError as exc:
        _raise(exc)


@router.post("/remediation/rebuild")
def rebuild_candidate(request: RebuildRequest) -> dict[str, Any]:
    try:
        return service.rebuild_candidate(request.proposal_id, request.proposal_digest)
    except WebMCPServiceError as exc:
        _raise(exc)


@router.post("/remediation/reverify")
def reverify_candidate(request: ReverifyRequest) -> dict[str, Any]:
    try:
        return service.reverify_candidate(request.candidate_id, request.new_source_sha256)
    except WebMCPServiceError as exc:
        _raise(exc)


@router.post("/proof/verify")
def verify_proof(request: VerifyProofRequest) -> dict[str, Any]:
    try:
        return service.verify_proof(request.proof_id.value)
    except WebMCPServiceError as exc:
        _raise(exc)
