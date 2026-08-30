from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from typing import Any, Protocol
from urllib.parse import urlsplit
from urllib.request import Request as UrlRequest, urlopen
from uuid import uuid4

from release_sentinel.domain.evidence import Decision, Finding
from release_sentinel.operations.attestation import SignedEvidenceBundle
from release_sentinel.release.judge import DeterministicJudge
from release_sentinel.observability.tracing import current_trace_id, inject_trace_context, safe_span, set_safe_attributes


@dataclass(frozen=True)
class GatekeeperVerdict:
    decision: Decision
    rationale: list[str]
    authority: str
    component: str
    llm_present: bool
    agent_influence: int
    ignored_agent_opinions: int
    transport: str
    trace_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["decision"] = self.decision.value
        return payload


class Gatekeeper(Protocol):
    def decide(self, release_id: str, findings: list[Finding], agent_opinions: list[dict[str, Any]]) -> GatekeeperVerdict: ...


def _finding_payload(findings: list[Finding]) -> list[dict[str, Any]]:
    return [item.to_dict() for item in findings]


class LocalDeterministicGatekeeper:
    """Offline reference gate used by unit tests and the bundled no-network demo.

    Production cloud proof requires the separate Go A2A gatekeeper. This class
    mirrors its deterministic policy so tests can run without a background service.
    """

    def __init__(self) -> None:
        self._judge = DeterministicJudge()

    def decide(self, release_id: str, findings: list[Finding], agent_opinions: list[dict[str, Any]]) -> GatekeeperVerdict:
        decision, rationale = self._judge.decide(findings)
        return GatekeeperVerdict(
            decision=decision,
            rationale=rationale + (["Agent opinions were received but have zero decision authority."] if agent_opinions else []),
            authority="DETERMINISTIC_REFERENCE_GATE",
            component="python-reference-gate",
            llm_present=False,
            agent_influence=0,
            ignored_agent_opinions=len(agent_opinions),
            transport="in_process_reference",
        )


A2A_VERSION_LEGACY = "0.3"
A2A_VERSION_CURRENT = "1.0"
A2A_SUPPORTED_VERSIONS = (A2A_VERSION_LEGACY, A2A_VERSION_CURRENT)


class GatekeeperRejected(RuntimeError):
    def __init__(self, code: str, payload: dict[str, Any]) -> None:
        super().__init__(f"gatekeeper rejected signed evidence: {code}")
        self.code = code
        self.payload = payload


class A2AGatekeeperClient:
    """A2A JSON-RPC client for the deterministic Go signed-evidence gatekeeper."""

    def __init__(
        self,
        base_url: str,
        *,
        audience: str | None = None,
        timeout_seconds: float = 8.0,
        protocol_version: str = A2A_VERSION_LEGACY,
    ) -> None:
        value = base_url.rstrip("/")
        parsed = urlsplit(value)
        local = parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost"}
        if parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
            raise ValueError("gatekeeper URL must be a service origin without credentials, path, query, or fragment")
        if local:
            if audience is not None:
                raise ValueError("local Gatekeeper calls must not request a cloud identity token")
        else:
            if parsed.scheme != "https" or not parsed.hostname or not parsed.hostname.endswith(".run.app"):
                raise ValueError("production Gatekeeper must be a private Cloud Run service origin")
            if not audience:
                raise ValueError("private Cloud Run Gatekeeper requires an identity-token audience")
            if audience.rstrip("/") != value:
                raise ValueError("Gatekeeper audience must match the Cloud Run service URL")
        self.base_url = value
        self.audience = audience
        self.timeout_seconds = timeout_seconds
        if protocol_version not in A2A_SUPPORTED_VERSIONS:
            raise ValueError(
                f"unsupported A2A protocol version {protocol_version!r}; "
                f"expected one of {A2A_SUPPORTED_VERSIONS}"
            )
        self.protocol_version = protocol_version

    def _authorization_header(self) -> str | None:
        if not self.audience:
            return None
        try:
            from google.auth.transport.requests import Request
            from google.oauth2 import id_token
        except ImportError as exc:
            raise RuntimeError("google-auth is required for authenticated gatekeeper calls") from exc
        token = id_token.fetch_id_token(Request(), self.audience)
        return f"Bearer {token}"

    def _post(self, payload: dict[str, Any]) -> dict[str, Any]:
        with safe_span(
            "gatekeeper.a2a_call",
            {
                "component": "release-sentinel-python",
                "agent_id": "go-gatekeeper",
                "agent_role": "deterministic_gatekeeper",
                "decision_authority": "DETERMINISTIC",
                "evidence_authority": "VERIFIED_SIGNED_EVIDENCE",
                "agent_influence": 0,
                "llm_present": False,
            },
        ) as span:
            headers = {"Content-Type": "application/json", "A2A-Version": self.protocol_version}
            inject_trace_context(headers)
            auth = self._authorization_header()
            if auth:
                headers["Authorization"] = auth
            req = UrlRequest(
                self.base_url + "/a2a",
                data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
                headers=headers,
                method="POST",
            )
            with urlopen(req, timeout=self.timeout_seconds) as response:
                body = json.loads(response.read().decode("utf-8"))
            if body.get("error"):
                raise RuntimeError("gatekeeper A2A request failed")
            verdict = self._extract_verdict(body)
            set_safe_attributes(span, {"verdict": verdict.get("decision") or "REJECTED"})
            body["_release_sentinel_trace_id"] = current_trace_id()
            return body

    @staticmethod
    def _extract_verdict(body: dict[str, Any]) -> dict[str, Any]:
        """Extract the verdict artifact from either A2A binding version.

        A2A 0.3 tags data parts with kind="data". v1.0 removed the discriminator,
        so a part carrying a dict under "data" is a data part regardless.
        """
        result = body.get("result") or {}
        task = result.get("task") if isinstance(result, dict) else None
        if isinstance(task, dict):
            result = task
        for artifact in result.get("artifacts") or []:
            for part in artifact.get("parts") or []:
                kind = part.get("kind")
                if kind not in (None, "data"):
                    continue
                if isinstance(part.get("data"), dict):
                    return part["data"]
        raise RuntimeError("gatekeeper A2A response did not contain a verdict artifact")

    @staticmethod
    def _extract_trace_id(body: dict[str, Any]) -> str | None:
        trace_id = body.get("_release_sentinel_trace_id")
        if not trace_id:
            result = body.get("result") or {}
            if isinstance(result, dict) and isinstance(result.get("task"), dict):
                result = result["task"]
            trace_id = (result.get("metadata") or {}).get("trace_id") if isinstance(result, dict) else None
        if isinstance(trace_id, str) and len(trace_id) == 32:
            return trace_id
        return None

    def _rpc_payload(self, decision_input: dict[str, Any]) -> dict[str, Any]:
        """Build a SendMessage request in the negotiated binding shape."""
        if self.protocol_version == A2A_VERSION_CURRENT:
            method, role = "SendMessage", "ROLE_USER"
            part: dict[str, Any] = {"data": decision_input}
        else:
            method, role = "message/send", "user"
            part = {"kind": "data", "data": decision_input}
        return {
            "jsonrpc": "2.0",
            "id": "rs-" + uuid4().hex,
            "method": method,
            "params": {
                "message": {
                    "role": role,
                    "messageId": "msg-" + uuid4().hex,
                    "parts": [part],
                },
                "configuration": {"blocking": True},
            },
        }

    def decide_attested(
        self,
        *,
        release_id: str,
        source_sha256: str,
        policy_sha256: str,
        signed_evidence_bundle: SignedEvidenceBundle | dict[str, Any],
        agent_opinions: list[dict[str, Any]],
    ) -> GatekeeperVerdict:
        signed = signed_evidence_bundle.to_dict() if isinstance(signed_evidence_bundle, SignedEvidenceBundle) else dict(signed_evidence_bundle)
        decision_input = {
            "release_id": release_id,
            "source_sha256": source_sha256,
            "policy_sha256": policy_sha256,
            "signed_evidence_bundle": signed,
            "agent_opinions": list(agent_opinions),
        }
        body = self._post(self._rpc_payload(decision_input))
        raw = self._extract_verdict(body)
        if not raw.get("accepted", False):
            raise GatekeeperRejected(str(raw.get("rejection_code") or "EVIDENCE_REJECTED"), raw)
        return GatekeeperVerdict(
            decision=Decision(raw["decision"]),
            rationale=list(raw.get("rationale") or []),
            authority=str(raw.get("authority") or "DETERMINISTIC_GO_GATEKEEPER"),
            component=str(raw.get("component") or "release-sentinel-go-gatekeeper"),
            llm_present=bool(raw.get("llm_present", False)),
            agent_influence=int(raw.get("agent_influence", 0)),
            ignored_agent_opinions=int(raw.get("ignored_agent_opinions", len(agent_opinions))),
            transport="A2A_JSONRPC",
            trace_id=self._extract_trace_id(body),
        )

    def attack_raw(
        self,
        *,
        release_id: str,
        source_sha256: str,
        policy_sha256: str,
        signed_evidence_bundle: dict[str, Any],
        agent_opinions: list[dict[str, Any]],
    ) -> dict[str, Any]:
        decision_input = {
            "release_id": release_id,
            "source_sha256": source_sha256,
            "policy_sha256": policy_sha256,
            "signed_evidence_bundle": signed_evidence_bundle,
            "agent_opinions": list(agent_opinions),
        }
        return self._extract_verdict(self._post(self._rpc_payload(decision_input)))

    def decide(self, release_id: str, findings: list[Finding], agent_opinions: list[dict[str, Any]]) -> GatekeeperVerdict:
        raise RuntimeError("remote Go gatekeeper requires a signed evidence bundle; unsigned findings are never authoritative")


def gatekeeper_from_env(*, require_remote: bool = False) -> Gatekeeper:
    url = os.getenv("RELEASE_SENTINEL_GATEKEEPER_URL", "").strip()
    if url:
        audience = os.getenv("RELEASE_SENTINEL_GATEKEEPER_AUDIENCE") or url
        # Local http URLs are intentionally unauthenticated for developer demos.
        if url.startswith("http://127.0.0.1") or url.startswith("http://localhost"):
            audience = None
        version = os.getenv("RELEASE_SENTINEL_A2A_VERSION", A2A_VERSION_LEGACY).strip() or A2A_VERSION_LEGACY
        return A2AGatekeeperClient(url, audience=audience, protocol_version=version)
    if require_remote:
        raise RuntimeError("RELEASE_SENTINEL_GATEKEEPER_URL is required")
    return LocalDeterministicGatekeeper()
