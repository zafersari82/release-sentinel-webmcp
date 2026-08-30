from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import time
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.request import urlopen

import pytest

from release_sentinel.domain.evidence import Decision, Evidence, EvidenceAuthority, EvidenceKind, Finding, Severity
from release_sentinel.domain.release import ReleaseReport
from release_sentinel.operations.attestation import OpenSSLDemoSigner, build_evidence_bundle, sign_evidence_bundle
from release_sentinel.release.gatekeeper import A2AGatekeeperClient
from release_sentinel.observability.tracing import add_span_processor, current_trace_id, safe_span

ROOT = Path(__file__).parents[1]
GO = shutil.which("go")
OPENSSL = shutil.which("openssl")
SOURCE_SHA = "a" * 64
POLICY_SHA = "b" * 64


def _port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def _finding():
    ev = Evidence(
        "e", EvidenceKind.EXECUTION_RESULT, EvidenceAuthority.ORGANIZATION_POLICY,
        "test", "failed", True, True, policy_id="org", policy_revision=1, policy_sha256=POLICY_SHA,
    )
    return Finding("f", "Auth boundary", Severity.HIGH, "organization_policy", "failed", [ev])


def _signed(private_key: Path, *, release_id: str = "r", blocked: bool = True):
    report = ReleaseReport(
        release_id=release_id,
        decision=Decision.NO_GO if blocked else Decision.GO,
        findings=[_finding()] if blocked else [],
        rationale=[], policy_id="org", policy_revision=1, policy_sha256=POLICY_SHA,
        execution_count=1,
    )
    bundle = build_evidence_bundle(report, source_sha256=SOURCE_SHA, now_unix=int(time.time()))
    return sign_evidence_bundle(bundle, OpenSSLDemoSigner(private_key, key_id="test-key"))


@pytest.fixture(scope="module")
def gatekeeper(tmp_path_factory):
    if not GO:
        pytest.skip("go toolchain not installed")
    if not OPENSSL:
        pytest.skip("openssl not installed")
    tmp = tmp_path_factory.mktemp("go-gatekeeper")
    private_key = tmp / "private.pem"
    public_key = tmp / "public.pem"
    subprocess.run([OPENSSL, "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(private_key)], check=True)
    subprocess.run([OPENSSL, "pkey", "-in", str(private_key), "-pubout", "-out", str(public_key)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    out = tmp / "gatekeeper"
    subprocess.run([GO, "build", "-o", str(out), "./cmd/gatekeeper"], cwd=ROOT/"gatekeeper", check=True)

    captured: list[dict] = []
    class CaptureHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            captured.append(json.loads(self.rfile.read(length) or b"{}"))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"{}")
        def log_message(self, *_):
            return
    collector = ThreadingHTTPServer(("127.0.0.1", 0), CaptureHandler)
    collector_thread = threading.Thread(target=collector.serve_forever, daemon=True)
    collector_thread.start()

    port = _port()
    env = dict(os.environ)
    env.update({
        "PORT": str(port),
        "GATEKEEPER_PUBLIC_URL": f"http://127.0.0.1:{port}",
        "RELEASE_SENTINEL_EVIDENCE_PUBLIC_KEY_PATH": str(public_key),
        "RELEASE_SENTINEL_EVIDENCE_KEY_ID": "test-key",
        "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": f"http://127.0.0.1:{collector.server_port}/v1/traces",
    })
    proc = subprocess.Popen([str(out)], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    url=f"http://127.0.0.1:{port}"
    for _ in range(60):
        try:
            with urlopen(url+"/healthz", timeout=.2) as r:
                health = json.loads(r.read())
                if health["status"] == "ok" and health["signed_evidence_required"] is True:
                    break
        except Exception:
            time.sleep(.05)
    else:
        err = proc.stderr.read().decode() if proc.stderr else ""
        proc.terminate()
        raise AssertionError("gatekeeper failed to start: " + err)
    yield {"url": url, "private_key": private_key, "captured": captured}
    proc.terminate()
    proc.wait(timeout=3)
    collector.shutdown()
    collector.server_close()
    collector_thread.join(timeout=2)


def test_agent_card_declares_oidc_and_no_llm_gatekeeper(gatekeeper):
    with urlopen(gatekeeper["url"]+"/.well-known/agent-card.json") as r:
        card=json.loads(r.read())
    assert card["protocolVersion"] == "0.3.0"
    assert card["preferredTransport"] == "JSONRPC"
    scheme = card["securitySchemes"]["googleOidc"]
    assert scheme["type"] == "openIdConnect"
    assert scheme["x-cloud-run-iam"] is True
    assert "roles/run.invoker" in scheme["description"]
    assert "aud" in scheme["description"]
    assert card["security"] == [{"googleOidc": []}]
    assert card["url"].endswith("/a2a")
    assert not any(name.lower() in {"anonymous", "none", "noauth"} for name in card["securitySchemes"])
    assert "Deterministic Gatekeeper" in card["name"]


def test_a2a_all_agents_go_still_no_go_with_signed_evidence(gatekeeper):
    c=A2AGatekeeperClient(gatekeeper["url"], audience=None)
    opinions=[{"agent":x,"vote":"GO"} for x in ("code","security","test","dissent")]
    signed = _signed(gatekeeper["private_key"], release_id="r", blocked=True)
    v=c.decide_attested(
        release_id="r", source_sha256=SOURCE_SHA, policy_sha256=POLICY_SHA,
        signed_evidence_bundle=signed, agent_opinions=opinions,
    )
    assert v.decision.value == "NO_GO"
    assert v.agent_influence == 0 and v.ignored_agent_opinions == 4
    assert v.transport == "A2A_JSONRPC" and v.llm_present is False


def test_a2a_tampered_severity_is_rejected(gatekeeper):
    c=A2AGatekeeperClient(gatekeeper["url"], audience=None)
    signed = _signed(gatekeeper["private_key"], release_id="r", blocked=True).to_dict()
    signed["bundle"]["results"][0]["severity"] = "INFO"
    raw = c.attack_raw(
        release_id="r", source_sha256=SOURCE_SHA, policy_sha256=POLICY_SHA,
        signed_evidence_bundle=signed, agent_opinions=[],
    )
    assert raw["accepted"] is False
    assert raw["rejection_code"] == "DIGEST_MISMATCH"


def test_a2a_old_go_bundle_cannot_be_replayed_into_current_release(gatekeeper):
    c=A2AGatekeeperClient(gatekeeper["url"], audience=None)
    signed = _signed(gatekeeper["private_key"], release_id="old-release", blocked=False).to_dict()
    raw = c.attack_raw(
        release_id="current-release", source_sha256=SOURCE_SHA, policy_sha256=POLICY_SHA,
        signed_evidence_bundle=signed, agent_opinions=[],
    )
    assert raw["accepted"] is False
    assert raw["rejection_code"] == "CONTEXT_MISMATCH"


def test_w3c_trace_context_reaches_go_as_same_trace_and_parent(gatekeeper):
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    exporter = InMemorySpanExporter()
    assert add_span_processor(SimpleSpanProcessor(exporter)) is True
    before = len(gatekeeper["captured"])
    client = A2AGatekeeperClient(gatekeeper["url"], audience=None)
    signed = _signed(gatekeeper["private_key"], release_id="trace-release", blocked=True)
    with safe_span("release_verdict_pipeline", {"component":"release-sentinel-python","agent_influence":0,"llm_present":False}):
        expected_trace_id = current_trace_id()
        verdict = client.decide_attested(
            release_id="trace-release", source_sha256=SOURCE_SHA, policy_sha256=POLICY_SHA,
            signed_evidence_bundle=signed, agent_opinions=[],
        )
    assert expected_trace_id and verdict.trace_id == expected_trace_id
    for _ in range(50):
        if len(gatekeeper["captured"]) > before:
            break
        time.sleep(.02)
    assert len(gatekeeper["captured"]) > before
    go_span = gatekeeper["captured"][-1]["resourceSpans"][0]["scopeSpans"][0]["spans"][0]
    assert go_span["traceId"] == expected_trace_id
    py_client = [s for s in exporter.get_finished_spans() if s.name == "gatekeeper.a2a_call"][-1]
    assert go_span["parentSpanId"] == f"{py_client.context.span_id:016x}"
    assert go_span["name"] == "gatekeeper.verdict_decide"


def test_trace_attributes_are_allowlisted_and_secret_free(gatekeeper):
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    exporter = InMemorySpanExporter()
    assert add_span_processor(SimpleSpanProcessor(exporter)) is True
    with safe_span("attribute-safety", {
        "component":"release-sentinel-python", "agent_id":"security_reviewer",
        "raw_prompt":"TOP_SECRET_PROMPT", "Authorization":"Bearer secret",
        "credential":"PRIVATE_KEY", "raw_evidence_payload":"SECRET_EVIDENCE",
    }):
        pass
    span = [s for s in exporter.get_finished_spans() if s.name == "attribute-safety"][-1]
    assert dict(span.attributes) == {"component":"release-sentinel-python", "agent_id":"security_reviewer"}
    payload_text = json.dumps(gatekeeper["captured"], sort_keys=True)
    for forbidden in ("raw_prompt", "Authorization", "credential", "raw_evidence_payload", "TOP_SECRET_PROMPT", "PRIVATE_KEY"):
        assert forbidden not in payload_text


def test_telemetry_export_failure_cannot_change_signed_verdict(tmp_path, gatekeeper):
    # The running Gatekeeper already uses a healthy local collector; this second process
    # points OTLP to a closed port and must still compute the same deterministic verdict.
    out = tmp_path / "gatekeeper-no-otel"
    subprocess.run([GO, "build", "-o", str(out), "./cmd/gatekeeper"], cwd=ROOT/"gatekeeper", check=True)
    port = _port()
    env = dict(os.environ)
    env.update({
        "PORT": str(port),
        "GATEKEEPER_PUBLIC_URL": f"http://127.0.0.1:{port}",
        "RELEASE_SENTINEL_EVIDENCE_PUBLIC_KEY_PATH": str(Path(gatekeeper["private_key"]).with_name("public.pem")),
        "RELEASE_SENTINEL_EVIDENCE_KEY_ID": "test-key",
        "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": "http://127.0.0.1:1/v1/traces",
    })
    proc = subprocess.Popen([str(out)], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    url = f"http://127.0.0.1:{port}"
    try:
        for _ in range(60):
            try:
                with urlopen(url+"/healthz", timeout=.2): break
            except Exception: time.sleep(.05)
        client=A2AGatekeeperClient(url, audience=None)
        signed=_signed(gatekeeper["private_key"], release_id="otel-down", blocked=True)
        verdict=client.decide_attested(release_id="otel-down",source_sha256=SOURCE_SHA,policy_sha256=POLICY_SHA,signed_evidence_bundle=signed,agent_opinions=[])
        assert verdict.decision.value == "NO_GO" and verdict.agent_influence == 0
    finally:
        proc.terminate()
        proc.wait(timeout=3)
