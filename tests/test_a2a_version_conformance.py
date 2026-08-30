"""A2A binding conformance across protocol versions.

A2A reached v1.0 under the Linux Foundation. The v1.0 JSON-RPC binding renamed
methods to PascalCase (``SendMessage``), replaced string enums with ProtoJSON
names (``ROLE_AGENT``, ``TASK_STATE_COMPLETED``) and removed the ``kind``
discriminator from Part. Spec section 3.6.2 requires an absent ``A2A-Version``
header to be interpreted as 0.3.

The Gatekeeper therefore serves both bindings from one endpoint. These tests
assert functional equivalence, which spec section 5.1 requires: the verdict
payload must be identical regardless of which binding produced it.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]

pytestmark = pytest.mark.skipif(
    shutil.which("go") is None or shutil.which("openssl") is None,
    reason="Go toolchain and OpenSSL are required for A2A conformance tests",
)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture(scope="module")
def gatekeeper():
    tmp = Path(tempfile.mkdtemp())
    private_key = tmp / "evidence-private.pem"
    public_key = tmp / "evidence-public.pem"
    subprocess.run(
        ["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(private_key)],
        check=True, capture_output=True,
    )
    subprocess.run(
        ["openssl", "pkey", "-in", str(private_key), "-pubout", "-out", str(public_key)],
        check=True, capture_output=True,
    )
    binary = tmp / "gatekeeper"
    subprocess.run(
        ["go", "build", "-C", str(ROOT / "gatekeeper"), "-o", str(binary), "./cmd/gatekeeper"],
        check=True, capture_output=True,
    )

    port = _free_port()
    env = dict(os.environ)
    env.update({
        "PORT": str(port),
        "GATEKEEPER_PUBLIC_URL": f"http://127.0.0.1:{port}",
        "RELEASE_SENTINEL_EVIDENCE_PUBLIC_KEY_PATH": str(public_key),
        "RELEASE_SENTINEL_EVIDENCE_KEY_ID": "conformance-test-key",
    })
    process = subprocess.Popen([str(binary)], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            urllib.request.urlopen(base + "/healthz", timeout=1).read()
            break
        except Exception:
            time.sleep(0.05)
    else:
        process.kill()
        pytest.fail("gatekeeper did not become ready")

    yield base
    process.kill()
    process.wait(timeout=10)
    shutil.rmtree(tmp, ignore_errors=True)


def _rpc(base: str, payload: dict, version: str | None = None):
    """Returns (body, headers). Headers are the case-insensitive message object:
    HTTP header names are case-insensitive per RFC 9110, so a plain dict() cast
    would make these assertions depend on the client's capitalisation."""
    headers = {"Content-Type": "application/json"}
    if version is not None:
        headers["A2A-Version"] = version
    request = urllib.request.Request(
        base + "/a2a", data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST"
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read().decode("utf-8")), response.headers


def _legacy_payload() -> dict:
    return {
        "jsonrpc": "2.0", "id": "conformance-legacy", "method": "message/send",
        "params": {"message": {
            "role": "user", "messageId": "msg-legacy",
            "parts": [{"kind": "data", "data": {"release_id": "conformance", "agent_opinions": []}}],
        }},
    }


def _current_payload() -> dict:
    return {
        "jsonrpc": "2.0", "id": "conformance-current", "method": "SendMessage",
        "params": {"message": {
            "role": "ROLE_USER", "messageId": "msg-current",
            "parts": [{"data": {"release_id": "conformance", "agent_opinions": []}}],
        }},
    }


def _task(result: dict) -> dict:
    task = result.get("task") if isinstance(result, dict) else None
    return task if isinstance(task, dict) else result


def _verdict(result: dict) -> dict:
    result = _task(result)
    for artifact in result.get("artifacts") or []:
        for part in artifact.get("parts") or []:
            if isinstance(part.get("data"), dict):
                return part["data"]
    raise AssertionError("no verdict artifact in response")


def test_absent_version_header_defaults_to_legacy(gatekeeper):
    """Spec 3.6.2: an empty A2A-Version MUST be interpreted as 0.3."""
    body, headers = _rpc(gatekeeper, _legacy_payload())
    assert headers.get("A2A-Version") == "0.3"
    result = body["result"]
    assert result["kind"] == "task"
    assert result["status"]["state"] == "completed"
    assert result["status"]["message"]["role"] == "agent"


def test_current_version_uses_protojson_enum_names(gatekeeper):
    """v1.0 uses ProtoJSON enum names and drops the kind discriminator."""
    body, headers = _rpc(gatekeeper, _current_payload(), version="1.0")
    assert headers.get("A2A-Version") == "1.0"
    result = body["result"]
    assert set(result) == {"task"}, "v1.0 SendMessage must return the oneof response wrapper"
    task = result["task"]
    assert "kind" not in task
    assert task["status"]["state"] == "TASK_STATE_COMPLETED"
    assert task["status"]["message"]["role"] == "ROLE_AGENT"
    for artifact in task["artifacts"]:
        for part in artifact["parts"]:
            assert "kind" not in part


def test_bindings_are_functionally_equivalent(gatekeeper):
    """Spec 5.1: the same input must produce the same verdict on any binding."""
    legacy, _ = _rpc(gatekeeper, _legacy_payload(), version="0.3")
    current, _ = _rpc(gatekeeper, _current_payload(), version="1.0")
    assert _verdict(legacy["result"]) == _verdict(current["result"])


def test_patch_version_negotiates_on_major_minor(gatekeeper):
    """Spec 3.6: patch numbers must not participate in negotiation."""
    _, headers = _rpc(gatekeeper, _current_payload(), version="1.0.7")
    assert headers.get("A2A-Version") == "1.0"


def test_unsupported_version_is_rejected(gatekeeper):
    """Spec 3.6.2: unsupported versions MUST return VersionNotSupportedError."""
    body, _ = _rpc(gatekeeper, _current_payload(), version="99.9")
    assert body.get("result") is None
    assert body["error"]["message"] == "VersionNotSupportedError"
    assert set(body["error"]["data"]["supported"]) == {"0.3", "1.0"}


def test_unknown_method_is_rejected(gatekeeper):
    payload = _current_payload() | {"method": "DeleteEverything"}
    body, _ = _rpc(gatekeeper, payload)
    assert body["error"]["code"] == -32601


def test_agent_card_is_version_specific_and_declares_authentication(gatekeeper):
    """Do not mix the mutually incompatible 0.3 and 1.0 Agent Card schemas."""
    with urllib.request.urlopen(gatekeeper + "/.well-known/agent-card.json", timeout=10) as response:
        legacy = json.loads(response.read().decode("utf-8"))
        assert response.headers.get("A2A-Version") == "0.3"
    assert legacy["protocolVersion"] == "0.3.0"
    assert legacy["preferredTransport"] == "JSONRPC"
    assert legacy["url"].endswith("/a2a")
    assert legacy["security"] == [{"googleOidc": []}]

    req = urllib.request.Request(
        gatekeeper + "/.well-known/agent-card.json", headers={"A2A-Version": "1.0"}
    )
    with urllib.request.urlopen(req, timeout=10) as response:
        current = json.loads(response.read().decode("utf-8"))
        assert response.headers.get("A2A-Version") == "1.0"

    assert "protocolVersion" not in current
    assert "url" not in current
    assert "preferredTransport" not in current
    interfaces = current["supportedInterfaces"]
    assert {(i["protocolBinding"], i["protocolVersion"]) for i in interfaces} == {
        ("JSONRPC", "0.3"), ("JSONRPC", "1.0")
    }
    assert all(i["url"].endswith("/a2a") for i in interfaces)
    oidc = current["securitySchemes"]["googleOidc"]["openIdConnectSecurityScheme"]
    assert oidc["openIdConnectUrl"].startswith("https://accounts.google.com/")
    assert current["securityRequirements"]


@pytest.mark.parametrize("version", ["1", "1.", ".0", "1.0.0.0", "v1.0"])
def test_malformed_versions_fail_closed(gatekeeper, version):
    body, _ = _rpc(gatekeeper, _current_payload(), version=version)
    assert body["error"]["message"] == "VersionNotSupportedError"


def test_method_name_is_bound_to_negotiated_version(gatekeeper):
    body, _ = _rpc(gatekeeper, _current_payload(), version="0.3")
    assert body["error"]["code"] == -32601
    body, _ = _rpc(gatekeeper, _legacy_payload(), version="1.0")
    assert body["error"]["code"] == -32601


def test_part_shape_is_bound_to_negotiated_version(gatekeeper):
    legacy_with_current_part = _legacy_payload()
    del legacy_with_current_part["params"]["message"]["parts"][0]["kind"]
    body, _ = _rpc(gatekeeper, legacy_with_current_part, version="0.3")
    assert body["error"]["code"] == -32602

    current_with_legacy_part = _current_payload()
    current_with_legacy_part["params"]["message"]["parts"][0]["kind"] = "data"
    body, _ = _rpc(gatekeeper, current_with_legacy_part, version="1.0")
    assert body["error"]["code"] == -32602


def test_unicode_digits_in_version_parameter_fail_closed(gatekeeper):
    from urllib.parse import quote
    request = urllib.request.Request(
        gatekeeper + "/a2a?A2A-Version=" + quote("１.０"),
        data=json.dumps(_current_payload()).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        body = json.loads(response.read().decode("utf-8"))
    assert body["error"]["message"] == "VersionNotSupportedError"
