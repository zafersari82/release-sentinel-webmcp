#!/usr/bin/env bash
set -euo pipefail
: "${PROJECT_ID:?set PROJECT_ID}"
: "${REGION:=us-central1}"
SERVICE="${SERVICE_NAME:-release-sentinel}"
URL="$(gcloud run services describe "$SERVICE" --project "$PROJECT_ID" --region "$REGION" --format='value(status.url)')"
TOKEN="$(gcloud auth print-identity-token)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

request_json() {
  local method="$1" path="$2" output="$3" attempt
  for attempt in $(seq 1 12); do
    if curl -fsS \
      --connect-timeout 10 \
      --max-time 900 \
      -X "$method" \
      -H "Authorization: Bearer $TOKEN" \
      "$URL$path" \
      -o "$output" \
      2>"$TMP/http.err"; then
      return 0
    fi
    if [[ "$attempt" -lt 12 ]]; then
      sleep 5
    fi
  done
  echo "CLOUD PROOF HTTP FAIL method=$method path=$path attempts=12" >&2
  if [[ -s "$TMP/http.err" ]]; then
    cat "$TMP/http.err" >&2
  fi
  return 1
}

request_json GET /v1/cloud-proof/runtime "$TMP/runtime.json"
request_json POST /v1/cloud-proof/adk-smoke "$TMP/adk.json"
request_json POST /v1/cloud-proof/release/vulnerable "$TMP/vulnerable.json"
request_json POST /v1/cloud-proof/release/fixed "$TMP/fixed.json"
request_json POST /v1/demo/attack-gate/downgrade_severity "$TMP/attack-tamper.json"
request_json POST /v1/demo/attack-gate/replay_previous_go "$TMP/attack-replay.json"

python - "$TMP/runtime.json" "$TMP/adk.json" "$TMP/vulnerable.json" "$TMP/fixed.json" "$TMP/attack-tamper.json" "$TMP/attack-replay.json" "$TMP" <<'PY'
import json,sys,pathlib
runtime,adk,vuln,fixed,tamper,replay=(json.load(open(p)) for p in sys.argv[1:7])
out=pathlib.Path(sys.argv[7])
assert runtime['signed_evidence_required'] is True
assert runtime['policy_hash_pinned'] is True
assert runtime['kms_signing_required'] is True and runtime['kms_key_configured'] is True
assert runtime['vertex_ai_mode'] is True
assert runtime['gatekeeper_configured'] is True and runtime['gatekeeper_transport']=='A2A_JSONRPC'
assert runtime['attestor_configured'] is True and runtime['evidence_key_configured'] is True
assert runtime['signed_evidence_required'] is True
assert runtime['adk_smoke_required'] is True
assert runtime['distributed_trace_configured'] is True
assert runtime['trace_export_contract']=='OTLP_TO_GOOGLE_BUILT_COLLECTOR_TO_TELEMETRY_API'
assert adk['adk_real_call'] is True and adk['gemini_real_call'] is True
assert adk['response_token_matched'] is True and adk['event_count'] > 0
assert adk['release_authority'] == 'NONE'
assert vuln['cloud_proof'] is True and vuln['report']['decision']=='NO_GO'
assert vuln['advisory_runtime']=='REAL_ADK'
assert vuln['distributed_trace']['trace_id']
assert vuln['report']['execution_count']==1 and 'ORGANIZATION_POLICY' in vuln['source_evidence_authorities']
assert vuln['signed_evidence']['verified_by_gatekeeper'] is True
assert vuln['trust_plane']['attestor']=='release-sentinel-evidence-attestor'
assert vuln['trust_plane']['attestor_sandbox_available'] is True
assert vuln['trust_plane']['orchestrator_can_sign_evidence'] is False
assert vuln['verdict_independence']['gatekeeper_component']=='release-sentinel-go-gatekeeper'
assert vuln['verdict_independence']['transport']=='A2A_JSONRPC'
assert vuln['verdict_independence']['llm_present'] is False and vuln['verdict_independence']['agent_influence']==0
assert vuln['provenance']['signature_hex'] and vuln['ledger_persisted'] is True
assert fixed['cloud_proof'] is True and fixed['report']['decision']=='GO'
assert fixed['advisory_runtime']=='REAL_ADK'
assert fixed['distributed_trace']['trace_id']
assert fixed['persistent_memory']['status']=='AVAILABLE'
assert fixed['persistent_memory']['prior_release_count'] >= 1
assert fixed['report']['advisory']['safe_prior_release_context']
assert fixed['signed_evidence']['verified_by_gatekeeper'] is True
assert fixed['report']['execution_count']==1 and fixed['provenance']['signature_hex'] and fixed['ledger_persisted'] is True
assert tamper['payload_reached_gatekeeper'] is True and tamper['attack_blocked'] is True
assert tamper['gatekeeper_accepted_evidence'] is False and tamper['rejection_code']=='DIGEST_MISMATCH'
assert replay['payload_reached_gatekeeper'] is True and replay['attack_blocked'] is True
assert replay['gatekeeper_accepted_evidence'] is False and replay['rejection_code']=='CONTEXT_MISMATCH'
for name,payload in [('vulnerable',vuln),('fixed',fixed)]:
    prov=payload['provenance']
    raw=json.dumps(prov['manifest'],sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
    (out/f'{name}.manifest.json').write_bytes(raw)
    (out/f'{name}.sig.bin').write_bytes(bytes.fromhex(prov['signature_hex']))
    (out/f'{name}.key_version.txt').write_text(prov['key_version'])
(out/'vulnerable.trace_id.txt').write_text(vuln['distributed_trace']['trace_id'])
(out/'fixed.trace_id.txt').write_text(fixed['distributed_trace']['trace_id'])
print('STRUCTURAL CLOUD PROOF PASS')
PY

verify_signature() {
  local name="$1"
  local key_version version_id key keyring location
  key_version="$(cat "$TMP/$name.key_version.txt")"
  version_id="${key_version##*/}"
  key="$(python - "$key_version" <<'PY'
import sys
parts=sys.argv[1].split('/')
print(parts[parts.index('cryptoKeys')+1])
PY
)"
  keyring="$(python - "$key_version" <<'PY'
import sys
parts=sys.argv[1].split('/')
print(parts[parts.index('keyRings')+1])
PY
)"
  location="$(python - "$key_version" <<'PY'
import sys
parts=sys.argv[1].split('/')
print(parts[parts.index('locations')+1])
PY
)"
  gcloud kms keys versions get-public-key "$version_id" \
    --project "$PROJECT_ID" --location "$location" --keyring "$keyring" --key "$key" \
    --output-file "$TMP/$name.public.pem" >/dev/null
  openssl dgst -sha256 -verify "$TMP/$name.public.pem" \
    -signature "$TMP/$name.sig.bin" "$TMP/$name.manifest.json" >/dev/null
}
verify_signature vulnerable
verify_signature fixed

verify_trace() {
  local name="$1" trace_id token trace_file attempt
  trace_id="$(cat "$TMP/$name.trace_id.txt")"
  trace_file="$TMP/$name.trace.json"
  for attempt in $(seq 1 18); do
    token="$(gcloud auth print-access-token)"
    if curl -fsS \
      -H "Authorization: Bearer $token" \
      -H "x-goog-user-project: $PROJECT_ID" \
      "https://cloudtrace.googleapis.com/v1/projects/$PROJECT_ID/traces/$trace_id" \
      -o "$trace_file" \
      2>"$TMP/$name.trace.err"; then
      if python3 - "$trace_file" <<'PYCHECK'
import json,sys
expected={
    "release_verdict_pipeline",
    "advisory.security_reviewer",
    "advisory.test_reviewer",
    "advisory.dissent_reviewer",
    "advisory.evidence_explainer",
    "gatekeeper.a2a_call",
    "gatekeeper.verdict_decide",
}
with open(sys.argv[1], encoding="utf-8") as f:
    body=json.load(f)
have={str(span.get("name", "")) for span in body.get("spans", [])}
raise SystemExit(0 if expected.issubset(have) else 1)
PYCHECK
      then
        echo "CLOUD TRACE PASS fixture=$name trace_id=$trace_id"
        return 0
      fi
    fi
    if [[ "$attempt" -lt 18 ]]; then
      sleep 5
    fi
  done
  echo "CLOUD TRACE FAIL fixture=$name trace_id=$trace_id missing expected distributed spans" >&2
  if [[ -s "$TMP/$name.trace.err" ]]; then
    cat "$TMP/$name.trace.err" >&2
  fi
  if [[ -s "$trace_file" ]]; then
    python3 - "$trace_file" <<'PYMISSING' >&2 || true
import json,sys
expected={
    "release_verdict_pipeline",
    "advisory.security_reviewer",
    "advisory.test_reviewer",
    "advisory.dissent_reviewer",
    "advisory.evidence_explainer",
    "gatekeeper.a2a_call",
    "gatekeeper.verdict_decide",
}
try:
    with open(sys.argv[1], encoding="utf-8") as f:
        body=json.load(f)
    have={str(span.get("name", "")) for span in body.get("spans", [])}
    print("CLOUD TRACE MISSING:", sorted(expected-have))
except Exception as exc:
    print("CLOUD TRACE READ ERROR:", exc)
PYMISSING
  fi
  return 1
}
verify_trace vulnerable
verify_trace fixed

echo 'CLOUD TRUST PROOF PASS: adk=REAL gemini=REAL vulnerable=NO_GO fixed=GO sandbox=ATTESTOR_REAL policy=FIRESTORE signed_evidence=KMS_VERIFIED tamper=BLOCKED replay=BLOCKED provenance=KMS_VERIFIED ledger=FIRESTORE gatekeeper=GO_A2A agent_influence=0'
