#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GK_PORT="${GATEKEEPER_ATTACK_PORT:-18091}"
API_PORT="${RELEASE_SENTINEL_ATTACK_PORT:-18080}"
TMP="$(mktemp -d)"
cleanup(){ kill ${API_PID:-0} ${GK_PID:-0} 2>/dev/null || true; rm -rf "$TMP"; }
trap cleanup EXIT

command -v go >/dev/null || { echo "Go 1.23+ is required" >&2; exit 2; }
command -v openssl >/dev/null || { echo "OpenSSL is required" >&2; exit 2; }
command -v curl >/dev/null || { echo "curl is required" >&2; exit 2; }

openssl ecparam -name prime256v1 -genkey -noout -out "$TMP/evidence-private.pem" >/dev/null 2>&1
openssl pkey -in "$TMP/evidence-private.pem" -pubout -out "$TMP/evidence-public.pem" >/dev/null 2>&1
go build -C "$ROOT/gatekeeper" -o "$TMP/gatekeeper" ./cmd/gatekeeper
PORT="$GK_PORT" \
GATEKEEPER_PUBLIC_URL="http://127.0.0.1:$GK_PORT" \
RELEASE_SENTINEL_EVIDENCE_PUBLIC_KEY_PATH="$TMP/evidence-public.pem" \
RELEASE_SENTINEL_EVIDENCE_KEY_ID="local-demo-ephemeral-key" \
  "$TMP/gatekeeper" >"$TMP/gatekeeper.log" 2>&1 & GK_PID=$!
for _ in $(seq 1 80); do curl -fsS "http://127.0.0.1:$GK_PORT/healthz" >/dev/null 2>&1 && break; sleep .05; done

cd "$ROOT"
PYTHONPATH=src \
RELEASE_SENTINEL_GATEKEEPER_URL="http://127.0.0.1:$GK_PORT" \
RELEASE_SENTINEL_DEMO_SIGNING_KEY="$TMP/evidence-private.pem" \
  python -m uvicorn release_sentinel.interfaces.api:app --host 127.0.0.1 --port "$API_PORT" >"$TMP/api.log" 2>&1 & API_PID=$!
for _ in $(seq 1 100); do curl -fsS "http://127.0.0.1:$API_PORT/healthz" >/dev/null 2>&1 && break; sleep .05; done

run_attack(){
  local attack="$1" expected_accept="$2" expected_code="$3" expected_verdict="$4"
  local raw
  raw="$(curl -fsS -X POST "http://127.0.0.1:$API_PORT/v1/demo/attack-gate/$attack")"
  python - "$raw" "$attack" "$expected_accept" "$expected_code" "$expected_verdict" <<'PY'
import json,sys
p=json.loads(sys.argv[1]); attack,accept,code,verdict=sys.argv[2:]
assert p['attack']==attack and p['payload_reached_gatekeeper'] is True and p['attack_blocked'] is True
assert p['gatekeeper_accepted_evidence'] is (accept=='true')
if code!='-': assert (p.get('rejection_code') or p.get('result_code'))==code
if verdict!='-': assert p.get('final_verdict')==verdict
print(f"{attack:22} BLOCKED  accepted={p['gatekeeper_accepted_evidence']}  code={p.get('rejection_code') or p.get('result_code')}  verdict={p.get('final_verdict')}")
PY
}

run_attack force_agents_go true VERDICT_UNCHANGED NO_GO
run_attack downgrade_severity false DIGEST_MISMATCH -
run_attack delete_blocker false DIGEST_MISMATCH -
run_attack forge_authority true IGNORED_NOT_IN_TRUST_SCHEMA NO_GO
run_attack replay_previous_go false CONTEXT_MISMATCH -
run_attack tamper_evidence_digest false DIGEST_MISMATCH -

echo "ATTACK THE GATE PASS: attempted=6 blocked=6 agent_influence=0"
