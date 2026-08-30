#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
openssl ecparam -name prime256v1 -genkey -noout -out "$TMP/evidence-private.pem" >/dev/null 2>&1
openssl pkey -in "$TMP/evidence-private.pem" -pubout -out "$TMP/evidence-public.pem" >/dev/null 2>&1
cleanup() {
  if [[ -n "${GK_PID:-}" ]]; then
    kill "$GK_PID" >/dev/null 2>&1 || true
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT
cd "$ROOT/gatekeeper"; go build -trimpath -o "$TMP/gatekeeper" ./cmd/gatekeeper
PORT=8091 GATEKEEPER_PUBLIC_URL=http://127.0.0.1:8091 RELEASE_SENTINEL_EVIDENCE_PUBLIC_KEY_PATH="$TMP/evidence-public.pem" RELEASE_SENTINEL_EVIDENCE_KEY_ID="local-demo-ephemeral-key" "$TMP/gatekeeper" & GK_PID=$!
cd "$ROOT"
export RELEASE_SENTINEL_GATEKEEPER_URL=http://127.0.0.1:8091
export RELEASE_SENTINEL_DEMO_SIGNING_KEY="$TMP/evidence-private.pem"
export PYTHONPATH=src
python -m uvicorn release_sentinel.interfaces.api:app --host 127.0.0.1 --port 8080
