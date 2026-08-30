#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
command -v go >/dev/null || { echo "Go 1.23+ is required for the local jury demo." >&2; exit 2; }
GO_VERSION="$(go env GOVERSION 2>/dev/null || go version | awk '{print $3}')"
python3 - "$GO_VERSION" <<'PY2'
import re,sys
m=re.search(r'(\d+)\.(\d+)', sys.argv[1])
if not m or tuple(map(int,m.groups())) < (1,23):
    raise SystemExit('Go 1.23+ is required; found '+sys.argv[1])
PY2
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
cd "$ROOT/gatekeeper"
go test ./...
go build -trimpath -o "$TMP/gatekeeper" ./cmd/gatekeeper
PORT="${GATEKEEPER_DEMO_PORT:-8091}" GATEKEEPER_PUBLIC_URL="http://127.0.0.1:${GATEKEEPER_DEMO_PORT:-8091}" RELEASE_SENTINEL_EVIDENCE_PUBLIC_KEY_PATH="$TMP/evidence-public.pem" RELEASE_SENTINEL_EVIDENCE_KEY_ID="local-demo-ephemeral-key" "$TMP/gatekeeper" >"$TMP/gatekeeper.log" 2>&1 & GK_PID=$!
for _ in $(seq 1 50); do curl -fsS "http://127.0.0.1:${GATEKEEPER_DEMO_PORT:-8091}/healthz" >/dev/null 2>&1 && break; sleep .05; done
cd "$ROOT"
RELEASE_SENTINEL_DEMO_SIGNING_KEY="$TMP/evidence-private.pem" PYTHONPATH=src python -m release_sentinel.interfaces.cli verdict-proof --gatekeeper-url "http://127.0.0.1:${GATEKEEPER_DEMO_PORT:-8091}"
