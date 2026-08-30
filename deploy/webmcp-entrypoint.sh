#!/bin/sh
set -eu

APP_PORT="${PORT:-8080}"
KEY_DIR="${RELEASE_SENTINEL_WEBMCP_KEY_DIR:-/tmp/release-sentinel-webmcp}"
PRIVATE_KEY="$KEY_DIR/evidence-private.pem"
PUBLIC_KEY="$KEY_DIR/evidence-public.pem"

mkdir -p "$KEY_DIR"
chmod 700 "$KEY_DIR"
openssl ecparam -name prime256v1 -genkey -noout -out "$PRIVATE_KEY"
openssl pkey -in "$PRIVATE_KEY" -pubout -out "$PUBLIC_KEY"
chmod 600 "$PRIVATE_KEY"
chmod 644 "$PUBLIC_KEY"

export RELEASE_SENTINEL_DEMO_SIGNING_KEY="$PRIVATE_KEY"
export RELEASE_SENTINEL_EVIDENCE_PUBLIC_KEY_PATH="$PUBLIC_KEY"
export RELEASE_SENTINEL_EVIDENCE_KEY_ID=local-demo-ephemeral-key
export RELEASE_SENTINEL_GATEKEEPER_URL=http://127.0.0.1:9090
export RELEASE_SENTINEL_WEBMCP_JUDGED_MODE=1

PORT=9090 GATEKEEPER_PUBLIC_URL=http://127.0.0.1:9090 \
  /usr/local/bin/release-sentinel-gatekeeper &
GATEKEEPER_PID=$!

cleanup() {
  kill "$GATEKEEPER_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

python - <<'PY'
import json
import time
import urllib.request

url = "http://127.0.0.1:9090/healthz"
for _ in range(50):
    try:
        with urllib.request.urlopen(url, timeout=0.25) as response:
            payload = json.loads(response.read().decode("utf-8"))
        if payload.get("status") == "ok" and payload.get("signed_evidence_required") is True:
            break
    except Exception:
        time.sleep(0.1)
else:
    raise SystemExit("deterministic Go Gatekeeper did not become ready")
PY

exec uvicorn release_sentinel.interfaces.api:app --host 0.0.0.0 --port "$APP_PORT"
