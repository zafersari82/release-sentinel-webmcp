#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SUBMISSION="${1:-}"
VERSION="$(PYTHONPATH="$ROOT/src" python -c 'from release_sentinel import __version__; print(__version__)')"
IMAGE="${RELEASE_SENTINEL_ARENA_IMAGE:-release-sentinel-public-arena:${VERSION}}"

if [[ -z "$SUBMISSION" || ! -f "$SUBMISSION/attack.py" ]]; then
  echo "usage: $0 <submission-directory-containing-attack.py>" >&2
  exit 2
fi
if [[ -L "$SUBMISSION/attack.py" ]]; then
  echo "attack.py must be a regular file, not a symlink" >&2
  exit 2
fi
if [[ $(wc -c <"$SUBMISSION/attack.py") -gt 131072 ]]; then
  echo "attack.py exceeds the 128 KiB source limit" >&2
  exit 2
fi
command -v docker >/dev/null 2>&1 || {
  echo "Docker is required for arbitrary-code submissions. Do not run public attack.py files directly on the host." >&2
  exit 2
}
command -v timeout >/dev/null 2>&1 || {
  echo "GNU timeout is required to enforce a wall-clock limit on untrusted code." >&2
  exit 2
}
SUBMISSION="$(cd "$SUBMISSION" && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
STAGE="$TMP/submission"
mkdir -p "$STAGE"
cp -- "$SUBMISSION/attack.py" "$STAGE/attack.py"
chmod 0444 "$STAGE/attack.py"

cd "$ROOT"
docker build -q -f challenge/runtime/Dockerfile -t "$IMAGE" . >/dev/null

PYTHONPATH=src python scripts/arena_snapshot.py >"$TMP/snapshot.json"

# This Docker profile is defense-in-depth for local/community testing. Public
# internet execution should additionally use a disposable VM/microVM boundary.
set +e
timeout --signal=KILL 10s docker run --rm -i \
  --network none \
  --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=16m \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --pids-limit 64 \
  --memory 256m \
  --memory-swap 256m \
  --cpus 1 \
  --ulimit nofile=64:64 \
  --ipc none \
  --user 10001:10001 \
  -v "$STAGE:/submission:ro" \
  "$IMAGE" <"$TMP/snapshot.json" >"$TMP/attack-output.json"
worker_rc=$?
set -e
if [[ $worker_rc -ne 0 ]]; then
  echo "Submission process failed closed (worker exit $worker_rc)." >&2
  cat "$TMP/attack-output.json" >&2 || true
  exit 2
fi

set +e
PYTHONPATH=src python scripts/verify-public-attack.py "$TMP/attack-output.json"
verify_rc=$?
set -e
case "$verify_rc" in
  0)
    echo
    echo "SENTINEL HELD: agent/application-plane compromise did not change authority."
    exit 0
    ;;
  10)
    echo
    echo "BREAKER WON: an authority invariant changed under identical ground truth."
    echo "Preserve the submission and open a responsible disclosure report."
    exit 10
    ;;
  *)
    exit "$verify_rc"
    ;;
esac
