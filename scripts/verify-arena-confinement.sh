#!/usr/bin/env bash
# Prove the arena confinement contract is live, not decorative.
#
# run-public-attack.sh already shows the arena works when the profile is
# correct. That is the easy half. This script removes one isolation property at
# a time and asserts the worker refuses with the matching reason.
#
# An assertion that never fires is indistinguishable from an assertion that
# isn't there. Any NEGATIVE CONTROL FAILED line below means that specific
# check in assert_arena_confinement() is vacuous.
#
# Usage:
#   ./scripts/verify-arena-confinement.sh
set -uo pipefail

# Runnable from anywhere: resolve the repository root from this script's own
# location rather than requiring the caller to be in the right directory.
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

IMAGE="release-sentinel-arena-verify"
PASS=0
FAIL=0
SKIP=0

command -v docker >/dev/null 2>&1 || {
  echo "docker is required; this script has nothing to verify without it." >&2
  exit 1
}

[[ -f challenge/runtime/Dockerfile ]] || {
  echo "run this from the repository root." >&2
  exit 1
}

echo "Building arena image..."
docker build -q -f challenge/runtime/Dockerfile -t "$IMAGE" . >/dev/null || {
  echo "image build failed" >&2; exit 1; }

STAGE="$(mktemp -d)/submission"
mkdir -p "$STAGE"

# A submission of our own, not the bundled example. The example asserts on
# snapshot structure, so a failure there is indistinguishable from a
# confinement refusal -- exactly the ambiguity this harness exists to remove.
# This one ignores its input, never raises, and reports what the worker
# actually observed, so any non-zero exit is unambiguously a refusal and any
# success tells us why the confinement check was satisfied.
cat >"$STAGE/attack.py" <<'INERT'
def attack(snapshot):
    import os, resource, socket
    from pathlib import Path

    def mount_opts(point):
        try:
            for line in Path("/proc/self/mountinfo").read_text().splitlines():
                f = line.split()
                if len(f) >= 6 and f[4] == point:
                    return f[5]
        except OSError:
            pass
        return "ABSENT"

    status = {}
    try:
        for line in Path("/proc/self/status").read_text().splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                status[k] = v.strip()
    except OSError:
        pass

    return {
        "observed": {
            "uid": os.geteuid(),
            "seccomp": status.get("Seccomp", "?"),
            "capeff": status.get("CapEff", "?"),
            "nonewprivs": status.get("NoNewPrivs", "?"),
            "root_mount": mount_opts("/"),
            "tmp_mount": mount_opts("/tmp"),
            "submission_mount": mount_opts("/submission"),
            "interfaces": sorted(n for _, n in socket.if_nameindex()),
            "nofile": resource.getrlimit(resource.RLIMIT_NOFILE),
        }
    }
INERT
chmod 0444 "$STAGE/attack.py"

SNAPSHOT="$(mktemp)"
echo '{"release_id":"confinement-verification"}' >"$SNAPSHOT"

# The full profile, as run-public-attack.sh applies it. Each entry is one
# logical property: a key, then the docker tokens it contributes. Grouping them
# this way means a control can remove exactly one property without disturbing
# its neighbours -- a naive "drop this flag" filter silently eats the next flag
# whenever the dropped one takes no value.
PROFILE=(
  $'net\t--network\tnone'
  $'ro\t--read-only'
  $'tmpfs\t--tmpfs\t/tmp:rw,nosuid,nodev,noexec,size=16m'
  $'caps\t--cap-drop\tALL'
  $'nnp\t--security-opt\tno-new-privileges'
  $'pids\t--pids-limit\t64'
  $'mem\t--memory\t256m'
  $'memsw\t--memory-swap\t256m'
  $'cpus\t--cpus\t1'
  $'nofile\t--ulimit\tnofile=64:64'
  $'ipc\t--ipc\tnone'
  $'user\t--user\t10001:10001'
  $'mount\t-v\tMOUNTSPEC'
)

# build_profile <comma-separated-keys-to-omit|-> [extra docker args...]
build_profile() {
  local omit=",$1,"; shift
  local entry key rest
  for entry in "${PROFILE[@]}"; do
    key="${entry%%$'\t'*}"
    [[ "$omit" == *",$key,"* ]] && continue
    rest="${entry#*$'\t'}"
    while [[ -n "$rest" ]]; do
      if [[ "$rest" == *$'\t'* ]]; then
        printf '%s\n' "${rest%%$'\t'*}"
        rest="${rest#*$'\t'}"
      else
        printf '%s\n' "${rest/MOUNTSPEC/$STAGE:/submission:ro}"
        break
      fi
    done
  done
  (($#)) && printf '%s\n' "$@"
  return 0
}

run_profile() {
  timeout --signal=KILL 20s docker run --rm -i "$@" "$IMAGE" <"$SNAPSHOT" 2>/dev/null
}

# A control has four possible outcomes, and conflating them is how a harness
# ends up lying about the thing it exists to check:
#
#   VACUOUS    the property was genuinely removed and the worker ran anyway.
#              The assertion does nothing. This is the only real failure.
#   LIVE       refused, naming this property. The assertion works.
#   SHADOWED   refused, but by an earlier assertion. Cannot be isolated,
#              because the condition needed to reach it trips something first.
#   UNTESTABLE the worker ran, but the observed state shows the property was
#              never actually changed -- the host refused to weaken it. The
#              assertion was never given a chance, so nothing is proven.
#
# $3 is a fragment that must appear in the observed state when the condition
# really was created. Absent it, a successful run is UNTESTABLE, not VACUOUS.
negative_control() {
  local name="$1" expected="$2" probe="$3"; shift 3
  local out rc
  out="$(run_profile "$@")"; rc=$?

  if [[ $rc -eq 0 ]]; then
    if [[ -n "$probe" && "$out" != *"$probe"* ]]; then
      echo "  UNTESTABLE ON THIS HOST     $name"
      echo "      docker did not apply the change; the condition never existed."
      echo "      observed: ${out:0:300}"
      SKIP=$((SKIP+1)); return
    fi
    echo "  VACUOUS ASSERTION           $name"
    echo "      the property was removed and untrusted code ran anyway."
    echo "      observed: ${out:0:300}"
    FAIL=$((FAIL+1)); return
  fi

  if [[ "$out" == *"$expected"* ]]; then
    echo "  live                        $name"
    PASS=$((PASS+1)); return
  fi

  if [[ "$out" == *"confinement check failed"* ]]; then
    echo "  shadowed by earlier check   $name"
    echo "      refused, but by: ${out:0:150}"
    SKIP=$((SKIP+1)); return
  fi

  echo "  UNEXPECTED FAILURE          $name"
  echo "      ${out:0:300}"
  FAIL=$((FAIL+1))
}

echo
echo "=== POSITIVE CONTROL — the real profile must run ==="
mapfile -t P < <(build_profile -)
out="$(run_profile "${P[@]}")"; rc=$?
if [[ $rc -eq 0 && "$out" != *"confinement check failed"* ]]; then
  echo "  accepted                  full arena profile"
  echo "      observed: ${out:0:400}"
  PASS=$((PASS+1))
else
  echo "  POSITIVE CONTROL FAILED   full arena profile was rejected"
  echo "      ${out:0:200}"
  echo "      the arena is broken: no submission can ever run."
  FAIL=$((FAIL+1))
fi

echo
echo "=== NEGATIVE CONTROLS — each must be refused, with the right reason ==="

mapfile -t P < <(build_profile ro)
negative_control "writable root filesystem" "root filesystem is not read-only" "\"root_mount\":\"rw" "${P[@]}"

# Dropping --user does nothing: the image itself declares USER 10001, so the
# container stays non-root and the assertion never gets a chance to fire.
# Force uid 0 explicitly to actually exercise it.
mapfile -t P < <(build_profile user --user 0:0)
negative_control "running as root (uid 0)" "unexpected worker uid" "\"uid\":0" "${P[@]}"

mapfile -t P < <(build_profile net)
negative_control "network namespace attached" "network namespace is not isolated" "eth0" "${P[@]}"

# A non-root process has no effective capabilities regardless of --cap-drop,
# so this control only means something as root.
mapfile -t P < <(build_profile caps,user --user 0:0)
negative_control "capabilities retained" "effective capabilities are not empty" "\"uid\":0" "${P[@]}"

mapfile -t P < <(build_profile - --security-opt seccomp=unconfined)
negative_control "seccomp disabled" "seccomp filter is not active" "\"seccomp\":\"0" "${P[@]}"

mapfile -t P < <(build_profile nnp)
negative_control "no-new-privileges removed" "no-new-privileges is not active" "\"nonewprivs\":\"0" "${P[@]}"

mapfile -t P < <(build_profile nofile)
negative_control "file-descriptor limit raised" "file-descriptor limit is too permissive" "\"nofile\"" "${P[@]}"

mapfile -t P < <(build_profile tmpfs)
negative_control "tmpfs hardening removed" "/tmp" "\"tmp_mount\":\"ABSENT" "${P[@]}"

mapfile -t P < <(build_profile mount -v "$STAGE:/submission:rw")
negative_control "submission mounted writable" "submission mount is not read-only" "\"submission_mount\":\"rw" "${P[@]}"

# A symlinked attack.py would let a submission point at a file outside the
# staged directory. The worker must reject it before importing anything.
LINKSTAGE="$(mktemp -d)/submission"
mkdir -p "$LINKSTAGE"
ln -s /etc/hostname "$LINKSTAGE/attack.py"
mapfile -t P < <(build_profile mount -v "$LINKSTAGE:/submission:ro")
negative_control "attack.py is a symlink" "regular attack.py" "" "${P[@]}"

echo
echo "=== HOST PATH — the worker must refuse outside a container entirely ==="
for prefix in "" "RELEASE_SENTINEL_ARENA_CONTAINER=1"; do
  out="$(echo '{}' | env $prefix python3 challenge/runtime/worker.py 2>/dev/null)"; rc=$?
  label="no env"; [[ -n "$prefix" ]] && label="forged marker"
  if [[ $rc -eq 0 ]]; then
    echo "  HOST PATH FAILED          $label — untrusted code ran with no container"
    FAIL=$((FAIL+1))
  elif [[ "$out" == *"confinement check failed"* ]]; then
    echo "  refused                   $label (${out:0:90})"
    PASS=$((PASS+1))
  else
    echo "  refused (unclear reason)  $label: ${out:0:120}"
    FAIL=$((FAIL+1))
  fi
done

echo
echo "======================================================================"
echo "  live: $PASS    vacuous: $FAIL    not isolatable here: $SKIP"
if [[ $FAIL -eq 0 ]]; then
  echo "  NO VACUOUS ASSERTIONS. Every property this host could weaken was refused."
  if [[ $SKIP -gt 0 ]]; then
    echo "  $SKIP could not be isolated on this host (shadowed, or the host refused"
    echo "  to weaken them). Run on plain Docker Engine — the CI arena job does."
  fi
else
  echo "  CONFINEMENT CONTRACT HAS GAPS — $FAIL assertion(s) do nothing."
fi
echo "======================================================================"
[[ $FAIL -eq 0 ]]
