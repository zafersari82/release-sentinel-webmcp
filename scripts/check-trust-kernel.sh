#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

mapfile -t declared < <(grep -vE '^\s*(#|$)' trust/TRUST_KERNEL.files)
mapfile -t manifested < <(awk '{print $2}' trust/TRUST_KERNEL.sha256)

[[ ${#declared[@]} -gt 0 ]] || { echo "TRUST KERNEL FAIL: empty scope" >&2; exit 2; }
[[ ${#declared[@]} -eq ${#manifested[@]} ]] || { echo "TRUST KERNEL FAIL: scope/manifest count mismatch" >&2; exit 2; }

for i in "${!declared[@]}"; do
  [[ "${declared[$i]}" == "${manifested[$i]}" ]] || {
    echo "TRUST KERNEL FAIL: manifest drift at index $i" >&2
    echo "declared=${declared[$i]} manifested=${manifested[$i]}" >&2
    exit 2
  }
done

sha256sum -c trust/TRUST_KERNEL.sha256
