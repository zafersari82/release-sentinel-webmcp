#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
mapfile -t declared < <(grep -vE '^\s*(#|$)' trust/COVERAGE_KERNEL.files)
mapfile -t manifested < <(awk '{print $2}' trust/COVERAGE_KERNEL.sha256)
[[ ${#declared[@]} -gt 0 ]] || { echo "COVERAGE KERNEL FAIL: empty scope" >&2; exit 2; }
[[ ${#declared[@]} -eq ${#manifested[@]} ]] || { echo "COVERAGE KERNEL FAIL: scope/manifest count mismatch" >&2; exit 2; }
for i in "${!declared[@]}"; do
  [[ "${declared[$i]}" == "${manifested[$i]}" ]] || {
    echo "COVERAGE KERNEL FAIL: manifest drift at index $i" >&2
    echo "declared=${declared[$i]} manifested=${manifested[$i]}" >&2
    exit 2
  }
done
sha256sum -c trust/COVERAGE_KERNEL.sha256
