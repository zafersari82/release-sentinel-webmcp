#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export PYTHONPATH="src:packages/agentseal/src${PYTHONPATH:+:$PYTHONPATH}"

VERSION="$(PYTHONPATH=src python -c 'from release_sentinel import __version__; print(__version__)')"
echo "== Release Sentinel v${VERSION}: DARE-YOU challenge =="
echo "AI may change software. It may never change the proof."
echo
python scripts/demo-autonomous-repair.py
echo
python scripts/challenge_report.py
echo
bash scripts/check-trust-kernel.sh
echo
(cd gatekeeper && go test ./...)
echo
pytest -q tests/test_agentseal_battery.py tests/test_remediation_authority.py tests/test_remediation_agent.py
echo
printf '%s\n' "DARE-YOU PASS: hostile substitution + trust-kernel freeze + self-approval firewall held."
