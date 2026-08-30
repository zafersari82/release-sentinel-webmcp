#!/usr/bin/env bash
set -euo pipefail
: "${PROJECT_ID:?set PROJECT_ID}"
: "${REGION:=us-central1}"
export REGION
./deploy/preflight.sh
./deploy/bootstrap-gcp.sh
python -m pip install -q -e '.[cloud]'
POLICY_JSON="src/release_sentinel/demo_fixture/organization-policy.json"
SEED_JSON="$(python deploy/seed_policy.py --project "$PROJECT_ID" --database "${POLICY_DATABASE:-release-sentinel-policy}" --policy "$POLICY_JSON")"
POLICY_SHA256="$(python -c 'import json,sys; print(json.loads(sys.argv[1])["sha256"])' "$SEED_JSON")"
export POLICY_SHA256
KMS_KEY_VERSION="$(./deploy/provenance-key.sh | tail -n1)"
export KMS_KEY_VERSION
EVIDENCE_KMS_KEY_VERSION="$(./deploy/evidence-key.sh | tail -n1)"
export EVIDENCE_KMS_KEY_VERSION
ATTESTOR_URL="$(./deploy/attestor.sh | tail -n1)"
export ATTESTOR_URL
GATEKEEPER_URL="$(./deploy/gatekeeper.sh | tail -n1)"
export GATEKEEPER_URL
./deploy/cloudrun.sh
./deploy/cloud-proof.sh
