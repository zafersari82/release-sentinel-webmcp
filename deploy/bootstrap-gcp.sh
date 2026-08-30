#!/usr/bin/env bash
set -euo pipefail
: "${PROJECT_ID:?set PROJECT_ID}"
: "${REGION:=us-central1}"
: "${POLICY_DATABASE:=release-sentinel-policy}"
RUNTIME_SA_NAME="${RUNTIME_SA_NAME:-release-sentinel-runtime}"
GATEKEEPER_SA_NAME="${GATEKEEPER_SA_NAME:-release-sentinel-gatekeeper}"
ATTESTOR_SA_NAME="${ATTESTOR_SA_NAME:-release-sentinel-attestor}"
BUILD_SA_NAME="${BUILD_SA_NAME:-release-sentinel-builder}"
RUNTIME_SA="$RUNTIME_SA_NAME@$PROJECT_ID.iam.gserviceaccount.com"
GATEKEEPER_SA="$GATEKEEPER_SA_NAME@$PROJECT_ID.iam.gserviceaccount.com"
ATTESTOR_SA="$ATTESTOR_SA_NAME@$PROJECT_ID.iam.gserviceaccount.com"
BUILD_SA="$BUILD_SA_NAME@$PROJECT_ID.iam.gserviceaccount.com"

ACCOUNT="$(gcloud auth list --filter=status:ACTIVE --format='value(account)' | head -n1)"
[[ -n "$ACCOUNT" ]] || { echo "no active gcloud account" >&2; exit 2; }
if [[ "$ACCOUNT" == *.gserviceaccount.com ]]; then DEPLOYER_MEMBER="serviceAccount:$ACCOUNT"; else DEPLOYER_MEMBER="user:$ACCOUNT"; fi

gcloud services enable \
  run.googleapis.com \
  cloudbuild.googleapis.com \
  cloudresourcemanager.googleapis.com \
  artifactregistry.googleapis.com \
  firestore.googleapis.com \
  aiplatform.googleapis.com \
  cloudkms.googleapis.com \
  iam.googleapis.com \
  secretmanager.googleapis.com \
  logging.googleapis.com \
  monitoring.googleapis.com \
  cloudtrace.googleapis.com \
  telemetry.googleapis.com \
  --project "$PROJECT_ID"

ensure_sa() {
  local name="$1" display="$2" email="$1@$PROJECT_ID.iam.gserviceaccount.com"
  if ! gcloud iam service-accounts describe "$email" --project "$PROJECT_ID" >/dev/null 2>&1; then
    gcloud iam service-accounts create "$name" --project "$PROJECT_ID" --display-name="$display"
  fi
}
ensure_sa "$RUNTIME_SA_NAME" "Release Sentinel runtime"
ensure_sa "$GATEKEEPER_SA_NAME" "Release Sentinel deterministic Gatekeeper"
ensure_sa "$ATTESTOR_SA_NAME" "Release Sentinel evidence attestor"
ensure_sa "$BUILD_SA_NAME" "Release Sentinel source build identity"

# Creating a service account and changing its IAM policy are distinct permissions.
# Validate the latter explicitly before attempting to grant actAs.
TOKEN="$(gcloud auth print-access-token)"
for sa in "$RUNTIME_SA" "$GATEKEEPER_SA" "$ATTESTOR_SA" "$BUILD_SA"; do
  SA_RESP="$(curl -fsS -X POST \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d '{"permissions":["iam.serviceAccounts.setIamPolicy"]}' \
    "https://iam.googleapis.com/v1/projects/$PROJECT_ID/serviceAccounts/$sa:testIamPermissions")"
  if ! python3 - "$SA_RESP" <<'PY2'
import json,sys
raise SystemExit(0 if "iam.serviceAccounts.setIamPolicy" in json.loads(sys.argv[1]).get("permissions", []) else 1)
PY2
  then
    echo "BOOTSTRAP FAIL: $ACCOUNT cannot manage IAM on $sa" >&2
    echo "Grant roles/iam.serviceAccountAdmin (or equivalent iam.serviceAccounts.setIamPolicy) to the deployer, then rerun." >&2
    exit 3
  fi
done

# The deployer may impersonate only the three purpose-specific service accounts.
for sa in "$RUNTIME_SA" "$GATEKEEPER_SA" "$ATTESTOR_SA" "$BUILD_SA"; do
  gcloud iam service-accounts add-iam-policy-binding "$sa" \
    --project "$PROJECT_ID" \
    --member="$DEPLOYER_MEMBER" \
    --role="roles/iam.serviceAccountUser" \
    --quiet >/dev/null
done

# Current Cloud Run source-deploy guidance requires the build identity to have
# the Cloud Run Builder role. We pass this identity explicitly at deploy time.
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:$BUILD_SA" \
  --role="roles/run.builder" \
  --condition=None \
  --quiet >/dev/null

ensure_db() {
  local db="$1"
  if ! gcloud firestore databases describe --project "$PROJECT_ID" --database "$db" >/dev/null 2>&1; then
    gcloud firestore databases create --project "$PROJECT_ID" --database "$db" --location "$REGION" --type=firestore-native --delete-protection
  fi
}
ensure_db "(default)"
ensure_db "$POLICY_DATABASE"

# Runtime may read the named policy database but not mutate policy documents.
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:$RUNTIME_SA" \
  --role="roles/datastore.viewer" \
  --condition="expression=resource.name=='projects/$PROJECT_ID/databases/$POLICY_DATABASE',title=release_sentinel_policy_readonly,description=Read-only organization policy database" \
  --quiet >/dev/null

# Attestor may read immutable organization policy but cannot write it.
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:$ATTESTOR_SA" \
  --role="roles/datastore.viewer" \
  --condition="expression=resource.name=='projects/$PROJECT_ID/databases/$POLICY_DATABASE',title=release_sentinel_attestor_policy_readonly,description=Evidence attestor read-only organization policy" \
  --quiet >/dev/null

# Runtime may append immutable evidence reports to the ledger database.
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:$RUNTIME_SA" \
  --role="roles/datastore.user" \
  --condition="expression=resource.name=='projects/$PROJECT_ID/databases/(default)',title=release_sentinel_ledger_rw,description=Evidence ledger database" \
  --quiet >/dev/null

gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:$RUNTIME_SA" \
  --role="roles/aiplatform.user" --condition=None --quiet >/dev/null

# Both application identities may emit trace telemetry through the local
# Google-built OpenTelemetry Collector. These permissions do not grant model,
# Firestore, KMS, or Gatekeeper decision authority.
for sa in "$RUNTIME_SA" "$GATEKEEPER_SA"; do
  gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    --member="serviceAccount:$sa" \
    --role="roles/telemetry.tracesWriter" --condition=None --quiet >/dev/null
  gcloud projects add-iam-policy-binding "$PROJECT_ID" \
    --member="serviceAccount:$sa" \
    --role="roles/serviceusage.serviceUsageConsumer" --condition=None --quiet >/dev/null
done


echo "BOOTSTRAP PASS runtime_sa=$RUNTIME_SA gatekeeper_sa=$GATEKEEPER_SA attestor_sa=$ATTESTOR_SA build_sa=$BUILD_SA deployer=$ACCOUNT"
