#!/usr/bin/env bash
set -euo pipefail
: "${PROJECT_ID:?set PROJECT_ID}"
: "${REGION:=us-central1}"
: "${EVIDENCE_KMS_KEY_VERSION:?set EVIDENCE_KMS_KEY_VERSION}"
SERVICE="${GATEKEEPER_SERVICE_NAME:-release-sentinel-gatekeeper}"
RUNTIME_SA_NAME="${RUNTIME_SA_NAME:-release-sentinel-runtime}"
RUNTIME_SA="$RUNTIME_SA_NAME@$PROJECT_ID.iam.gserviceaccount.com"
GATEKEEPER_SA_NAME="${GATEKEEPER_SA_NAME:-release-sentinel-gatekeeper}"
GATEKEEPER_SA="$GATEKEEPER_SA_NAME@$PROJECT_ID.iam.gserviceaccount.com"
BUILD_SA_NAME="${BUILD_SA_NAME:-release-sentinel-builder}"
BUILD_SA="$BUILD_SA_NAME@$PROJECT_ID.iam.gserviceaccount.com"

if ! gcloud iam service-accounts describe "$GATEKEEPER_SA" --project "$PROJECT_ID" >/dev/null 2>&1; then
  gcloud iam service-accounts create "$GATEKEEPER_SA_NAME" --project "$PROJECT_ID" --display-name="Release Sentinel deterministic Gatekeeper"
fi

KEY_VERSION_ID="${EVIDENCE_KMS_KEY_VERSION##*/}"
KEY_NAME="$(python3 - "$EVIDENCE_KMS_KEY_VERSION" <<'PY2'
import sys
p=sys.argv[1].split('/')
print(p[p.index('cryptoKeys')+1])
PY2
)"
KEYRING="$(python3 - "$EVIDENCE_KMS_KEY_VERSION" <<'PY2'
import sys
p=sys.argv[1].split('/')
print(p[p.index('keyRings')+1])
PY2
)"
LOCATION="$(python3 - "$EVIDENCE_KMS_KEY_VERSION" <<'PY2'
import sys
p=sys.argv[1].split('/')
print(p[p.index('locations')+1])
PY2
)"
TMP_PUB="$(mktemp)"; trap 'rm -f "$TMP_PUB"' EXIT
gcloud kms keys versions get-public-key "$KEY_VERSION_ID" --project "$PROJECT_ID" --location "$LOCATION" --keyring "$KEYRING" --key "$KEY_NAME" --output-file "$TMP_PUB" >/dev/null
PUBLIC_KEY_B64="$(base64 < "$TMP_PUB" | tr -d '\n')"

gcloud run deploy "$SERVICE" \
  --project "$PROJECT_ID" \
  --region "$REGION" \
  --source gatekeeper \
  --build-service-account "projects/$PROJECT_ID/serviceAccounts/$BUILD_SA" \
  --service-account "$GATEKEEPER_SA" \
  --no-allow-unauthenticated \
  --cpu 1 \
  --memory 256Mi \
  --concurrency 40 \
  --timeout 30 \
  --set-env-vars="RELEASE_SENTINEL_EVIDENCE_PUBLIC_KEY_B64=$PUBLIC_KEY_B64,RELEASE_SENTINEL_EVIDENCE_KEY_ID=$EVIDENCE_KMS_KEY_VERSION"

URL="$(gcloud run services describe "$SERVICE" --project "$PROJECT_ID" --region "$REGION" --format='value(status.url)')"
gcloud run services update "$SERVICE" --project "$PROJECT_ID" --region "$REGION" --update-env-vars="GATEKEEPER_PUBLIC_URL=$URL" >/dev/null

gcloud run services add-iam-policy-binding "$SERVICE" --project "$PROJECT_ID" --region "$REGION" \
  --member="serviceAccount:$RUNTIME_SA" --role="roles/run.invoker" --quiet >/dev/null
SERVICE_NAME="$SERVICE" SERVICE_ACCOUNT="$GATEKEEPER_SA" OTEL_SECRET_NAME="${SERVICE}-otel-config" ./deploy/otel-sidecar.sh
printf '%s\n' "$URL"
