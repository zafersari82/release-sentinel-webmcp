#!/usr/bin/env bash
set -euo pipefail
: "${PROJECT_ID:?set PROJECT_ID}"
: "${REGION:=us-central1}"
: "${VERTEX_LOCATION:=global}"
: "${POLICY_SHA256:?set POLICY_SHA256}"
: "${KMS_KEY_VERSION:?set KMS_KEY_VERSION}"
: "${GATEKEEPER_URL:?set GATEKEEPER_URL}"
: "${ATTESTOR_URL:?set ATTESTOR_URL}"
: "${EVIDENCE_KMS_KEY_VERSION:?set EVIDENCE_KMS_KEY_VERSION}"
SERVICE="${SERVICE_NAME:-release-sentinel}"
RUNTIME_SA_NAME="${RUNTIME_SA_NAME:-release-sentinel-runtime}"
RUNTIME_SA="$RUNTIME_SA_NAME@$PROJECT_ID.iam.gserviceaccount.com"
BUILD_SA_NAME="${BUILD_SA_NAME:-release-sentinel-builder}"
BUILD_SA="$BUILD_SA_NAME@$PROJECT_ID.iam.gserviceaccount.com"
POLICY_DATABASE="${POLICY_DATABASE:-release-sentinel-policy}"

gcloud beta run deploy "$SERVICE" \
  --project "$PROJECT_ID" \
  --region "$REGION" \
  --source . \
  --build-service-account "projects/$PROJECT_ID/serviceAccounts/$BUILD_SA" \
  --service-account "$RUNTIME_SA" \
  --no-allow-unauthenticated \
  --execution-environment gen2 \
  --concurrency 1 \
  --cpu 2 \
  --memory 2Gi \
  --timeout 600 \
  --set-env-vars="RELEASE_SENTINEL_MODEL=gemini-3.6-flash,GOOGLE_CLOUD_PROJECT=$PROJECT_ID,GOOGLE_CLOUD_LOCATION=$VERTEX_LOCATION,GOOGLE_GENAI_USE_ENTERPRISE=TRUE,RELEASE_SENTINEL_POLICY_DATABASE=$POLICY_DATABASE,RELEASE_SENTINEL_LEDGER_DATABASE=(default),RELEASE_SENTINEL_POLICY_ID=demo-release-policy,RELEASE_SENTINEL_POLICY_REVISION=1,RELEASE_SENTINEL_POLICY_SHA256=$POLICY_SHA256,RELEASE_SENTINEL_PROVENANCE_SIGNING_REQUIRED=true,RELEASE_SENTINEL_KMS_KEY_VERSION=$KMS_KEY_VERSION,RELEASE_SENTINEL_GATEKEEPER_URL=$GATEKEEPER_URL,RELEASE_SENTINEL_GATEKEEPER_AUDIENCE=$GATEKEEPER_URL,RELEASE_SENTINEL_ATTESTOR_URL=$ATTESTOR_URL,RELEASE_SENTINEL_ATTESTOR_AUDIENCE=$ATTESTOR_URL,RELEASE_SENTINEL_EVIDENCE_KMS_KEY_VERSION=$EVIDENCE_KMS_KEY_VERSION"

ACCOUNT="$(gcloud auth list --filter=status:ACTIVE --format='value(account)' | head -n1)"
if [[ "$ACCOUNT" == *.gserviceaccount.com ]]; then MEMBER="serviceAccount:$ACCOUNT"; else MEMBER="user:$ACCOUNT"; fi
gcloud run services add-iam-policy-binding "$SERVICE" --project "$PROJECT_ID" --region "$REGION" \
  --member="$MEMBER" --role="roles/run.invoker" --quiet >/dev/null

SERVICE_NAME="$SERVICE" SERVICE_ACCOUNT="$RUNTIME_SA" OTEL_SECRET_NAME="${SERVICE}-otel-config" ./deploy/otel-sidecar.sh
gcloud run services describe "$SERVICE" --project "$PROJECT_ID" --region "$REGION" --format='value(status.url)'
