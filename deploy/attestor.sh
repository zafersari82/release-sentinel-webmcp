#!/usr/bin/env bash
set -euo pipefail
: "${PROJECT_ID:?set PROJECT_ID}"
: "${REGION:=us-central1}"
: "${POLICY_SHA256:?set POLICY_SHA256}"
: "${EVIDENCE_KMS_KEY_VERSION:?set EVIDENCE_KMS_KEY_VERSION}"
SERVICE="${ATTESTOR_SERVICE_NAME:-release-sentinel-attestor}"
ATTESTOR_SA_NAME="${ATTESTOR_SA_NAME:-release-sentinel-attestor}"
ATTESTOR_SA="$ATTESTOR_SA_NAME@$PROJECT_ID.iam.gserviceaccount.com"
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
  --service-account "$ATTESTOR_SA" \
  --no-allow-unauthenticated \
  --execution-environment gen2 \
  --sandbox-launcher \
  --concurrency 1 \
  --cpu 1 \
  --memory 1Gi \
  --timeout 120 \
  --command=uvicorn \
  --args=release_sentinel.interfaces.attestor_api:app,--host,0.0.0.0,--port,8080 \
  --set-env-vars="GOOGLE_CLOUD_PROJECT=$PROJECT_ID,GOOGLE_CLOUD_LOCATION=$REGION,RELEASE_SENTINEL_POLICY_DATABASE=$POLICY_DATABASE,RELEASE_SENTINEL_POLICY_ID=demo-release-policy,RELEASE_SENTINEL_POLICY_REVISION=1,RELEASE_SENTINEL_POLICY_SHA256=$POLICY_SHA256,RELEASE_SENTINEL_EVIDENCE_KMS_KEY_VERSION=$EVIDENCE_KMS_KEY_VERSION"

URL="$(gcloud run services describe "$SERVICE" --project "$PROJECT_ID" --region "$REGION" --format='value(status.url)')"
gcloud run services add-iam-policy-binding "$SERVICE" --project "$PROJECT_ID" --region "$REGION" \
  --member="serviceAccount:$RUNTIME_SA" --role="roles/run.invoker" --quiet >/dev/null
printf '%s\n' "$URL"
