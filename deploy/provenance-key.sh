#!/usr/bin/env bash
set -euo pipefail
: "${PROJECT_ID:?set PROJECT_ID}"
: "${REGION:=us-central1}"
RUNTIME_SA_NAME="${RUNTIME_SA_NAME:-release-sentinel-runtime}"
RUNTIME_SA="$RUNTIME_SA_NAME@$PROJECT_ID.iam.gserviceaccount.com"
KEYRING="${KMS_KEYRING:-release-sentinel}"
KEY="${KMS_KEY:-provenance-signing}"

if ! gcloud kms keyrings describe "$KEYRING" --project "$PROJECT_ID" --location "$REGION" >/dev/null 2>&1; then
  gcloud kms keyrings create "$KEYRING" --project "$PROJECT_ID" --location "$REGION"
fi
if ! gcloud kms keys describe "$KEY" --project "$PROJECT_ID" --location "$REGION" --keyring "$KEYRING" >/dev/null 2>&1; then
  gcloud kms keys create "$KEY" --project "$PROJECT_ID" --location "$REGION" --keyring "$KEYRING" \
    --purpose=asymmetric-signing --default-algorithm=ec-sign-p256-sha256
fi

gcloud kms keys add-iam-policy-binding "$KEY" --project "$PROJECT_ID" --location "$REGION" --keyring "$KEYRING" \
  --member="serviceAccount:$RUNTIME_SA" --role="roles/cloudkms.signer" --quiet >/dev/null

VERSION="$(gcloud kms keys versions list --project "$PROJECT_ID" --location "$REGION" --keyring "$KEYRING" --key "$KEY" \
  --filter='state=ENABLED' --sort-by='~name' --limit=1 --format='value(name)' | head -n1)"
[[ -n "$VERSION" ]] || { echo "no ENABLED KMS signing key version found" >&2; exit 3; }
if [[ "$VERSION" == projects/* ]]; then
  KEY_VERSION="$VERSION"
else
  KEY_VERSION="projects/$PROJECT_ID/locations/$REGION/keyRings/$KEYRING/cryptoKeys/$KEY/cryptoKeyVersions/$VERSION"
fi
printf '%s\n' "$KEY_VERSION"
