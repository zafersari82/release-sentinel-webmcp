#!/usr/bin/env bash
set -euo pipefail

command -v gcloud >/dev/null || { echo "Run this script in Google Cloud Shell (gcloud missing)." >&2; exit 2; }
PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project 2>/dev/null || true)}"
REGION="${REGION:-us-central1}"
[[ -n "$PROJECT_ID" && "$PROJECT_ID" != "(unset)" ]] || {
  echo "No Google Cloud project selected. In Cloud Shell run: gcloud config set project YOUR_PROJECT_ID" >&2
  exit 2
}
export PROJECT_ID REGION

ACCOUNT="$(gcloud auth list --filter=status:ACTIVE --format='value(account)' | head -n1)"
[[ -n "$ACCOUNT" ]] || { echo "No active gcloud account in Cloud Shell." >&2; exit 2; }

VENV="${RELEASE_SENTINEL_CLOUD_VENV:-.cloud-venv}"
python3 -m venv "$VENV"
CURRENT_DIR="$(pwd)"
export PATH="$CURRENT_DIR/$VENV/bin:$PATH"
python -m pip install -q --upgrade pip setuptools wheel

echo "Release Sentinel Cloud Proof"
echo "project=$PROJECT_ID region=$REGION account=$ACCOUNT"
./deploy/e2e-cloud.sh
