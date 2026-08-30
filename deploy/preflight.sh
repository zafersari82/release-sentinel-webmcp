#!/usr/bin/env bash
set -euo pipefail
: "${PROJECT_ID:?set PROJECT_ID}"
: "${REGION:=us-central1}"
for bin in gcloud curl python3 openssl; do
  command -v "$bin" >/dev/null || { echo "PREFLIGHT FAIL: $bin is required" >&2; exit 2; }
done
ACCOUNT="$(gcloud auth list --filter=status:ACTIVE --format='value(account)' | head -n1)"
[[ -n "$ACCOUNT" ]] || { echo "PREFLIGHT FAIL: no active gcloud account" >&2; exit 2; }
PROJECT_NUMBER="$(gcloud projects describe "$PROJECT_ID" --format='value(projectNumber)')"
[[ -n "$PROJECT_NUMBER" ]] || { echo "PREFLIGHT FAIL: project not visible: $PROJECT_ID" >&2; exit 2; }

BILLING_ENABLED="$(gcloud billing projects describe "$PROJECT_ID" --format='value(billingEnabled)' 2>/dev/null || true)"
if [[ "$BILLING_ENABLED" != "True" && "$BILLING_ENABLED" != "true" ]]; then
  echo "PREFLIGHT FAIL: billing is not enabled or cannot be verified for project=$PROJECT_ID" >&2
  exit 2
fi

# Test effective project permissions instead of guessing from role names. This
# catches direct, group, folder, and organization-level grants alike.
PROJECT_PERMS=(
  resourcemanager.projects.setIamPolicy
  serviceusage.services.enable
  iam.serviceAccounts.create
  datastore.databases.create
  cloudtrace.traces.get
)
PERM_JSON="$(python3 - "${PROJECT_PERMS[@]}" <<'PY'
import json,sys
print(json.dumps({"permissions": sys.argv[1:]}))
PY
)"
TOKEN="$(gcloud auth print-access-token)"
RESP="$(curl -fsS -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d "$PERM_JSON" \
  "https://cloudresourcemanager.googleapis.com/v3/projects/$PROJECT_NUMBER:testIamPermissions")"
MISSING="$(python3 - "$RESP" "${PROJECT_PERMS[@]}" <<'PY'
import json,sys
have=set(json.loads(sys.argv[1]).get("permissions", []))
want=sys.argv[2:]
print("\n".join(p for p in want if p not in have))
PY
)"
if [[ -n "$MISSING" ]]; then
  echo "PREFLIGHT FAIL: active principal lacks required effective project permissions:" >&2
  while IFS= read -r p; do [[ -n "$p" ]] && echo "  - $p" >&2; done <<< "$MISSING"
  cat >&2 <<'HINTS'
Suggested role mapping (or equivalent custom permissions):
  resourcemanager.projects.setIamPolicy -> roles/resourcemanager.projectIamAdmin
  serviceusage.services.enable          -> roles/serviceusage.serviceUsageAdmin
  iam.serviceAccounts.create            -> roles/iam.serviceAccountCreator (Service Account Admin is also sufficient)
  datastore.databases.create            -> roles/datastore.owner
  cloudtrace.traces.get                  -> roles/cloudtrace.user
Cloud KMS key creation later requires roles/cloudkms.admin (or equivalent key-create permissions).
Managing IAM on the newly-created service accounts requires iam.serviceAccounts.setIamPolicy, normally roles/iam.serviceAccountAdmin or Owner.
Cloud Run source deployment also requires the deployer permissions documented by Google; this repo grants roles/run.builder only to the dedicated build identity.
HINTS
  exit 3
fi

echo "PREFLIGHT PASS project=$PROJECT_ID project_number=$PROJECT_NUMBER region=$REGION account=$ACCOUNT billing=enabled iam=ready"
