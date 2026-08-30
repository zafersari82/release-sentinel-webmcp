#!/usr/bin/env bash
set -euo pipefail
: "${PROJECT_ID:?set PROJECT_ID}"
: "${REGION:=us-central1}"
: "${SERVICE_NAME:?set SERVICE_NAME}"
: "${SERVICE_ACCOUNT:?set SERVICE_ACCOUNT}"
CONFIG_FILE="${OTEL_CONFIG_FILE:-deploy/otel-collector-config.yaml}"
SECRET_NAME="${OTEL_SECRET_NAME:-${SERVICE_NAME}-otel-config}"
COLLECTOR_IMAGE="${OTEL_COLLECTOR_IMAGE:-us-docker.pkg.dev/cloud-ops-agents-artifacts/google-cloud-opentelemetry-collector/otelcol-google:0.156.0}"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

if gcloud secrets describe "$SECRET_NAME" --project "$PROJECT_ID" >/dev/null 2>&1; then
  gcloud secrets versions add "$SECRET_NAME" --project "$PROJECT_ID" --data-file="$CONFIG_FILE" >/dev/null
else
  gcloud secrets create "$SECRET_NAME" --project "$PROJECT_ID" --data-file="$CONFIG_FILE" >/dev/null
fi
gcloud secrets add-iam-policy-binding "$SECRET_NAME" --project "$PROJECT_ID" \
  --member="serviceAccount:$SERVICE_ACCOUNT" --role="roles/secretmanager.secretAccessor" --quiet >/dev/null

gcloud run services describe "$SERVICE_NAME" --project "$PROJECT_ID" --region "$REGION" --format=export > "$TMP/service.yaml"
python3 - "$TMP/service.yaml" "$SECRET_NAME" "$PROJECT_ID" "$COLLECTOR_IMAGE" <<'PY'
import sys, yaml
path, secret_name, project_id, collector_image = sys.argv[1:]
with open(path, encoding='utf-8') as f:
    doc = yaml.safe_load(f)
template = doc.setdefault('spec', {}).setdefault('template', {})
meta = template.setdefault('metadata', {})
annotations = meta.setdefault('annotations', {})
annotations['run.googleapis.com/container-dependencies'] = '{"app":["collector"]}'
annotations['run.googleapis.com/secrets'] = f'{secret_name}:projects/{project_id}/secrets/{secret_name}'
spec = template.setdefault('spec', {})
containers = spec.setdefault('containers', [])
if not containers:
    raise SystemExit('Cloud Run service has no ingress container')
app = containers[0]
app['name'] = 'app'
env = app.setdefault('env', [])
env = [item for item in env if item.get('name') not in {'OTEL_EXPORTER_OTLP_ENDPOINT','OTEL_SERVICE_NAME'}]
env.extend([
    {'name':'OTEL_EXPORTER_OTLP_ENDPOINT','value':'http://localhost:4318'},
    {'name':'OTEL_SERVICE_NAME','value':doc.get('metadata',{}).get('name','release-sentinel')},
])
app['env'] = env
collector = {
    'name':'collector',
    'image':collector_image,
    'args':['--config=/etc/otelcol-google/config.yaml'],
    'env':[{'name':'GOOGLE_CLOUD_PROJECT','value':project_id}],
    'startupProbe':{'httpGet':{'path':'/','port':13133},'timeoutSeconds':30,'periodSeconds':30},
    'livenessProbe':{'httpGet':{'path':'/','port':13133},'timeoutSeconds':30,'periodSeconds':30},
    'volumeMounts':[{'mountPath':'/etc/otelcol-google/','name':'otel-config'}],
}
spec['containers'] = [app, collector]
spec['volumes'] = [v for v in spec.get('volumes', []) if v.get('name') != 'otel-config'] + [
    {'name':'otel-config','secret':{'items':[{'key':'latest','path':'config.yaml'}],'secretName':secret_name}}
]
# Exported service status is not accepted by replace; format=export normally omits it,
# but remove defensively without altering IAM policy.
doc.pop('status', None)
with open(path, 'w', encoding='utf-8') as f:
    yaml.safe_dump(doc, f, sort_keys=False)
PY

gcloud run services replace "$TMP/service.yaml" --project "$PROJECT_ID" --region "$REGION" --quiet >/dev/null
echo "OTEL SIDECAR READY service=$SERVICE_NAME collector=$COLLECTOR_IMAGE endpoint=http://localhost:4318"
