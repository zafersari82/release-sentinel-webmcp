# Live Google Cloud proof contract

A repository or HTTP endpoint is **not** live-GCP verified merely because it builds or returns HTTP 200. `deploy/cloud-proof.sh` is intentionally strict and is the only automated live-proof contract in this repository.

## Required deployment

1. Dedicated source-build service account.
2. Python orchestrator as a private Cloud Run service.
3. Evidence Attestor as a separate private Cloud Run service with real Cloud Run Sandbox execution.
4. Go Gatekeeper as a separate private Cloud Run service with no LLM dependency.
5. Runtime → Gatekeeper service-to-service IAM using a Google-signed ID token with audience equal to the Gatekeeper service URL.
6. Named read-only Firestore policy database plus the existing Firestore release-report ledger.
7. Dedicated evidence-signing KMS P-256 key usable only by the Attestor.
8. Separate provenance-signing KMS key.
9. Google-built OpenTelemetry Collector sidecar on the Python runtime and Gatekeeper, receiving local OTLP and exporting traces to `telemetry.googleapis.com`.
10. Gatekeeper configured only with the evidence public key + expected key-version ID; it receives no Vertex/Gemini model permission.
11. Cloud Run deployment region and Vertex model location are separate: `REGION` defaults to `us-central1`, while `VERTEX_LOCATION` defaults to `global` for the Gemini runtime.

`deploy/otel-sidecar.sh` follows the Cloud Run sidecar model and mounts `deploy/otel-collector-config.yaml` from a service-specific Secret Manager secret. The application sends OTLP to `localhost:4318`; the collector authenticates to the Google Telemetry API using the Cloud Run service identity.

## Mandatory proof sequence

The live proof invokes the same release context twice:

```text
VULNERABLE
repository → real Sandbox → blocking machine evidence → KMS signed evidence
→ private A2A Gatekeeper → NO_GO → Firestore report

FIXED
repository → real Sandbox → clean machine evidence → KMS signed evidence
→ private A2A Gatekeeper → GO → Firestore report
```

The second run must read at least one bounded prior-release summary from the first run and provide that safe history to the dissent reviewer. Raw evidence bodies and provenance are not model memory.

## Mandatory assertions

The proof fails unless all of the following are real:

- ADK → Gemini model turn,
- exact policy revision and external SHA-256 pin,
- real Cloud Run Sandbox execution,
- evidence bundle signed with the dedicated evidence KMS key,
- private A2A Gatekeeper call and Gatekeeper cryptographic verification,
- vulnerable result `NO_GO`, fixed result `GO`,
- 4/4 forced advisory `GO` still unable to change a blocking verdict,
- Firestore report persistence,
- fixed run observes prior safe release context,
- final provenance signed by the separate KMS key and independently verified,
- a real Cloud Trace record containing `release_verdict_pipeline`, four advisory spans, `gatekeeper.a2a_call`, and `gatekeeper.verdict_decide` under the same trace ID,
- severity-tamper and old-GO replay attacks remain blocked.

The proof uses OpenTelemetry/OTLP for ingestion. The Go Gatekeeper emits OTLP/HTTP JSON with lowercase hex trace/span IDs and numeric enum values, and the local collector is configured to flush one-span batches promptly. The proof uses the supported Cloud Trace read API only to retrieve the resulting trace by ID and prove that the distributed spans actually arrived. Trace reads include `x-goog-user-project: $PROJECT_ID` so quota attribution cannot silently fall back to an unrelated local ADC project.

## Run

```bash
export PROJECT_ID='your-project-id'
export REGION='us-central1'
export VERTEX_LOCATION='global'
./deploy/e2e-cloud.sh
```

Only a successful final `CLOUD TRUST PROOF PASS` from a real Google Cloud project is live verification. Local tests, mocked credentials, bundled fixtures, or an offline executor must not be described as Cloud Run Sandbox proof.


## Retained live proof excerpt

The operator-run proof that drove the v2.2.6 consolidation is retained at
`challenge/verification/GCP_CLOUD_TRUST_PROOF_2026-08-21.txt`. That run was performed on the
patched v2.2.5 working tree; redeploy v2.2.6 from a clean checkout before making an exact
artifact-to-deployment equivalence claim.
