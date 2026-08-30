# Release Sentinel — Enterprise Agent Control Plane

Enterprise fleet capabilities live around, not inside, the deterministic verdict kernel:

- runtime Agent Registry with 4 advisory + 1 deterministic records,
- `GET /v1/agents` and Judge View registry table,
- W3C distributed trace across Python advisory spans, A2A client, and Go Gatekeeper,
- OpenTelemetry/OTLP export contract for Google-built Collector → Google Telemetry API,
- bounded cross-session release memory from the existing Firestore ledger,
- private Cloud Run identity/audience validation,
- Agent Card OIDC/IAM deployment metadata,
- Control Center Judge View and six predefined resilience scenarios,
- cloud-proof assertions for real trace retrieval, persistent memory, Sandbox, KMS, Firestore, private A2A, and ADK/Gemini.

The deterministic verdict package remains independent from model runtimes. The Go HTTP adapter exposes version-correct 0.3 `message/send` and 1.0 `SendMessage` bindings without changing verdict authority.
