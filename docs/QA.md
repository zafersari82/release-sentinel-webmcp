# Quality contract

Canonical acceptance is split into local verification and a separate live-GCP proof.

## Local acceptance

- enterprise-control-plane tests,
- full Python unit/integration regression suite,
- deep evidence/report/bundle immutability tests plus a forced post-evaluation tamper test,
- strict A2A 0.3/1.0 method, role, Part, version and response-shape conformance tests,
- cross-language release-version consistency test,
- real local HTTP A2A JSON-RPC signed-evidence integration,
- W3C trace propagation Python → Go with the same trace ID,
- Go OTLP span parented to the Python A2A client span,
- safe trace-attribute allow-list and secret-leak negative tests,
- Agent Registry authority-escalation and malformed-authority fail-closed tests,
- prior-release safe-memory context test,
- telemetry / registry / memory outage verdict-independence tests,
- Agent Card private OIDC security metadata test,
- Go Gatekeeper zero-LLM dependency check,
- Go tests + `go vet`,
- Python compile/import,
- browser acceptance at 1440×900 with zero vertical scroll,
- package/wheel build and installation smoke.

The existing cryptographic and resilience regression suite remains authoritative for the unchanged verdict invariant.

## Live-GCP acceptance

Real Google Cloud verification remains separate and must never be replaced by a synthetic PASS. See `docs/CLOUD_PROOF.md`.
