# Architecture — Release Sentinel

Release Sentinel separates the **application/control plane** from the **deterministic trust plane**. Registry, telemetry, memory, and LLM agents can enrich operation and review, but none are prerequisites for the final verdict.

## Control plane

The Python service owns the Control Center, Agent Registry, advisory ADK workflow, Firestore release-history projection, cloud-proof coordination, and OpenTelemetry client/root spans. Four registered agents are advisory: `security_reviewer`, `test_reviewer`, `dissent_reviewer`, and `evidence_explainer`.

The runtime registry contains five trusted bootstrap records. Runtime self-registration is advisory-only; unknown or malformed `decision_authority` values are rejected and cannot acquire deterministic authority.

## Persistent release memory

The existing Firestore `release_reports` ledger is reused. Each report receives a sortable `history_key`; `recent_for_release(release_id, limit=5)` returns only a bounded safe summary. Raw evidence bodies, provenance signatures, repository contents, credentials, and tokens are not part of the model context. If the memory query fails, the advisory layer receives no history and the Gatekeeper still runs.

## Distributed trace

One trace is propagated across the release-verdict path:

```text
release_verdict_pipeline
  ├─ advisory.security_reviewer
  ├─ advisory.test_reviewer
  ├─ advisory.dissent_reviewer
  ├─ advisory.evidence_explainer
  └─ gatekeeper.a2a_call
       ──W3C traceparent/tracestate──>
          gatekeeper.verdict_decide
```

Python uses OpenTelemetry SDK + OTLP/HTTP. The Go Gatekeeper preserves the W3C trace context and emits a bounded OTLP/HTTP server span without adding an LLM/model dependency. Export errors are swallowed outside the decision path.

Only these business attributes may be attached: `component`, `agent_id`, `agent_role`, `decision_authority`, `evidence_authority`, `verdict`, `agent_influence`, `llm_present`.

## Deterministic trust plane

1. An organization policy revision is stored outside the reviewed repository and externally SHA-256 pinned.
2. A dedicated Evidence Attestor retrieves that policy read-only and executes its checker inside Cloud Run Sandbox.
3. The Attestor canonicalizes the result into `release-sentinel.evidence-bundle.v1` and signs the bundle with a purpose-specific Cloud KMS asymmetric P-256 key.
4. The Python service sends the signed bundle plus non-authoritative agent opinions to the private Go Gatekeeper over A2A JSON-RPC `message/send`.
5. Before computing any verdict, the Gatekeeper verifies key ID, ECDSA signature, canonical bundle digest, release ID, source SHA-256, policy SHA-256, and freshness window.
6. Only fields inside the verified bundle can contribute blocking semantics. Caller-supplied `authority` labels have no decision meaning.
7. The Gatekeeper ignores agent opinions by design and returns GO / CONDITIONAL_GO / NO_GO.

## Evidence lifecycle integrity

Authoritative findings are deeply immutable after collection: finding sequences are tuples, evidence metadata is recursively frozen, and the release report records a canonical `evidence_sha256` seal. Advisory code receives only a redacted scalar projection, never domain evidence objects. Before attestation, `build_evidence_bundle()` recomputes the evidence-set seal and fails closed on any mismatch. This closes the entire collection → advisory → report → attestation handoff, not only the final cryptographic verification step.

## Verdict-independence invariant

```text
policy + verified evidence
        ↓
deterministic Go Gatekeeper
        ↓
verdict

registry / telemetry / memory / agents = non-authoritative surroundings
```

For a fixed verified evidence bundle, changing all advisory opinions to `GO`, or losing registry, memory, or telemetry, cannot remove a blocker or change the deterministic verdict.

## Identity boundary

Production uses separate service identities. The Python runtime has only the permissions needed for its model/ledger work and Cloud Run invocation. The Gatekeeper service account has no Vertex/Gemini model role, no evidence-signing permission, and no application-ledger permission. Cloud Run IAM requires a Google-signed identity token for service-to-service invocation.

## Replay and tamper boundaries

Evidence is bound to release ID, source SHA-256, policy SHA-256, execution ID, nonce, and a short validity interval. Mutating severity, deleting findings, changing evidence digests, or replaying a valid bundle into another release/source context cannot create an authoritative verdict. The verifier intentionally permits the same valid bundle to be queried repeatedly within that TTL; replay resistance is scoped to context substitution rather than one-shot nonce consumption.
