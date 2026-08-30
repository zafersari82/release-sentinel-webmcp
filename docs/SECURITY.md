# Security model

## Root of trust

The trust root is not a model response, registry row, telemetry backend, memory document, or caller-supplied `authority` string. It is externally pinned organization policy, trusted sandbox execution owned by the Evidence Attestor, the dedicated evidence-signing KMS key, and independent verification by the Go Gatekeeper.

## Service identities

- **Runtime:** ADK/Gemini access, ledger access, and explicit Cloud Run invoker access to private services. No evidence-signing permission.
- **Evidence Attestor:** read-only policy access + evidence KMS signer. No model role in the attestation flow.
- **Go Gatekeeper:** Cloud Run service identity, trace-write/service-usage permission for its local collector, and no Vertex/Gemini role, no ledger role, no KMS-signing role.
- **Build identity:** source-build permissions only.

The production Gatekeeper URL is not caller-arbitrary. The Python client accepts local loopback HTTP only for development; production must be an HTTPS `*.run.app` service origin with an exact matching identity-token audience.

## Evidence lifecycle seal

The evidence trust boundary starts before signing. `Evidence`, `Finding`, `ReleaseReport`, `EvidenceBundle`, and `SignedEvidenceBundle` expose no mutable path back to authoritative bytes. `ReleaseReport.evidence_sha256` binds the evaluated evidence set to the later attestation step, which recomputes the seal and raises `EvidenceIntegrityError` instead of signing if the report has changed. This protects against both advisory mutation and mutation introduced by embedding code between evaluation and signing.

## Agent authority

The registry distinguishes `ADVISORY` and `DETERMINISTIC`. Only trusted bootstrap configuration contains the deterministic Gatekeeper record. Runtime self-registration is advisory-only and malformed/unknown authority values are rejected.

Agent payloads retain `authority=NONE` for backward-compatible decision semantics; the registry separately classifies those agents as `decision_authority=ADVISORY`.

## Telemetry safety

Trace business attributes are allow-listed and bounded. Prompts, model responses, repository contents, authorization headers, identity tokens, raw evidence payloads, credentials, secrets, and PII are never intentional span attributes. Telemetry setup/export failure is outside the release decision path.

## Persistent memory safety

Release history reuses the Firestore report ledger. Dissent receives only bounded safe summaries: release/report identity, decision, policy revision, execution count, time, and limited finding metadata. Evidence bodies and provenance are excluded. A memory failure becomes `UNAVAILABLE` advisory context and does not alter Gatekeeper execution.


## Public challenge plane

`challenge/` and `release_sentinel.public_challenge` are deliberately outside
the trust kernel. A compromise of the public worker, scoreboard, UI, or attacker
process is not allowed to grant access to policy storage, evidence-signing keys,
provenance keys, production credentials, or Gatekeeper decision authority.

The Code Arena executes contestant `attack.py` in a separate container with no
network, read-only root filesystem, all Linux capabilities dropped,
`no-new-privileges`, PID/memory/CPU/file-descriptor limits, a ten-second wall
clock, and only a copied regular `attack.py` mounted read-only. The contestant
receives a redacted JSON snapshot and returns JSON. The authoritative process
never imports contestant code.

This container profile is defense-in-depth for local/community testing, not a
claim that containers are a complete hostile-code boundary. Public internet
execution must add disposable VM/microVM isolation and remain secret-free.

The verifier distinguishes **agent compromise** from **authority compromise**.
Forged `GO`, policy, waiver, memory, and authority fields may demonstrate a
compromised application plane; they count as a break only if trusted evidence
bytes or the deterministic verdict move under fixed ground truth.

## Attack the Gate

The Control Center exposes six fixed safe resilience scenarios; it does not expose an arbitrary attack-payload editor. Expected outcomes remain:

| Scenario | Expected result |
|---|---|
| Force agents 4/4 GO | signed evidence accepted; verdict remains NO_GO |
| HIGH → INFO | DIGEST_MISMATCH |
| Delete blocker | DIGEST_MISMATCH |
| Tamper evidence digest | DIGEST_MISMATCH |
| Add forged authority field | ignored; verdict unchanged |
| Replay old GO into current release/source | CONTEXT_MISMATCH |

## Key separation

Evidence attestation and final provenance use different KMS keys. Possessing provenance-signing authority does not confer evidence-signing authority.
