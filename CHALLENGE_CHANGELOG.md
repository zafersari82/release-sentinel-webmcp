# WebMCP Challenge Changelog

This file summarizes work presented as challenge-period WebMCP contribution in the public Release Sentinel repository. Release Sentinel predates the WebMCP Challenge; the pre-challenge foundation is explicitly separated below and documented with evidence paths in `CHALLENGE_PROVENANCE.md`.

Development checkpoint SHA-256: `634c8fbfb9697169cdb76fe4b3c5f52cf5295b039b22a29dec02da8a3af3c967`

## WebMCP capability plane

- Added an exact, typed inventory of 12 WebMCP tools split into `READ`, `CHALLENGE`, and `PROPOSE` capability classes.
- Added strict Pydantic input contracts with extra-field rejection and bounded challenge/revision/attack enums.
- Added explicit forbidden-capability tests: no verdict setter, Gatekeeper override, policy disable, signed-evidence editor, generic execute endpoint, shell, or arbitrary filesystem capability.
- Added browser registration through `document.modelContext.registerTool()` when supported.
- Added an explicit `UNAVAILABLE` state when WebMCP is absent; the page never pretends registration succeeded.
- Added `run_attack_suite`, an agent-native browser-side composition that executes the bounded attack catalog through the existing `run_attack` path and derives containment, authority-gain, and agent-influence metrics without creating a new backend authority surface.

## Typed challenge service and API

- Added `release_sentinel.webmcp` service adapters over the release, Coverage Arena, minimizer, remediation, rebuild, and Gatekeeper foundation.
- Added `/v1/webmcp/*` typed endpoints through a dedicated FastAPI router.
- Added bounded package-owned counterexample selection and minimization; caller-supplied source is not accepted.
- Added a strict package-owned remediation registry with exactly three challenge-facing scenarios: `demo-cross-tenant`, `demo-path-traversal`, and `demo-evidence-tamper`.
- Added distinct vulnerable/fixed fixture pairs for all three remediation scenarios; callers cannot supply arbitrary fixture paths, source, shell, or filesystem inputs.
- Added a server-owned remediation state machine:
  `NO_GO -> PROPOSAL_ONLY -> NEW SOURCE HASH -> NOT_YET_REVERIFIED -> FRESH REVERIFICATION -> GO|NO_GO`.
- Added digest/context mismatch rejection for proposal/rebuild/reverify transitions.
- Added judged-mode fail-closed support for remote deterministic Go Gatekeeper re-verification.
- Added self-guiding `next_action` errors so an agent can recover from invalid identifiers without inventing authority-bearing state.
- Flattened local JSON Schema references so agent-facing tool schemas expose bounded enum choices without `$ref` / `$defs` leakage.

## Proof Arena web experience

- Added `/arena` as a judge-focused WebMCP Proof Arena.
- Added a visual authority chain showing `AI Agent: NO RELEASE AUTHORITY` and `Gatekeeper: FINAL AUTHORITY`.
- Added interactive attack controls, Coverage Arena Rev1/Rev2/Rev3 comparison, scoped zero-escape warning, counterexample/minimizer view, bounded remediation hash transition, proof verification, and a browser-local agent action timeline.
- Added explicit human-control fallback when WebMCP is unavailable.
- Reframed the Arena hero around `CAPABILITY WITHOUT AUTHORITY` rather than implementation provenance.
- Added the Human Proof Checkpoint after the agent timeline: after fresh re-verification, a human can independently check proof integrity, context binding, rebuilt-source identity, and deterministic proof authority. This checkpoint never sets or overrides a release verdict.

## Dependency and execution hardening

- Removed the ambiguous PyPI `agentseal` dev dependency and made local development install the repository-owned `packages/agentseal` package explicitly.
- Added CI coverage for the local AgentSeal install path so dependency confusion cannot silently regress.
- Added native Chrome WebMCP execution coverage in addition to the Playwright browser harness.

## Challenge tests and public-repo assets

- Added contract, service, API, schema, packaging, browser, native-Chrome, and security regression tests for the WebMCP surface.
- Added `CHALLENGE_PROVENANCE.md`, this changelog, `docs/WEBMCP_CHALLENGE.md`, and a root MIT license.
- Added a challenge Proof Arena screenshot under `artifacts/`.
- Added `Dockerfile.webmcp` + `deploy/webmcp-entrypoint.sh` for a single public service that still runs the deterministic Go Gatekeeper as a separate localhost process with an ephemeral signing key.
- Added a declared browser-test extra and submission-packaging contract tests so the public repository does not depend on undeclared Playwright tooling or stale bundle artifacts.
- Added a Render Blueprint (`render.yaml`) that explicitly deploys `Dockerfile.webmcp`, waits on the WebMCP tool-catalog health endpoint, and auto-deploys only after repository checks pass.

## Pre-challenge foundation — not claimed as challenge-period work

Repository-retained artifacts dated 2026-08-20, 2026-08-21, and 2026-08-22 establish that Release Sentinel existed before the WebMCP Challenge. The pre-challenge foundation includes the deterministic release decision boundary and Go Gatekeeper integration, signed-evidence/verdict-independence controls, advisory-agent separation, tamper/replay behavior, Coverage Arena and reference-oracle/benchmark work, security challenge infrastructure, bounded remediation/rebuild primitives, and the original release-control experience.

These capabilities are inputs to the challenge submission, not challenge-period creation claims. See `CHALLENGE_PROVENANCE.md` for the exact evidence paths and lineage statement.
