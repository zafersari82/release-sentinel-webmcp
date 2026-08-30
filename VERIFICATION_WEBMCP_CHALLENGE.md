# WebMCP Challenge Verification

This document records reproducible verification for the public WebMCP submission. Release Sentinel predates the WebMCP Challenge; `CHALLENGE_PROVENANCE.md` separates the pre-challenge foundation from challenge-period WebMCP work. GitHub Actions is the authoritative execution record for current repository commits.

## Provenance anchor

Development checkpoint SHA-256:

```text
634c8fbfb9697169cdb76fe4b3c5f52cf5295b039b22a29dec02da8a3af3c967
```

The checkpoint artifact entered this workspace without `.git`. Repository-retained evidence dated 2026-08-20, 2026-08-21, and 2026-08-22 is documented in `CHALLENGE_PROVENANCE.md`; repository commit history is not fabricated or backdated.

## Current WebMCP contract

The application exposes exactly 12 bounded tools:

```text
inspect_release
inspect_trust_boundary
run_attack
run_attack_suite
inspect_coverage
compare_gate_revisions
find_counterexamples
minimize_counterexample
propose_remediation
rebuild_candidate
reverify_candidate
verify_proof
```

`run_attack_suite` is browser-side composition over the existing `run_attack` capability. It does not add a generic execute endpoint or a new backend authority path.

There is no WebMCP verdict setter, Gatekeeper override, policy disable, signed-evidence editor, arbitrary shell, arbitrary filesystem capability, or caller-supplied source execution path.

The remediation surface accepts exactly three package-owned demo identities:

```text
demo-cross-tenant
demo-path-traversal
demo-evidence-tamper
```

Each maps to a distinct package-owned vulnerable/fixed fixture pair. Rebuilds produce a new source hash, inherit no verdict, and require fresh verification.

## Human Proof Checkpoint

After a rebuilt candidate receives fresh deterministic re-verification, the Arena exposes a separate human proof check. The human invokes the existing `verify_proof` capability and requires all of the following before the UI can show `VERIFIED BY HUMAN`:

- proof source SHA-256 equals the rebuilt candidate source SHA-256;
- proof source SHA-256 equals the fresh re-verification source SHA-256;
- evidence integrity is verified;
- the proof is context-bound;
- proof authority is deterministic.

The checkpoint never sets or overrides a release verdict. The original release can remain `NO_GO` while a separately rebuilt candidate earns fresh `GO` proof.

## Verified implementation checkpoint

Implementation SHA verified before this documentation-only update:

```text
db642fa58ff657e79baef25f9da308b0c00b8e2c
```

### `trust-gates`

GitHub Actions run: `33305095569`

All six jobs completed successfully:

- Python suite + trust kernel
- AgentSeal library
- Go Gatekeeper
- WebMCP submission container
- Shell + arena isolation contract
- Arena confinement (real container)

Observed results:

- full Python suite: **294 passed**;
- trust-boundary guard subset: **72 passed**, with no skipped guard tests;
- frozen trust kernel: `OK: trust kernel matches freeze manifest`;
- Go `vet`, race tests, and build: successful;
- real-container arena confinement checks: successful;
- judge Docker container build and signed-evidence remediation smoke: successful;
- browser acceptance: successful.

Browser acceptance reported:

```text
registeredTools: 12
webmcpStatus: REGISTERED
current release verdict: NO_GO
humanProofStatus: VERIFIED BY HUMAN
timelineEvents: 8
revisionCards: 3
horizontal overflow: none at 1440px
```

The successful human proof detail was bound to `demo-cross-tenant-fixed`, the rebuilt source, sealed evidence, bound proof context, and deterministic proof authority. A deliberately mismatched proof source was also exercised and failed closed.

### Native Chrome WebMCP

GitHub Actions run: `33305093926`

Native Chrome version: `151.0.7922.173`.

The browser exposed `document.modelContext` and `executeTool`; exactly 12 tools were registered in the same window. Native execution proved:

- `inspect_release` returned `NO_GO` with deterministic authority and `NO_RELEASE_AUTHORITY` for WebMCP;
- `run_attack(force_agents_go)` was blocked, retained `NO_GO`, ignored 4/4 advisory `GO` opinions, and reported agent influence `0`;
- `run_attack_suite` executed all 8 bounded attacks;
- `contained_count = 8`;
- `all_contained = true`;
- `unexpected_authority_gains = 0`;
- `max_agent_influence = 0`;
- suite authority remained `DETERMINISTIC_GO_GATEKEEPER`;
- WebMCP authority remained `NO_RELEASE_AUTHORITY`.

## Verification commands

Python and architecture:

```bash
PYTHONPATH=src:packages/agentseal/src pytest -q --strict-markers
./scripts/check-trust-kernel.sh
./scripts/check-coverage-kernel.sh
```

Go Gatekeeper:

```bash
cd gatekeeper
go vet ./...
go test -race ./...
go build -trimpath ./...
```

Browser acceptance:

```bash
pip install -e '.[browser]'
playwright install chromium
python tests/browser_webmcp_acceptance.py
```

The GitHub `WebMCP submission container` job additionally builds `Dockerfile.webmcp`, runs the signed-evidence attack/remediation flow against the separate localhost Go Gatekeeper, and runs the browser acceptance harness. The separate Native Chrome workflow executes registered tools through `document.modelContext`, not only through HTTP adapters.

## Required invariants

A checkpoint is not considered verified unless all of the following hold:

- WebMCP tool inventory and browser registration agree.
- No trust/coverage freeze guard silently skips.
- Agent opinions have zero release-decision authority.
- Proposal and rebuild transitions cannot inherit a previous verdict.
- Fresh re-verification is source-hash bound.
- Human proof verification cannot convert a mismatch into approval.
- Human proof verification requires deterministic proof authority.
- Missing Gatekeeper dependencies fail closed in judged mode.
- `0 observed escapes` remains scoped to the named fixed benchmark corpus and is never represented as universal security.

This file update is documentation-only. Its resulting branch HEAD must independently pass both `trust-gates` and `webmcp-native` before merge; the implementation evidence above remains tied to the exact SHA and run IDs recorded here.
