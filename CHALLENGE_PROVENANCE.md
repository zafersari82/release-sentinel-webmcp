# Challenge Provenance

Release Sentinel predates the WebMCP Challenge. This submission does not claim the pre-challenge release-security foundation as challenge-period work.

Repository-retained verification artifacts establish that Release Sentinel was already being exercised before the challenge window:

- `challenge/verification/ARENA_CONFINEMENT_WINDOWS_WSL_2026-08-20.txt` records a user-run arena-confinement session captured on **2026-08-20**.
- `challenge/verification/GCP_CLOUD_TRUST_PROOF_2026-08-21.txt` records a user-run Google Cloud trust proof dated **2026-08-21**, including signed evidence, tamper/replay blocking, the deterministic Gatekeeper path, and zero agent influence in that run.
- `challenge/verification/COVERAGE_ARENA_REFERENCE_PROOF_2026-08-22.json` retains the pre-challenge Coverage Arena reference measurement artifact.

These files are evidence retained in the repository; they are not reconstructed Git history. No historical commits are fabricated or backdated.

## Checkpoint anchor

A development checkpoint used in the lineage is identified as:

`Release Sentinel v2.3.0 Coverage Arena Multi-Challenge Checkpoint`

SHA-256:

```text
634c8fbfb9697169cdb76fe4b3c5f52cf5295b039b22a29dec02da8a3af3c967
```

The checkpoint was supplied to this workspace as a ZIP without a `.git` directory. Its SHA-256 is retained as an artifact-level lineage anchor. Public Git history records the reviewable commits made after the public repository was created.

## Pre-challenge foundation — not claimed as challenge-period work

The retained checkpoint/evidence establish a foundation that includes, among other things:

- the deterministic release decision boundary and Go Gatekeeper integration;
- signed/hash-bound evidence and verdict-independence controls;
- advisory-agent separation and zero-authority decision semantics;
- tamper/replay challenge behavior;
- Coverage Arena measurement infrastructure, qualified reference-oracle work, and benchmark artifacts;
- cross-tenant and path-traversal security challenge work;
- bounded remediation/rebuild primitives and the original release-control experience.

Those capabilities strengthen the submission, but they are not represented here as work first created during the WebMCP Challenge.

## Challenge-period WebMCP contribution

Challenge-period WebMCP work was carried out during the official Submission Period. The public challenge repository was created on **August 29, 2026**, and its public implementation history is dated within the Submission Period.

The public challenge work turns that foundation into an agent-operable, browser-native workflow while preserving the authority boundary. Challenge-facing commits add and harden:

- the typed 12-tool WebMCP capability plane with `READ`, `CHALLENGE`, and `PROPOSE` classes;
- browser-native `document.modelContext.registerTool()` registration and native-Chrome acceptance;
- strict, self-contained agent-facing schemas and self-guiding `next_action` failures;
- the agent-native `run_attack_suite` browser composition;
- `/v1/webmcp/*` adapters that expose bounded capabilities without a generic execute surface;
- the WebMCP Proof Arena and its explicit `CAPABILITY WITHOUT AUTHORITY` interaction model;
- three allowlisted, package-owned remediation scenarios with distinct vulnerable/fixed fixture pairs;
- proposal → new source hash → fresh deterministic re-verification with no inherited verdict;
- the Human Proof Checkpoint: agent acts, Gatekeeper decides, human independently verifies proof;
- WebMCP-specific browser, native-Chrome, CI, Docker, and Render deployment verification.

`CHALLENGE_CHANGELOG.md` summarizes these challenge-facing additions. The public commit history is the authoritative record for their implementation sequence.

## Authority statement

Provenance never grants authority. WebMCP remains non-authoritative regardless of whether a capability is old or new: agents may inspect, challenge, measure, and propose, but only the deterministic Gatekeeper can issue a release verdict. Human proof verification checks evidence; it does not approve a release.
