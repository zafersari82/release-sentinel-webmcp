# Release Sentinel WebMCP Proof Arena

Release Sentinel gives an AI agent useful security capabilities while withholding release authority.

> **The agent couldn't change the proof, so it had to change the software.**

## Provenance

Release Sentinel predates the WebMCP Challenge. Repository-retained verification artifacts show active Release Sentinel work on 2026-08-20 and 2026-08-21, with a Coverage Arena reference artifact retained for 2026-08-22. The pre-challenge trust, deterministic Gatekeeper, signed-evidence, Coverage Arena, and related foundation is not claimed as challenge-period work.

The source lineage includes a reproducible development checkpoint identified by SHA-256:

`634c8fbfb9697169cdb76fe4b3c5f52cf5295b039b22a29dec02da8a3af3c967`

The checkpoint artifact entered this workspace without `.git`; its hash is retained as an artifact-level provenance anchor. Public Git history records repository commits and is not backdated or fabricated. See `CHALLENGE_PROVENANCE.md` for the explicit evidence paths and `CHALLENGE_CHANGELOG.md` for challenge-period additions.

## Authority architecture

```text
AI Agent
  │  NO RELEASE AUTHORITY
  ▼
WebMCP capability plane
  │  bounded typed requests
  ▼
Release Sentinel /v1/webmcp API
  │
  ├── Coverage Arena ── measurement only
  ├── Attack scenarios ── challenge only
  └── Bounded remediation ── proposal only
  │
  ▼
Signed/hash-bound proof context
  │
  ▼
Deterministic Gatekeeper
     FINAL RELEASE AUTHORITY
```

WebMCP can inspect, challenge, measure and request bounded state transitions. It cannot set `GO`, override the Gatekeeper, edit signed evidence, disable policy, approve its own remediation, execute arbitrary shell commands, or provide arbitrary source to the minimizer.

## WebMCP tools

The browser exposes exactly 12 typed tools:

| Tool | Capability | Purpose |
| --- | --- | --- |
| `inspect_release` | READ | Read the current demo release, blocker and proof identity. |
| `inspect_trust_boundary` | READ | Read the authority model. |
| `run_attack` | CHALLENGE | Run one predefined Gatekeeper attack scenario. |
| `run_attack_suite` | CHALLENGE | Browser-side agent composition over the bounded attack catalog with derived containment and authority metrics. |
| `inspect_coverage` | READ | Read one fixed challenge/revision measurement. |
| `compare_gate_revisions` | READ | Compare Rev1/Rev2/Rev3 on the same hash-bound corpus. |
| `find_counterexamples` | CHALLENGE | List observed package-owned `ESCAPE` identities. |
| `minimize_counterexample` | CHALLENGE | Minimize one package-owned observed escape. |
| `propose_remediation` | PROPOSE | Create a server-owned proposal with no decision authority. |
| `rebuild_candidate` | PROPOSE | Produce a new hash-bound candidate with no inherited verdict. |
| `reverify_candidate` | PROPOSE | Request fresh deterministic verification of the new source hash. |
| `verify_proof` | READ | Recompute a supported proof/context binding. |

`run_attack_suite` is intentionally not a new backend mega-endpoint: the browser composes the same bounded `run_attack` capability that an agent can call individually.

The browser receives this inventory from `GET /v1/webmcp/tools` and registers it with `document.modelContext.registerTool()` when the supported browser API is present.

## Run locally

For the full judged topology, use the challenge container:

```bash
docker build -f Dockerfile.webmcp -t release-sentinel-webmcp .
docker run --rm -p 8080:8080 release-sentinel-webmcp
```

Open `http://127.0.0.1:8080/arena`. This path runs the Python WebMCP app and the deterministic Go A2A Gatekeeper as separate processes with a fresh ephemeral evidence-signing trust root.

For Python-only development, start the FastAPI app directly:

```bash
pip install -e packages/agentseal -e '.[dev]'
uvicorn release_sentinel.interfaces.api:app --host 127.0.0.1 --port 8000
```

The human Proof Arena works without WebMCP. A browser that does not expose `document.modelContext.registerTool()` shows `UNAVAILABLE` and keeps the human controls active.

For Render, `render.yaml` explicitly selects `Dockerfile.webmcp` and uses `/v1/webmcp/tools` as the health check.

## Judged-mode Gatekeeper

The recommended challenge deployment is `Dockerfile.webmcp`. It builds the Go A2A Gatekeeper and runs it as a separate localhost process beside the public FastAPI application. A fresh P-256 demo evidence key is generated when the container starts; the private key is supplied only to the Python signer and the public key is supplied to the Go verifier. No signing key is committed to the repository.

The entrypoint sets:

```text
RELEASE_SENTINEL_GATEKEEPER_URL=http://127.0.0.1:9090
RELEASE_SENTINEL_WEBMCP_JUDGED_MODE=1
```

In judged mode, missing/unhealthy Gatekeeper configuration fails closed with `GATEKEEPER_DEPENDENCY_UNAVAILABLE`; it does not silently substitute a different authority path. Local Python-only development remains explicitly identified as a reference path.

## Demo sequence

The shortest judge-understandable sequence is:

1. `inspect_release` → current source is `NO_GO`.
2. `inspect_trust_boundary` → AI/WebMCP layers have no release authority.
3. `run_attack_suite` → the agent executes the full bounded attack catalog and derives containment/authority metrics while the Gatekeeper remains final authority.
4. `compare_gate_revisions(cross-tenant)` → Rev1 has 23 observed escapes, Rev2 has 3, Rev3 has 0 on the fixed benchmark corpus.
5. `find_counterexamples` → select a package-owned observed escape.
6. `minimize_counterexample` → produce a bounded verified reproducer.
7. `propose_remediation` → select one of three package-owned demo scenarios; proposal is explicitly `PROPOSAL_ONLY`.
8. `rebuild_candidate` → a new source SHA-256 is produced and the state is `NOT_YET_REVERIFIED`.
9. `reverify_candidate` → fresh evidence/proof is bound to the new source hash; only the deterministic Gatekeeper returns the final verdict.
10. Human Proof Checkpoint → the human invokes the existing `verify_proof` capability and independently requires evidence integrity, context binding, rebuilt-source identity, and deterministic proof authority. The checkpoint does not issue a verdict.

The collaboration model is: `Agent acts → Gatekeeper decides → Human verifies proof`.

## Coverage claim discipline

Coverage Arena is a measurement instrument. In the reference challenges, Rev3 currently reports `0 observed escapes` on its fixed benchmark corpus.
Release Sentinel does **not** convert that observation into a universal-security claim. The Proof Arena displays the exact warning:

> `0 observed escapes is scoped to this fixed benchmark corpus.`

Overblocks remain visible next to escapes so a stricter policy is not misrepresented as cost-free.

## Failure states

- **WebMCP unavailable:** UI shows `UNAVAILABLE`; human controls remain available.
- **Remote Gatekeeper unavailable in judged mode:** authority-sensitive operation fails closed.
- **Coverage runner/oracle failure:** operation fails rather than classifying infrastructure failure as SAFE/UNSAFE.
- **Unknown counterexample:** rejected; caller source text is never used as a substitute.
- **Unknown remediation scenario:** rejected by the strict package-owned allowlist.
- **Wrong proposal digest:** `PROPOSAL_DIGEST_MISMATCH`.
- **Wrong/new source context:** `SOURCE_CONTEXT_MISMATCH`.
- **Unknown candidate/proof:** rejected with a bounded identifier error and self-guiding `next_action` where applicable.
- **Human proof mismatch:** the browser remains `VERIFICATION FAILED`; it cannot convert a mismatch into approval.

## Verification

Challenge-focused checks:

```bash
pytest tests/test_webmcp_contracts.py tests/test_webmcp_service.py tests/test_webmcp_api.py -q
python tests/browser_webmcp_acceptance.py
```

Full regression and kernel freeze checks remain mandatory before a public checkpoint is published. Current observed results are recorded in `VERIFICATION_WEBMCP_CHALLENGE.md` and GitHub Actions.
