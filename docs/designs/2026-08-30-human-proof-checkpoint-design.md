# Human Proof Checkpoint Design

## Goal

Make the WebMCP submission read as one coherent product rather than a collection of challenge adapters: the agent does the work, the deterministic Gatekeeper decides, and the human independently verifies the resulting proof.

This change also removes stale submission copy, upgrades the single hard-coded remediation demo into a small allowlisted fixture registry, and keeps all authority boundaries fail-closed.

## Non-negotiable constraints

- WebMCP never gains release authority.
- `GO` / `NO_GO` remains owned by the deterministic Go Gatekeeper.
- Human verification does not approve a release; it independently verifies evidence integrity and context binding.
- No caller-supplied source code, shell command, filesystem path, policy mutation, or arbitrary fixture identifier is accepted.
- New demo scenarios are package-owned and allowlisted.
- Existing signed-evidence, trust-kernel, coverage-kernel, and judged-mode behavior must remain unchanged.
- The existing `run_attack_suite` remains browser-side WebMCP orchestration; no mega backend endpoint is introduced.
- The WebMCP tool inventory remains 12 tools unless a separate design explicitly changes it.

## 1. Submission provenance and presentation

### Problem

The public repository and Arena still contain stale copy that describes the current submission as `PRE-EXISTING v2.3.0 CORE` plus an extension, and the README still documents 11 WebMCP tools. This conflicts with the current product presentation and makes the first screen about provenance instead of the security model.

### Design

Replace `PREEXISTING_WORK.md` with `CHALLENGE_PROVENANCE.md`.

The new document will preserve the known baseline ZIP SHA-256 as a provenance anchor, describe it neutrally as a development checkpoint, and avoid claims that cannot be established by the public Git history. It will explicitly state that repository history is not fabricated or backdated and that artifact hashes are retained so reviewers can reproduce the submitted lineage.

The README provenance section will point to `CHALLENGE_PROVENANCE.md`, update the tool inventory to 12, and include `run_attack_suite` as an agent-native composite capability.

The Arena hero eyebrow becomes:

`CAPABILITY WITHOUT AUTHORITY · WEBMCP PROOF ARENA`

The hero lede remains centered on the governing idea:

`Give the agent capability, never release authority. If it cannot change the proof, it has to change the software.`

Detailed provenance moves to the footer/docs rather than being the first message shown to a judge.

## 2. Allowlisted demo scenario registry

### Problem

`ProposalRequest.demo_release_id` is currently constrained to the single literal `demo-vulnerable`. This is safe but makes the remediation workflow look like a one-off demo.

### Design

Introduce a package-owned scenario registry with exactly three supported IDs:

1. `demo-cross-tenant`
2. `demo-path-traversal`
3. `demo-evidence-tamper`

The request schema will use an enum rather than a permissive regex/string. Unknown IDs fail validation before reaching remediation logic.

Each scenario entry defines only server-owned metadata required by the existing bounded remediation path:

- `release_id`
- vulnerable fixture identity
- fixed fixture identity
- human-readable scenario label
- supported proof identity after fresh verification

No scenario may specify executable caller content. The remediation service resolves the enum to package-owned fixture data.

To minimize authority-surface change, the registry will live in the WebMCP/demo fixture layer and reuse the existing proposal → rebuild → reverify path. It will not alter Gatekeeper policy or signed-evidence semantics.

## 3. Human Verification Checkpoint

### Problem

Today `verify_proof` is one tool among many. The UI does not make the human-agent collaboration explicit after the agent finishes remediation.

### User experience

After a successful `reverify_candidate` response, the Arena reveals a new card immediately below the agent timeline:

**Agent work is complete. Don’t trust it — verify it.**

The card displays:

- old source SHA-256
- new source SHA-256
- Gatekeeper verdict returned by fresh verification
- deterministic decision authority
- a `Verify independently` button

The card starts in `UNVERIFIED BY HUMAN` state.

Clicking `Verify independently` calls the existing `verify_proof` capability for the proof identity bound to the rebuilt candidate. The result is rendered as four independent checks:

- `evidence_integrity_verified`
- `context_bound`
- proof `source_sha256` equals the newly rebuilt source hash
- authority is deterministic Gatekeeper authority

The UI changes to `VERIFIED BY HUMAN` only when every required check is true.

A failed or mismatched check never upgrades the visual state. It renders `VERIFICATION FAILED` with the exact failed predicates.

### Authority semantics

The human checkpoint does **not** call a new approval endpoint and does **not** set a verdict. It verifies a proof already produced by the deterministic system.

Therefore the final chain is:

`Agent acts → Gatekeeper decides → Human verifies proof`

not:

`Agent acts → Human approves → system trusts human`

## 4. Data flow

1. Agent or human selects one allowlisted demo scenario.
2. Existing WebMCP remediation tools produce a proposal.
3. Existing rebuild path creates a new source hash with no inherited verdict.
4. Existing reverify path obtains fresh signed evidence and a deterministic Gatekeeper verdict.
5. Browser stores only the identifiers and hashes already returned by the flow.
6. Human verification card becomes available.
7. `verify_proof` recomputes supported proof integrity/context binding.
8. Browser compares proof source hash to the candidate hash from step 3.
9. Only if all checks match does the human card show `VERIFIED BY HUMAN`.

No browser-side state is authoritative for release decisions.

## 5. Error handling and fail-closed behavior

- Unknown scenario ID: Pydantic validation failure; no remediation side effect.
- Scenario without a package-owned fixed fixture: server rejects proposal creation.
- Reverify without matching candidate/source hash: existing error path remains authoritative.
- Human verification before successful reverify: button/card unavailable.
- Proof source hash differs from rebuilt source hash: verification state is failure even if signature integrity is otherwise valid.
- `verify_proof` error: exact structured error and `next_action` are shown; UI remains unverified.
- WebMCP unavailable: existing human controls continue to work; no false registered/verified state.

## 6. Files and responsibilities

### Provenance/presentation

- `CHALLENGE_PROVENANCE.md` — authoritative submission provenance narrative.
- `PREEXISTING_WORK.md` — removed after all references are migrated.
- `README.md` — 12-tool inventory and current submission framing.
- `src/release_sentinel/interfaces/static/arena.html` — hero copy and human verification card markup.
- `src/release_sentinel/interfaces/static/arena.css` — verification-card states only; no unrelated redesign.

### Scenario registry

- `src/release_sentinel/webmcp/contracts.py` — strict `DemoReleaseId` enum and request schema.
- `src/release_sentinel/webmcp/demo_runtime.py` or a focused `demo_scenarios.py` module if current file size/responsibility warrants separation — package-owned registry resolution.
- `src/release_sentinel/webmcp/remediation_service.py` — resolve scenario metadata through registry, preserving existing bounded remediation operations.

### Human verification

- `src/release_sentinel/interfaces/static/arena.js` — reveal checkpoint after reverify, call existing `verify_proof`, compare candidate/proof hashes, render deterministic verification state.

## 7. Test strategy

All changes are test-first.

### Provenance/presentation tests

Add regression assertions that:

- public Arena hero does not contain `PRE-EXISTING v2.3.0 CORE`;
- README documents exactly 12 WebMCP tools and includes `run_attack_suite`;
- README no longer points to the removed provenance filename;
- `CHALLENGE_PROVENANCE.md` exists and contains the retained checkpoint SHA-256.

### Scenario registry tests

Add tests that:

- exactly three demo IDs are exposed in the WebMCP input schema;
- each supported scenario produces a bounded proposal through package-owned fixtures;
- an arbitrary ID fails before service execution;
- callers cannot inject path/source/shell fields due to `extra="forbid"`.

### Human verification tests

Extend browser acceptance to prove:

- verification card is hidden before successful reverify;
- card appears after fresh reverify;
- correct proof + matching candidate hash produces `VERIFIED BY HUMAN`;
- valid proof with mismatched source hash produces `VERIFICATION FAILED`;
- verification does not issue a second verdict or mutate Gatekeeper state;
- WebMCP unavailable fallback does not fabricate verification.

### Full regression gates

Before merge:

- full Python suite
- trust-boundary guard suite with no silent skips
- frozen trust kernel
- frozen coverage kernel
- Go `vet`, `test -race`, and build
- AgentSeal suite
- real container confinement
- WebMCP submission-container browser acceptance
- native Chrome WebMCP execution

## 8. Commit/merge shape

The branch will use three reviewable logical commits:

1. `docs/ui: align challenge provenance and arena framing`
2. `feat: add allowlisted WebMCP demo scenarios`
3. `feat: add human proof verification checkpoint`

After all branch checks pass, open a PR, review the complete diff, require green CI, and squash-merge to `main` so the public history remains concise.
