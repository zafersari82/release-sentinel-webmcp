# Human Proof Checkpoint Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the current WebMCP demo into a coherent human-agent proof workflow with truthful provenance, three package-owned remediation scenarios, and an explicit human verification checkpoint after fresh Gatekeeper re-verification.

**Architecture:** Keep the 12-tool WebMCP capability plane unchanged. Add a single package-owned scenario registry that owns demo IDs, fixture pairs, labels, and proof IDs; route proposal/rebuild/reverify/verify-proof through that registry. The browser reveals a non-authoritative human verification card only after fresh re-verification and uses the existing `verify_proof` capability to independently compare evidence integrity, context binding, candidate source hash, and deterministic authority.

**Tech Stack:** Python 3.12, Pydantic 2, FastAPI, vanilla JavaScript/CSS, Playwright acceptance tests, Go Gatekeeper CI.

**Spec:** `docs/designs/2026-08-30-human-proof-checkpoint-design.md`

## Global Constraints

- WebMCP never gains release authority.
- `GO` / `NO_GO` remains owned by the deterministic Go Gatekeeper.
- Human verification verifies proof; it does not approve a release.
- Demo IDs and proof IDs are strict enums; arbitrary caller IDs remain invalid.
- No caller-supplied source, shell command, filesystem path, or policy mutation is introduced.
- Three scenarios use three distinct package-owned vulnerable/fixed fixture pairs.
- Existing trust and coverage kernels remain untouched.
- WebMCP tool inventory remains exactly 12.

---

### Task 1: Align provenance and public presentation

**Files:**
- Create: `CHALLENGE_PROVENANCE.md`
- Delete: `PREEXISTING_WORK.md`
- Modify: `README.md`
- Modify: `CHALLENGE_CHANGELOG.md`
- Modify: `docs/WEBMCP_CHALLENGE.md`
- Modify: `VERIFICATION_WEBMCP_CHALLENGE.md`
- Modify: `src/release_sentinel/interfaces/static/arena.html`
- Test: `tests/test_webmcp_submission_packaging.py`

**Interfaces:**
- Consumes: existing checkpoint SHA `634c8fbfb9697169cdb76fe4b3c5f52cf5295b039b22a29dec02da8a3af3c967`.
- Produces: one authoritative provenance document and public copy that consistently describes 12 tools and the capability-without-authority product.

- [ ] **Step 1: Write failing provenance/presentation regressions**

Add assertions equivalent to:

```python
root = Path(__file__).parents[1]
readme = (root / "README.md").read_text(encoding="utf-8")
arena = (root / "src/release_sentinel/interfaces/static/arena.html").read_text(encoding="utf-8")
provenance = root / "CHALLENGE_PROVENANCE.md"

assert provenance.exists()
assert not (root / "PREEXISTING_WORK.md").exists()
assert "PRE-EXISTING v2.3.0 CORE" not in arena
assert "CAPABILITY WITHOUT AUTHORITY · WEBMCP PROOF ARENA" in arena
assert "run_attack_suite" in readme
assert "exactly 12 typed tools" in readme
assert "PREEXISTING_WORK.md" not in readme
assert "634c8fbfb9697169cdb76fe4b3c5f52cf5295b039b22a29dec02da8a3af3c967" in provenance.read_text(encoding="utf-8")
```

- [ ] **Step 2: Run the focused packaging test and confirm RED**

Run via CI or local pytest:

```bash
PYTHONPATH=src:packages/agentseal/src pytest -q tests/test_webmcp_submission_packaging.py
```

Expected: failures for missing `CHALLENGE_PROVENANCE.md`, stale hero copy, stale 11-tool/provenance references.

- [ ] **Step 3: Replace provenance copy without inventing history**

`CHALLENGE_PROVENANCE.md` must retain the checkpoint SHA, describe it neutrally as a development checkpoint/provenance anchor, and state only public-history facts that are verifiable. Remove `PREEXISTING_WORK.md` after all references are migrated.

Update public docs so no first-screen or current-inventory copy says `PRE-EXISTING v2.3.0 CORE`, `exactly 11 tools`, or points at the removed filename. Keep dated historical test counts explicitly labeled as historical where they are retained; do not silently rewrite an old test result into a new one.

- [ ] **Step 4: Update Arena hero/footer**

Use:

```html
<p class="eyebrow">CAPABILITY WITHOUT AUTHORITY · WEBMCP PROOF ARENA</p>
```

Keep the existing lede. Move provenance to a compact footer/docs reference rather than the hero.

- [ ] **Step 5: Re-run focused tests and commit**

Expected: provenance/presentation tests PASS.

Commit message:

```text
docs/ui: align challenge provenance and arena framing
```

---

### Task 2: Add three strict package-owned demo scenarios

**Files:**
- Create: `src/release_sentinel/webmcp/demo_scenarios.py`
- Create: `src/release_sentinel/demo_fixture/repository_path_traversal_vulnerable/app.py`
- Create: `src/release_sentinel/demo_fixture/repository_path_traversal_fixed/app.py`
- Create: `src/release_sentinel/demo_fixture/repository_evidence_tamper_vulnerable/app.py`
- Create: `src/release_sentinel/demo_fixture/repository_evidence_tamper_fixed/app.py`
- Modify: `src/release_sentinel/webmcp/contracts.py`
- Modify: `src/release_sentinel/webmcp/demo_runtime.py`
- Modify: `src/release_sentinel/webmcp/remediation_service.py`
- Modify: `src/release_sentinel/webmcp/service.py`
- Modify: `src/release_sentinel/interfaces/static/arena.html`
- Modify: `src/release_sentinel/interfaces/static/arena.js`
- Test: `tests/test_webmcp_contracts.py`
- Test: `tests/test_webmcp_service.py`
- Test: `tests/test_webmcp_agent_schema.py`

**Interfaces:**
- Produces: `DemoReleaseId`, `ProofId`, immutable `DemoScenario`, `get_scenario()`, `fixture_for_proof()`.
- Consumes: existing package-owned `repository_vulnerable` / `repository_fixed` as the cross-tenant pair.

- [ ] **Step 1: Write RED tests for strict scenario enums and service flow**

Require exactly these release IDs:

```python
{
    "demo-cross-tenant",
    "demo-path-traversal",
    "demo-evidence-tamper",
}
```

Require an arbitrary ID such as `../../tmp/payload` to fail Pydantic validation and service resolution. Parameterize the proposal → rebuild → reverify path across all three IDs and assert:

```python
assert proposal["authority"] == "PROPOSAL_ONLY"
assert rebuilt["old_source_sha256"] != rebuilt["new_source_sha256"]
assert rebuilt["verdict"] == "NOT_YET_REVERIFIED"
assert result["source_sha256"] == rebuilt["new_source_sha256"]
assert result["final_verdict"] == "GO"
assert result["fresh_evaluation"] is True
assert result["proof_id"].endswith("-fixed")
```

- [ ] **Step 2: Confirm RED**

Run:

```bash
PYTHONPATH=src:packages/agentseal/src pytest -q \
  tests/test_webmcp_contracts.py \
  tests/test_webmcp_service.py \
  tests/test_webmcp_agent_schema.py
```

Expected: failures because only `demo-vulnerable` exists and reverify does not return a proof ID.

- [ ] **Step 3: Implement `demo_scenarios.py` as the single authority for demo IDs**

Use immutable structures equivalent to:

```python
class DemoReleaseId(str, Enum):
    CROSS_TENANT = "demo-cross-tenant"
    PATH_TRAVERSAL = "demo-path-traversal"
    EVIDENCE_TAMPER = "demo-evidence-tamper"

class ProofId(str, Enum):
    CURRENT = "demo-current"
    CROSS_TENANT_FIXED = "demo-cross-tenant-fixed"
    PATH_TRAVERSAL_FIXED = "demo-path-traversal-fixed"
    EVIDENCE_TAMPER_FIXED = "demo-evidence-tamper-fixed"

@dataclass(frozen=True)
class DemoScenario:
    release_id: DemoReleaseId
    label: str
    vulnerable_fixture: str
    fixed_fixture: str
    fixed_proof_id: ProofId
```

The registry maps each release ID to distinct package-owned fixture names. `get_scenario()` and `fixture_for_proof()` raise a bounded lookup error for unknown values; no arbitrary filesystem strings pass through.

- [ ] **Step 4: Add distinct fixture pairs**

Path traversal vulnerable fixture:

```python
from pathlib import Path

def resolve_export(root: Path, user_path: str) -> Path:
    return root / user_path
```

Path traversal fixed fixture must resolve both paths and reject a target outside the root.

Evidence-tamper vulnerable fixture:

```python
def evidence_matches(payload: bytes, claimed_digest: str) -> bool:
    return True
```

Evidence-tamper fixed fixture must compare `hashlib.sha256(payload).hexdigest()` to the claimed digest.

- [ ] **Step 5: Generalize `demo_runtime.py` without arbitrary path acceptance**

Replace the vulnerable/fixed ternary with a package-owned fixture map such as:

```python
FIXTURE_DIRECTORIES = {
    "cross_tenant_vulnerable": ("repository_vulnerable", 1),
    "cross_tenant_fixed": ("repository_fixed", 0),
    "path_traversal_vulnerable": ("repository_path_traversal_vulnerable", 1),
    "path_traversal_fixed": ("repository_path_traversal_fixed", 0),
    "evidence_tamper_vulnerable": ("repository_evidence_tamper_vulnerable", 1),
    "evidence_tamper_fixed": ("repository_evidence_tamper_fixed", 0),
}
```

Unknown fixture names raise instead of falling through to a default directory.

- [ ] **Step 6: Route remediation records through scenario metadata**

Extend proposal/candidate records to retain `demo_release_id`, fixed fixture name, and fixed proof ID. `propose_remediation()` resolves a scenario; `rebuild_candidate()` verifies the target digest against that scenario's fixed fixture; `reverify_candidate()` evaluates that fixed fixture and returns `proof_id`.

- [ ] **Step 7: Route `verify_proof` through the same registry**

Keep `demo-current` for the current blocked cross-tenant proof. Resolve fixed proof IDs through `fixture_for_proof()` and return the same evidence/context fields as today.

- [ ] **Step 8: Add a remediation scenario selector in Arena**

Add a strict `<select id="demoScenarioSelect">` containing exactly the three release IDs. The proposal button passes the selected value; no free-form input is introduced.

- [ ] **Step 9: Re-run focused tests and commit**

Commit message:

```text
feat: add allowlisted WebMCP demo scenarios
```

---

### Task 3: Add the non-authoritative human proof verification checkpoint

**Files:**
- Modify: `src/release_sentinel/interfaces/static/arena.html`
- Modify: `src/release_sentinel/interfaces/static/arena.css`
- Modify: `src/release_sentinel/interfaces/static/arena.js`
- Modify: `tests/browser_webmcp_acceptance.py`
- Modify: `tests/browser_webmcp_native_acceptance.py` only if native assertions need the new post-reverify state.

**Interfaces:**
- Consumes: reverify result fields `proof_id`, `source_sha256`, `final_verdict`, `authority`; candidate fields `old_source_sha256`, `new_source_sha256`; existing `verify_proof` tool.
- Produces: browser-only state `UNVERIFIED BY HUMAN`, `VERIFIED BY HUMAN`, or `VERIFICATION FAILED`. None is a release verdict.

- [ ] **Step 1: Write RED browser assertions**

Before reverify:

```python
assert page.locator("#humanProofCard").get_attribute("hidden") is not None
```

After reverify:

```python
page.wait_for_function("!document.querySelector('#humanProofCard').hidden")
assert page.locator("#humanProofStatus").inner_text() == "UNVERIFIED BY HUMAN"
```

After clicking independent verification with a matching proof:

```python
page.click("#verifyHumanProof")
page.wait_for_function("document.querySelector('#humanProofStatus').textContent === 'VERIFIED BY HUMAN'")
```

Add a second page/stub where the proof returns a different `source_sha256`; require `VERIFICATION FAILED` even when `evidence_integrity_verified` and `context_bound` are true.

- [ ] **Step 2: Confirm RED**

Run browser acceptance and expect missing-card/assertion failures.

- [ ] **Step 3: Add semantic card markup**

Place immediately below the timeline:

```html
<section id="humanProofCard" class="panel humanProofCard" hidden>
  <p class="eyebrow">HUMAN CHECKPOINT · VERIFY, DON'T TRUST</p>
  <h2>Agent work is complete. Don’t trust it — verify it.</h2>
  ...
  <button id="verifyHumanProof">Verify independently</button>
  <strong id="humanProofStatus">UNVERIFIED BY HUMAN</strong>
</section>
```

Render old/new hashes, Gatekeeper verdict, and decision authority.

- [ ] **Step 4: Add fail-closed browser verification logic**

Extend `state` with the latest reverify result and human verification state. `renderReverify()` reveals the card only after a successful fresh reverify. Clicking the button invokes:

```javascript
const proof = await invokeTool('verify_proof', {proof_id: state.reverify.proof_id});
const checks = {
  evidence: proof.evidence_integrity_verified === true,
  context: proof.context_bound === true,
  source: proof.source_sha256 === state.candidate.new_source_sha256,
  authority: /^DETERMINISTIC_/.test(String(proof.authority || '')),
};
```

Set `VERIFIED BY HUMAN` only when `Object.values(checks).every(Boolean)`; otherwise set `VERIFICATION FAILED` and list failed predicates. Do not mutate `currentVerdict`, candidate verdict, or Gatekeeper state.

- [ ] **Step 5: Style three visual states without redesigning the page**

Add focused CSS classes for neutral, verified, and failed card states. Reuse existing panel/kv/button primitives.

- [ ] **Step 6: Re-run browser acceptance and commit**

Commit message:

```text
feat: add human proof verification checkpoint
```

---

### Task 4: Full verification, public docs refresh, PR and merge

**Files:**
- Modify: `VERIFICATION_WEBMCP_CHALLENGE.md` with fresh results only after they exist.
- Modify: `CHALLENGE_CHANGELOG.md` with the completed scenario/human-checkpoint additions.

**Interfaces:**
- Produces: one reviewable PR whose CI proves the final branch state.

- [ ] **Step 1: Run/observe the full branch gates**

Required:

```text
full Python suite
trust-boundary guard suite with no silent skips
frozen trust kernel
frozen coverage kernel
Go vet + race test + build
AgentSeal suite
real container confinement
WebMCP submission-container browser acceptance
Native Chrome WebMCP execution
```

- [ ] **Step 2: Update verification documentation from actual results**

Do not guess counts. Copy only observed current CI/test results. Mark old verification blocks as historical or replace them with the fresh checkpoint.

- [ ] **Step 3: Review complete branch diff**

Reject the branch if any diff introduces:

```text
set_verdict
force_go as an authority method
override_gatekeeper
arbitrary shell/filesystem/source input
caller-controlled fixture paths
browser-side approval authority
```

- [ ] **Step 4: Open PR and require green checks**

PR title:

```text
feat: add human proof checkpoint and bounded demo scenarios
```

- [ ] **Step 5: Squash merge only after green CI**

After merge, run the same `main` workflows and require green results before declaring completion.
