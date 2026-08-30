# WebMCP Agent-Only Attack Suite Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an agent-only `run_attack_suite` WebMCP capability that executes the fixed eight-attack campaign through the existing `run_attack` path, aggregates containment evidence, and preserves deterministic Gatekeeper authority.

**Architecture:** Register one additional `CHALLENGE` tool with an empty input schema. Implement orchestration only in the browser WebMCP capability plane by reading authoritative attack names from the `run_attack` tool schema, sequentially invoking the existing attack HTTP path, and aggregating results without adding a backend mega-endpoint or a human button.

**Tech Stack:** Python 3.12, Pydantic v2, FastAPI, vanilla JavaScript, Chrome WebMCP, Playwright, pytest, Go Gatekeeper.

**Spec:** `docs/designs/2026-08-30-webmcp-agent-attack-suite-design.md`

## Global Constraints

- `run_attack_suite` capability class is `CHALLENGE`.
- No new release-decision, approval, override, shell, repository mutation, policy mutation, or signed-evidence mutation capability.
- No `/v1/webmcp/attack-suite` backend endpoint.
- Attack names come from the existing `run_attack` input schema, never a second JavaScript list.
- Execution is sequential and fail-closed.
- No visible human UI control for the suite.
- The suite does not automate remediation.
- Full child attack results remain in the response.
- `all_contained` is scoped to this bounded campaign and is not a universal-security claim.

---

### Task 1: Lock the WebMCP contract and agent-only boundary

**Files:**
- Create: `tests/test_webmcp_agent_attack_suite.py`
- Modify: `src/release_sentinel/webmcp/contracts.py`

**Interfaces:**
- Consumes: `AttackName`, `EmptyRequest`, `CapabilityClass`, `TOOL_DEFINITIONS`.
- Produces: a `run_attack_suite` tool definition with `CHALLENGE` capability and empty input schema.

- [ ] **Step 1: Write failing contract tests**

Create tests that assert the catalog has 12 tools, `run_attack_suite` exists, its capability is `CHALLENGE`, its schema accepts no properties, the `run_attack` schema exposes all authoritative `AttackName` values, and the arena source contains no `data-attack-suite` or click binding.

- [ ] **Step 2: Run the focused tests and verify RED**

Run: `pytest -q tests/test_webmcp_agent_attack_suite.py`
Expected: FAIL because `run_attack_suite` is absent.

- [ ] **Step 3: Register the minimum tool contract**

Add `run_attack_suite` to `TOOL_DEFINITIONS` immediately after `run_attack`, using `CapabilityClass.CHALLENGE` and `EmptyRequest`. The description must say it executes the complete bounded campaign, cannot issue a verdict, and points the agent toward coverage/counterexample analysis next.

- [ ] **Step 4: Re-run focused tests**

Run: `pytest -q tests/test_webmcp_agent_attack_suite.py`
Expected: contract assertions pass while orchestration assertions remain RED until Task 2.

- [ ] **Step 5: Commit**

Commit message: `test: define agent-only WebMCP attack suite`

---

### Task 2: Implement schema-derived sequential orchestration

**Files:**
- Modify: `tests/test_webmcp_agent_attack_suite.py`
- Modify: `src/release_sentinel/interfaces/static/arena.js`

**Interfaces:**
- Consumes: `state.catalog.tools`, the `run_attack` tool `input_schema.properties.attack_name.enum`, and the existing `request('/v1/webmcp/attack/<name>')` path.
- Produces: `run_attack_suite` browser tool handler returning deterministic aggregate fields plus full child results.

- [ ] **Step 1: Add failing static behavior assertions**

Require the arena code to locate the `run_attack` tool schema from the catalog, read its enum values, avoid a duplicated attack-name array, await attacks sequentially, expose `run_attack_suite` in `toolHandlers`, and summarize suite results in the timeline.

- [ ] **Step 2: Verify RED**

Run: `pytest -q tests/test_webmcp_agent_attack_suite.py`
Expected: FAIL on missing suite orchestration.

- [ ] **Step 3: Add a focused helper and handler**

Implement a small browser helper that reads attack names from `state.catalog`, executes the existing `run_attack` handler sequentially, and returns:

```json
{
  "suite": "bounded_release_attack_suite",
  "attacks_requested": 8,
  "attacks_executed": 8,
  "contained_count": 8,
  "all_contained": true,
  "unexpected_authority_gains": 0,
  "max_agent_influence": 0,
  "final_verdicts": ["NO_GO"],
  "authority": "DETERMINISTIC_GO_GATEKEEPER",
  "webmcp_authority": "NO_RELEASE_AUTHORITY",
  "results": []
}
```

Aggregation must derive every value from child results. Mixed child Gatekeeper authority yields `MIXED_AUTHORITY`. Any child request error aborts the suite.

- [ ] **Step 4: Re-run focused tests**

Run: `pytest -q tests/test_webmcp_agent_attack_suite.py`
Expected: PASS.

- [ ] **Step 5: Commit**

Commit message: `feat: orchestrate bounded attacks through WebMCP`

---

### Task 3: Prove native Chrome WebMCP execution

**Files:**
- Modify: `tests/browser_webmcp_native_acceptance.py`

**Interfaces:**
- Consumes: browser-native `document.modelContext.getTools()` and `executeTool()`.
- Produces: an end-to-end acceptance proof that the 12th tool is current-window WebMCP and returns bounded aggregate evidence.

- [ ] **Step 1: Extend the native acceptance assertions**

Change the expected current-window tool count from 11 to 12. Find `run_attack_suite` by exact name and current window, execute it with `{}`, parse the result, and assert 8 requested/executed, 8 contained, `all_contained == true`, no authority gains, max agent influence 0, `NO_RELEASE_AUTHORITY`, and eight individually inspectable authoritative attack names.

- [ ] **Step 2: Run the native test in the challenge container**

Run through the existing `webmcp-native` workflow/challenge container rather than a mocked DOM.
Expected: PASS on WebMCP-enabled Chrome.

- [ ] **Step 3: Commit**

Commit message: `test: execute agent attack suite through native WebMCP`

---

### Task 4: Full verification and integration

**Files:**
- No semantic production changes expected.

**Interfaces:**
- Consumes: the completed branch.
- Produces: a green, mergeable checkpoint.

- [ ] **Step 1: Run full Python suite**

Run: `pytest -q --strict-markers`
Expected: all tests pass with no trust-boundary guard skips.

- [ ] **Step 2: Run frozen trust-kernel and Go gates**

Run the existing trust-gates workflow, including frozen trust-kernel checks, `go vet ./...`, `go test -race ./...`, and `go build -trimpath ./...`.
Expected: all jobs green.

- [ ] **Step 3: Run submission-container browser acceptance**

Use the existing challenge container workflow.
Expected: browser registration and execution acceptance green.

- [ ] **Step 4: Run native Chrome WebMCP workflow**

Expected: `run_attack_suite` executes through `document.modelContext.executeTool()` and all assertions pass.

- [ ] **Step 5: Integrate only the verified branch**

Fast-forward/merge the verified branch into `main` without unrelated refactors.
