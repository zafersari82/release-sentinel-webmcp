# WebMCP Agent-Only Attack Suite Design

## Goal

Add one WebMCP capability, `run_attack_suite`, that lets an AI agent execute the complete bounded adversarial campaign without a matching human UI button, while preserving the existing authority boundary: WebMCP may challenge the release but may never issue or override a release verdict.

## Why this exists

The current arena exposes `run_attack`, which can execute one bounded scenario at a time. A human can trigger individual attacks from visible arena controls, and an agent can call the same tool through WebMCP. The new capability must demonstrate agent-native value that is not merely equivalent to clicking an existing button.

`run_attack_suite` therefore becomes a compound WebMCP-only challenge capability. It executes every attack already enumerated by `run_attack`, reports the full per-attack evidence, and returns an aggregate containment summary. It does not perform remediation and it does not make a release decision.

## Authority constraints

These constraints are non-negotiable:

- Capability class remains `CHALLENGE`.
- No `GO`, `NO_GO`, approval, override, evidence edit, policy edit, shell, or command-execution authority is added.
- Every underlying scenario continues to use the existing `run_attack` path and the deterministic remote Gatekeeper.
- `webmcp_authority` remains `NO_RELEASE_AUTHORITY`.
- A dependency failure must fail closed. The suite must never convert an incomplete campaign into a successful containment claim.
- The suite must not invoke `propose_remediation`, `rebuild_candidate`, or `reverify_candidate` automatically. The agent must still choose the repair path itself.

## Architecture

### 1. Tool contract

Add `run_attack_suite` to `TOOL_DEFINITIONS` in `src/release_sentinel/webmcp/contracts.py`.

It uses `EmptyRequest`, because the campaign scope is fixed by the authoritative `AttackName` enum. Its description must explicitly say that it runs the complete bounded campaign and that the next analytical step is to inspect coverage/counterexamples rather than infer release authority.

The tool catalog count changes from 11 to 12.

### 2. Browser-side orchestration, not a mega endpoint

Do not create a new server endpoint such as `/v1/webmcp/attack-suite`.

Implement the suite in `src/release_sentinel/interfaces/static/arena.js` as an agent-facing WebMCP handler that orchestrates the existing bounded `run_attack` HTTP calls sequentially. This keeps the server trust surface unchanged and makes the new behavior genuinely part of the WebMCP capability plane rather than a disguised backend automation endpoint.

The suite obtains the authoritative attack names from the registered `run_attack` tool schema already returned by `/v1/webmcp/tools`. It must not maintain a second hard-coded list of attack names in JavaScript.

Execution order follows the enum order exposed by the schema. Each attack is awaited before the next begins. If any call throws, the suite throws immediately with the existing structured recovery information and does not emit a false aggregate success result.

### 3. Result shape

A successful `run_attack_suite` result contains:

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
  "results": ["full existing run_attack result objects"]
}
```

The aggregation rules are deterministic:

- `contained_count` counts results with `attack_blocked === true`.
- `all_contained` is true only when every requested attack executed and every result is blocked.
- `unexpected_authority_gains` counts any result whose `agent_influence` is non-zero or whose `webmcp_authority` differs from `NO_RELEASE_AUTHORITY`.
- `max_agent_influence` is the maximum numeric `agent_influence` observed.
- `final_verdicts` is the sorted unique set of non-null `final_verdict` values from the campaign.
- `authority` is the shared Gatekeeper authority only if every result reports the same deterministic authority; otherwise it is `MIXED_AUTHORITY`, which makes the anomaly visible rather than hiding it.
- The full underlying results remain present so the aggregate cannot erase contradictory evidence.

The result is a measurement/challenge report. `all_contained: true` must never be described as a general proof of zero vulnerabilities.

### 4. No human button

Do not add a DOM control, `data-attack-suite` element, click listener, or other visible arena action for the suite. It is discoverable through `document.modelContext.getTools()` and executable through `document.modelContext.executeTool()` only.

The arena timeline may record the suite when an agent invokes it. Its summary should show the number contained and the maximum agent influence, for example: `8/8 attacks contained · max agent influence 0`.

### 5. Native browser acceptance

Extend `tests/browser_webmcp_native_acceptance.py` to prove the capability through the browser-native WebMCP interface, not by directly calling JavaScript helpers.

The acceptance test must assert:

- 12 current-window WebMCP tools are registered.
- `run_attack_suite` exists in the current window.
- `document.modelContext.executeTool()` successfully executes it with `{}`.
- `attacks_requested == 8`.
- `attacks_executed == 8`.
- `contained_count == 8` and `all_contained is True` for the known challenge fixture.
- `unexpected_authority_gains == 0`.
- `max_agent_influence == 0`.
- `webmcp_authority == "NO_RELEASE_AUTHORITY"`.
- every returned child result is one of the authoritative `AttackName` values and remains individually inspectable.

The existing single `run_attack(force_agents_go)` acceptance remains. The suite test complements it rather than replacing it.

## TDD sequence

1. Add failing contract tests for the 12th tool, `CHALLENGE` capability, empty schema, and absence of a human button binding.
2. Add failing browser/static tests that require schema-derived attack enumeration and deterministic aggregation behavior.
3. Add failing native Chrome acceptance assertions for `run_attack_suite`.
4. Implement the minimum contract and browser orchestration needed to make those tests pass.
5. Run the complete Python suite, frozen trust-kernel checks, Go vet/race/build, submission-container browser acceptance, and native Chrome WebMCP workflow.
6. Merge to `main` only after all required gates are green.

## Files expected to change

- `src/release_sentinel/webmcp/contracts.py` — register the 12th bounded WebMCP capability.
- `src/release_sentinel/interfaces/static/arena.js` — implement schema-derived agent-only suite orchestration and timeline summary.
- `tests/test_webmcp_agent_attack_suite.py` — contract/static behavior and authority-boundary tests.
- `tests/browser_webmcp_native_acceptance.py` — native current-window execution proof.
- Existing workflow files should not need semantic changes unless a test command currently hard-codes the tool count outside the acceptance script.

## Explicit non-goals

- No automatic remediation chain.
- No new release-decision endpoint.
- No new Gatekeeper authority.
- No arbitrary attack names supplied by the agent.
- No shell or repository mutation capability.
- No claim that 8/8 contained attacks imply universal security.
- No visible arena button for `run_attack_suite`.
