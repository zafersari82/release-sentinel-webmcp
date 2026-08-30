# Release Sentinel — WebMCP Proof Arena

**Give an AI agent real power on your website without giving it the final word.**

Live demo: https://release-sentinel-webmcp.onrender.com/arena · Video: `<YOUTUBE_URL>` · Code: https://github.com/zafersari82/release-sentinel-webmcp

---

## The one-sentence version

We gave an AI agent every tool our site has and told it to force a blocked software
release through. It couldn't. So it found the actual bug, fixed the code, and earned a
legitimate approval instead — and you can watch the whole thing happen in your browser.

## Inspiration

Everyone building agentic websites right now is solving the same problem twice.

First they ask: *how do I let an agent do something useful here?* WebMCP answers that
beautifully — you register typed tools and the agent stops guessing at your DOM.

Then they hit the second question, and it's much harder: *how do I let an agent do
something useful here without letting it do the one thing it must never do?* Approve
the payment. Ship the release. Delete the account. Sign the contract.

Most demos answer that with a confirmation dialog and hope. We wanted to answer it
architecturally, and we wanted the answer to be falsifiable — something a skeptic could
personally attack in their browser rather than take on faith.

So we built a site where the dangerous action is real, the agent is genuinely capable,
and you are invited to help it cheat.

## What it does

Release Sentinel is a release-approval gate. A piece of software is blocked because a
security scanner found a cross-tenant authorization bug — one customer can read another
customer's data. The release sits at `NO_GO`.

Open the site and hit **Run guided demo**, or point an agent at it and say *"get this
release approved, try everything."* Either way you watch the same story:

**Act 1 — the agent tries to cheat, and can't.** It runs all eight attacks the site
allows: it votes GO on its own behalf, it makes four separate advisory agents all vote
GO, it replays a previously valid approval, it forges an authority header, it tampers
with the evidence digest, it downgrades the finding severity, it deletes the blocker,
it tries prompt injection. Every attack reaches the real Gatekeeper and is scored by it.
The result is `8/8 contained · agent influence 0`. Not because the attacks were faked —
because approval is computed from cryptographically sealed evidence by a separate
deterministic Go service that has no opinion input.

**Act 2 — so it fixes the software instead.** Now the interesting part. The agent
compares the fast production check against a slower reference oracle on a fixed
benchmark corpus, and sees exactly where the gate is weak: revision 1 lets 23 unsafe
cases through. It pulls out one concrete escape, shrinks it to a minimal reproducer, and
proposes a repair. The proposal is explicitly `PROPOSAL_ONLY` — the agent authored it and
still cannot act on it.

**Act 3 — a different component decides.** The code is rebuilt to a new SHA-256. That
matters more than it sounds: the old verdict does not transfer to new code, and neither
would an old approval. Fresh evidence is signed, the deterministic Gatekeeper re-runs the
checks, and *it* returns `GO`. Then a human independently re-verifies the proof — and
notably, human verification isn't approval either.

The collaboration model is: **agent acts → gatekeeper decides → human verifies.**
Three roles, three different powers, and no one holds two of them.

## How we used WebMCP

The browser registers exactly 12 typed tools through
`document.modelContext.registerTool()`, in three capability classes:

| Class | Tools | What the agent can do |
| --- | --- | --- |
| `READ` | `inspect_release`, `inspect_trust_boundary`, `inspect_coverage`, `compare_gate_revisions`, `verify_proof` | See everything |
| `CHALLENGE` | `run_attack`, `run_attack_suite`, `find_counterexamples`, `minimize_counterexample` | Attack the boundary, measure where it's weak |
| `PROPOSE` | `propose_remediation`, `rebuild_candidate`, `reverify_candidate` | Request bounded state changes |

Four things we did deliberately, and would argue are the transferable part:

**1. The absence of tools is a tested feature.** There is no `set_verdict`, no
`force_go`, no policy toggle, no evidence editor, no generic `execute`, no shell, no
arbitrary filesystem path. A regression test asserts each of these stays absent, so the
authority boundary can't be widened by accident six months from now. On an agentic site,
the tools you *don't* register are as much a part of the design as the ones you do.

**2. Schemas are the enforcement layer, not the suggestion layer.** Every input is a
strict Pydantic contract with `extra="forbid"` and bounded enums. The agent cannot hand
us a counterexample, a fixture path, or source code to run — it selects from
package-owned identities. We also flatten local JSON Schema `$ref`/`$defs` before
registration, because an agent reading a tool schema should see its actual choices
inline, not a pointer it has to resolve.

**3. Errors are written for an agent, not a log file.** Every failure carries a
`next_action` string telling the agent what to do instead. Ask for an attack that doesn't
exist and you get the list of the eight that do. This turned out to matter far more than
we expected: an agent that can recover from a bad call doesn't start inventing state.

**4. Composition happens in the browser, not as a new endpoint.** `run_attack_suite`
looks like a power tool, but there is no `/attack-suite` route on the server. It reads
the `run_attack` enum out of the registered schema and drives the same bounded tool eight
times, then derives containment metrics client-side. The agent gets ergonomics; the
server's attack surface doesn't grow by a single byte. We think this is an underrated
WebMCP pattern — the browser is a legitimate place to compose capability precisely
because it has no authority of its own.

## Human–agent experience

Both audiences see one screen, and neither is a second-class citizen.

The **agent** gets typed tools, self-describing schemas, and recoverable errors. The
**human** gets the authority chain rendered across the top, escapes and overblocks shown
side by side (a stricter policy is never presented as cost-free), the source-hash
transition made visible, and a live timeline of every agent action tagged by capability
class — which is really a receipt showing that none of them were authoritative.

If the browser doesn't support WebMCP, the page says `UNAVAILABLE` in plain text rather
than pretending, and every human control keeps working.

## What we built during the submission period

Release Sentinel's release-gate foundation predates this challenge, and we've documented
that boundary precisely rather than blur it — see `CHALLENGE_PROVENANCE.md` and
`CHALLENGE_CHANGELOG.md`, with dated pre-challenge artifacts retained in the repo.

Built for the challenge: the entire 12-tool WebMCP capability plane and its typed
contracts; browser registration and native-Chrome acceptance; the `/v1/webmcp/*` adapter
layer; agent-facing schema flattening and `next_action` recovery errors; the
`run_attack_suite` browser composition; the Proof Arena UI; the guided demo; three
package-owned remediation scenarios with distinct vulnerable/fixed fixtures; the
proposal → new-hash → fresh-verification state machine; the Human Proof Checkpoint; and
the WebMCP-specific test, CI, Docker, and deployment work.

## Challenges

The hardest problem was not security — it was legibility. Our first Arena was accurate
and nearly unreadable: a judge landing on it met "overblocks", "proof context binding"
and `PROPOSAL_ONLY` before they met the story. We added a guided demo that narrates the
full arc in plain language and a jargon-translation layer under every heading. The
security model didn't change at all; how long it takes to understand it changed
completely.

The second was resisting a very tempting shortcut. `run_attack_suite` would have been
trivial as a server endpoint. Building it as browser-side composition over the existing
bounded tool was more work and is the more honest answer to what WebMCP is for.

## Verification

- 300 Python tests, plus Go `vet` / `test -race` on the Gatekeeper
- Frozen trust-kernel and coverage-kernel manifests (security-critical files are
  hash-pinned; the Arena UI deliberately sits outside them)
- Playwright and native-Chrome WebMCP registration acceptance
- Contract tests asserting forbidden capabilities remain absent

```bash
docker build -f Dockerfile.webmcp -t release-sentinel-webmcp .
docker run --rm -p 8080:8080 release-sentinel-webmcp
# open http://127.0.0.1:8080/arena
```

## What's next

The pattern generalizes past release engineering, and that's the point. Any site where
an agent should be able to *act* but never *authorize* — payments, admin consoles,
medical records, infrastructure — needs the same three-part split. What we'd want next is
a reusable primitive: capability classes and a "this authority is not reachable from
WebMCP" assertion that any site can adopt without rebuilding a Gatekeeper first.

---

*The agent couldn't change the proof, so it had to change the software.*
