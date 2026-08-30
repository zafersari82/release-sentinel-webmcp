# BREAK THE PROOF

**Bring your best engineer. The source is open. The rules are open. The agents
may betray us. Break the proof.**

Release Sentinel does not ask whether an AI agent can be prompt-injected. We
assume it can. The public challenge asks a narrower, falsifiable question:

> Can compromise of the untrusted AI/application plane change the bytes trusted
> as release evidence or the deterministic release decision?

Start with [`RULES.md`](RULES.md) and [`SAFE_HARBOR.md`](SAFE_HARBOR.md).
Two example attacks are under `submissions/`.

The challenge infrastructure is deliberately **outside** the trust kernel. Even
if the public arena UI, worker, or scoreboard is compromised, it must possess no
evidence-signing key and no decision authority.

## Fail-closed worker guard (v2.1.1)

`challenge/runtime/worker.py` is intentionally not a general-purpose local
runner. Invoking it directly on a host fails before contestant code is imported.
The worker requires the published confinement profile to be observable from
inside the process (non-root arena UID, container marker, read-only mounts,
`NoNewPrivs`, zero effective capabilities, seccomp, loopback-only networking,
and the FD limit). This is defense-in-depth on top of the launcher, not a claim
that a container alone is a universal hostile-code sandbox.
