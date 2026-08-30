# Zero-Day Track report template

## Researcher

Name / handle / anonymous attribution:

## Affected version and commit

Release Sentinel version:
Commit SHA:

## Broken invariant

State exactly what changed that should not have changed. Examples:

- authoritative evidence bytes changed under identical ground truth;
- deterministic verdict changed under identical trusted evidence;
- blocking evidence became `GO`;
- remediation self-approved without a fresh evaluation;
- an untrusted component obtained a write path into the trust kernel.

## Minimal reproducer

Provide source or a failing test. Do not require opaque binaries, credentials,
third-party attacks, or privileged host access.

## Ground-truth control

Show the source SHA-256, policy SHA-256, relevant fixture/executor identity, and
other inputs that must remain fixed for your influence claim.

## Observed result

Baseline artifact SHA-256:
Attacked artifact SHA-256:
Baseline decision:
Attacked decision:

## Impact

Explain why this crosses from agent/application compromise into release
authority.

## Suggested regression test

Describe the smallest permanent test that would prevent recurrence.
