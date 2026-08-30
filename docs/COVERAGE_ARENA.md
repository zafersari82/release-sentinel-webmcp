# Coverage Arena v2.3.0

## The question it answers

A production release gate is normally optimized for speed, repeatability, and low operating cost. A reference specification can afford to be broader and slower. Coverage Arena measures the disagreement between those two things.

> **The oracle is the specification; the production gate is the cheap approximation.**

If the oracle were cheap enough to run on every commit, the sensible engineering choice would be to add it to the production policy. Coverage Arena exists for the cases where the reference check is intentionally more expensive: broader property vectors, malformed-input exploration, isolated runtime evaluation, hidden/run-specific challenge material, or other controls that are inappropriate for the hot release path.

Coverage Arena therefore does not report “percent secure”. It reports scoped observations bound to exact challenge, fixture, policy, benchmark, oracle, gatekeeper, and runner identities.

## Measurement outcomes

For a build-valid candidate:

| Gate | Oracle | Classification |
| --- | --- | --- |
| GO | SAFE | CORRECT_ACCEPT |
| GO | UNSAFE | ESCAPE |
| NO_GO | SAFE | OVERBLOCK |
| NO_GO | UNSAFE | CORRECT_BLOCK |

Build-invalid candidates and infrastructure/security failures are `INVALID_CANDIDATE` and never enter SAFE/UNSAFE denominators.

## First challenge: strict cross-tenant authorization

The measured interface is:

```python
can_read(requester_tenant, resource_tenant) -> bool
```

The reference invariant requires:

- exactly identical, non-empty string tenant IDs -> allow;
- distinct tenant IDs -> deny, including case, whitespace, prefix/suffix and selected Unicode distinctions;
- malformed IDs -> deny.

The production approximation intentionally checks only one organization-owned example (`tenant-a` requesting `tenant-b`). That makes the gap measurable: some unsafe mutations still deny that one pair while violating other reference vectors.

The challenge itself is versioned at `src/release_sentinel/coverage/challenges/cross_tenant_v1.json` and is SHA-256 bound into measurement scope.

## Second challenge: path traversal containment

The second measured interface is:

```python
can_open_path(base_dir, requested_path, resolved_target) -> bool
```

The reference invariant requires both lexical and filesystem-resolved targets to remain inside the
base directory. It rejects relative escape via `..`, selected percent-encoded and double-encoded
traversal, backslash separators, absolute requests, NUL-bearing paths, resolved symlink escapes,
and string-prefix collisions such as `/srv/assets_evil`. The `resolved_target` argument models the
post-filesystem-resolution target without giving benchmark candidates filesystem access.

This challenge is intentionally from a different security family than authorization. It is
versioned at `src/release_sentinel/coverage/challenges/path_traversal_v1.json`, has its own qualified
oracle, fixed SAFE/UNSAFE corpus, policy revisions, benchmark manifest, and signed receipts, but it
uses the **same shared measurement protocol and comparison engine** as cross-tenant authorization.
Adding it exposed two challenge-specific couplings in the prototype runner/import graph; those were
removed by introducing shared benchmark models, an invariant-agnostic oracle protocol, a generic
reference runner, and a dedicated comparison module. The production release trust plane was not
modified.

## Oracle qualification

No measurement is finalizable until the oracle passes its known-answer qualification:

- robust known-fixed implementation -> SAFE;
- known-vulnerable implementation -> UNSAFE;
- all defined faulty oracle-rule mutants are killed by the qualification vector suite.

The qualification manifest digest and self-test digest travel in Oracle Results and Coverage Receipts.

## Deterministic Benchmark Lane

Each built-in challenge has its own deterministic benchmark containing two 30-candidate populations.

**Cross-tenant SAFE/UNSAFE:** semantics-preserving exact-identity rewrites versus lossy or
equivalence-expanding mutations such as normalization, prefix/suffix, truncation, and malformed-ID
permissiveness.

**Path-containment SAFE/UNSAFE:** semantically equivalent containment implementations using
`commonpath`, `relpath`, or separator-guarded prefix logic versus traversal-filter overfitting,
lexical-only checks, naive prefix checks, decode-once checks, resolved-only checks, and symlink-blind
variants.

Generator intent is never authoritative. A candidate enters SAFE or UNSAFE denominators only after
the independently qualified challenge oracle confirms that verdict.

The manifest pins the generator revision, base fixture digest, operator inventory, and every candidate source digest. The fixed benchmark has no seed field because candidate generation is not sampled; identical inventories therefore have one manifest identity. The case inventory is split into hash-frozen SAFE/UNSAFE data files so the executable measurement modules stay small and reviewable.


## Policy trade-off reference demo

Each offline reference demo evaluates one fixed 60-candidate benchmark against three intentionally
simplified policy revisions. Both challenges produce a monotone trade-off frontier under their own
hash-bound scope:

```text
cross-tenant:
  rev 1: 23 escapes / 30 unsafe,  0 overblocks / 30 safe
  rev 2:  3 escapes / 30 unsafe,  4 overblocks / 30 safe
  rev 3:  0 escapes / 30 unsafe, 21 overblocks / 30 safe

path-traversal:
  rev 1: 27 escapes / 30 unsafe,  0 overblocks / 30 safe
  rev 2:  6 escapes / 30 unsafe,  4 overblocks / 30 safe
  rev 3:  0 escapes / 30 unsafe, 14 overblocks / 30 safe
```

This is the point of the four-cell matrix: tightening a gate can reduce observed escapes while increasing legitimate-release blocking. All three revisions are measured under the same benchmark manifest and independently qualified oracle; each signed receipt carries a different policy SHA-256. The CLI additionally emits a common `comparison_scope_sha256`, so a copied trade-off point cannot lose the fixture/challenge/benchmark/oracle/runner context it was measured under. Because the exact same candidate IDs traverse all three policies, policy comparisons are paired rather than independent. The CLI additionally emits a self-contained signed comparison receipt (`release-sentinel.coverage-comparison-receipt.v1`, claim `SCOPED_PAIRED_POLICY_TRADEOFF`) that binds the common comparison scope, benchmark identity, policy hashes, frontier points, and McNemar diagnostics under `agent_authority=NONE`.

## Ordering protocol

Ordering is enforced as protocol state:

1. candidate and context are fixed;
2. candidate is build-valid;
3. gate evaluates;
4. Recorder creates and signs `GateSnapshot(sequence=1, oracle_result_present=false)`;
5. Oracle verifies that signed snapshot and matching context;
6. Oracle evaluates and signs `OracleResult(sequence=2)` containing the Gate Snapshot digest;
7. Assessor classifies and aggregates;
8. final Coverage Receipt is signed.

An Oracle Result cannot be validly produced by the protocol helper without a valid signed Gate Snapshot. Tampered signatures and mismatched measurement contexts fail closed.

## Signing model

The core code exposes signing/verifying interfaces. Unit/reference runs use `HMAC_SHA256_TEST_ONLY`, deliberately labelled as non-production. Production design uses separate Cloud KMS keys for:

- Coverage Gate Snapshot signing;
- Coverage Oracle signing;
- final Coverage Receipt signing.

The existing release evidence/provenance keys are not reused for these purposes.

## Statistics

Raw counts are primary. For example:

```text
confirmed unsafe: 30
correctly blocked: 27
escapes: 3
```

Rates, when rendered, include numerator/denominator and Wilson 95% intervals. For the cross-tenant 30-per-class corpus the three policy points are:

| policy | escape rate (Wilson 95%) | overblock rate (Wilson 95%) |
| --- | --- | --- |
| rev 1 | 23/30 = 76.7% [59.1%, 88.2%] | 0/30 = 0.0% [0.0%, 11.4%] |
| rev 2 | 3/30 = 10.0% [3.5%, 25.6%] | 4/30 = 13.3% [5.3%, 29.7%] |
| rev 3 | 0/30 = 0.0% [0.0%, 11.4%] | 21/30 = 70.0% [52.1%, 83.3%] |

These intervals are reported for uncertainty transparency, not as a claim that the fixed operator corpus is a random sample from all possible patches. For revision comparisons the CLI additionally reports exact two-sided McNemar diagnostics over discordant candidate pairs: escape rev1→rev2 `20/0` (`p=1.9073486328125e-06`), rev2→rev3 `3/0` (`p=0.25`), rev1→rev3 `23/0` (`p=2.384185791015625e-07`); overblock rev1→rev2 `0/4` (`p=0.125`), rev2→rev3 `0/17` (`p=1.52587890625e-05`), rev1→rev3 `0/21` (`p=9.5367431640625e-07`). The six-test family is corrected with Holm-Bonferroni. Ordered adjusted-alpha thresholds are `0.008333333333333333`, `0.01`, `0.0125`, `0.016666666666666666`, `0.025`, and `0.05`; the first four nulls remain rejected after correction, while rev1→rev2 overblock (`p=0.125`) and rev2→rev3 escape (`p=0.25`) remain non-rejected. Therefore the end-to-end rev1→rev3 comparison is retained on both axes under family-wise correction. These are scoped diagnostics for the fixed hash-bound corpus, not population-wide significance claims. The deterministic benchmark supports reproducible comparison under its hash-bound scope; a receipt never claims that an observed rate is a universal security probability.


The independent path-traversal corpus is evaluated the same way. Its frontier is `27→6→0` escapes
and `0→4→14` overblocks. Paired exact McNemar discordant counts are: escape rev1→rev2 `21/0`
(`p=9.5367431640625e-07`), rev2→rev3 `6/0` (`p=0.03125`), rev1→rev3 `27/0`
(`p=1.4901161193847656e-08`); overblock rev1→rev2 `0/4` (`p=0.125`), rev2→rev3 `0/10`
(`p=0.001953125`), rev1→rev3 `0/14` (`p=0.0001220703125`). Holm-Bonferroni again leaves the
end-to-end changes rejected on both axes while the smaller rev2→rev3 escape and rev1→rev2
overblock steps remain non-rejected. These diagnostics are scoped only to the path challenge's own
fixed benchmark hash.

## Counterexample minimization

The bounded line-granularity minimizer accepts a reduction only if the supplied full escape predicate remains true. In production that predicate must encode all of:

- build-valid;
- Gate = GO;
- Oracle = UNSAFE.

Budget exhaustion is labelled `REDUCED_COUNTEREXAMPLE`, never “minimal”. Only a completed search receives `MINIMAL_UNDER_CONFIGURED_GRANULARITY`.

## Escape corpus and replay

Observed escapes can be stored as immutable, context-bound records. Historical replay classifies a previously known escape as blocked, regressed, or other under a later evaluation. An escape that again becomes `GO + UNSAFE` is a `COVERAGE_REGRESSION`.

## Hunt Lane

The Hunt Lane interface is intentionally non-statistical. Model output can provide `source` and `rationale` only. Attempts and newly observed escapes are reported separately from Benchmark Lane counts. Model payloads containing `oracle_verdict`, `classification`, `gate_decision`, receipt, signature, or authority fields are rejected.

AI authority remains `NONE`.

## Current implementation status

v2.3.0 currently contains the deterministic reference core and unit-tested trust protocol:

- qualified cross-tenant and path-traversal oracles;
- two versioned challenge manifests from distinct security families;
- separate 60-candidate deterministic benchmarks for each challenge (30 SAFE + 30 UNSAFE each);
- five-way classification;
- Wilson statistics;
- signed Gate Snapshot -> Oracle Result ordering;
- scoped signed Coverage Receipt;
- bounded minimizer;
- immutable escape corpus/replay;
- Hunt Lane authority boundary;
- invariant-agnostic shared reference runner/comparison core and `coverage-demo --challenge ...` CLI.

`REFERENCE_OFFLINE` is not a live-cloud proof. The separate Cloud Run Recorder/Oracle/Assessor deployment and real sandbox + signed-evidence Go Gatekeeper integration must be completed and live-proven before the project claims production Coverage Arena deployment.
