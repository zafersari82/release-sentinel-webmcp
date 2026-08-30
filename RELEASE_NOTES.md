# Release Sentinel v2.3.0 — Coverage Arena

v2.3.0 adds Coverage Arena, a separate measurement plane that quantifies where a fast production release gate diverges from a broader reference specification.

## Core thesis

**The oracle is the specification; the production gate is the cheap approximation.**

The oracle is intentionally allowed to be broader, slower, and more expensive than a normal per-commit gate. Coverage Arena measures that approximation gap under an exact hash-bound scope. It does not replace the existing release authority and it does not claim a universal “percent secure” score.

## New measurement core

- versioned `cross-tenant-authorization` and `path-traversal-containment` challenge manifests;
- qualified strict tenant-isolation oracle plus an independent path-containment oracle covering traversal encoding, separator, absolute-path, symlink-resolution, and prefix-collision cases;
- known-fixed / known-vulnerable oracle self-test;
- defined faulty oracle-rule mutants that must all be killed by the qualification suite;
- deterministic SAFE benchmark transforms and UNSAFE benchmark mutations;
- generator labels are non-authoritative: the oracle confirms actual SAFE/UNSAFE population membership;
- five-way result model: `CORRECT_ACCEPT`, `ESCAPE`, `OVERBLOCK`, `CORRECT_BLOCK`, `INVALID_CANDIDATE`;
- raw-count-first aggregation with Wilson 95% intervals as derived presentation data;
- exact measurement context binding for challenge, fixture, candidate, policy, benchmark, oracle, gatekeeper, runner, and nonce;
- signed Gate Snapshot -> Oracle Result ordering protocol;
- context/signature/tamper rejection;
- scoped Coverage Receipt with explicit `tested` and `not_tested` categories and `agent_authority=NONE`;
- bounded counterexample minimizer that never labels budget exhaustion as minimal;
- immutable escape corpus with deterministic IDs, deduplication, and historical regression replay;
- non-statistical Hunt Lane boundary that rejects model attempts to inject authoritative verdict/classification fields;
- invariant-agnostic shared reference runner/comparison core and `release-sentinel coverage-demo --challenge {cross-tenant,path-traversal}`.


## Review hardening checkpoint

- removed the unused benchmark `seed` from benchmark identity; deterministic inventories now have one manifest identity;
- expanded the fixed Benchmark Lane to **30 oracle-confirmed SAFE + 30 oracle-confirmed UNSAFE** candidates and moved the case inventory into hash-frozen data files;
- bumped the benchmark manifest/generator to `release-sentinel.coverage-benchmark.v3` / `cross-tenant-benchmark-v3`;
- added a third deliberately stricter reference policy revision over the exact same benchmark;
- reference policy rev 1 measures **23 escapes / 30 unsafe** and **0 overblocks / 30 safe**;
- reference policy rev 2 measures **3 escapes / 30 unsafe** and **4 overblocks / 30 safe**;
- reference policy rev 3 measures **0 observed escapes / 30 unsafe** and **21 overblocks / 30 safe**;
- `coverage-demo` renders all three signed scoped receipts and a self-contained `tradeoff` block containing the common comparison-scope SHA-256, benchmark SHA-256, raw counts, observed rates, Wilson 95% intervals, and exact paired McNemar comparisons over candidate IDs;
- exact McNemar results on the fixed corpus: escape rev1→rev2 `20/0` discordant (`p=1.9073486328125e-06`), rev2→rev3 `3/0` (`p=0.25`), rev1→rev3 `23/0` (`p=2.384185791015625e-07`); overblock rev1→rev2 `0/4` (`p=0.125`), rev2→rev3 `0/17` (`p=1.52587890625e-05`), rev1→rev3 `0/21` (`p=9.5367431640625e-07`);
- the six McNemar tests are corrected as one family with Holm-Bonferroni; all four previously rejected nulls remain rejected, while rev1→rev2 overblock and rev2→rev3 escape remain non-rejected; each comparison now records `holm_rank`, `adjusted_alpha`, and `reject_null_after_correction`;
- the full paired frontier is bound into `release-sentinel.coverage-comparison-receipt.v1` with claim `SCOPED_PAIRED_POLICY_TRADEOFF`, `agent_authority=NONE`, and a deterministic `HMAC_SHA256_TEST_ONLY` reference signature.

## Second-invariant generalization checkpoint

- added `path-traversal-containment`, a security family independent of authorization;
- path benchmark: **30 oracle-confirmed SAFE + 30 oracle-confirmed UNSAFE** candidates;
- path policy rev 1: **27 escapes / 30 unsafe**, **0 overblocks / 30 safe**;
- path policy rev 2: **6 escapes / 30 unsafe**, **4 overblocks / 30 safe**;
- path policy rev 3: **0 observed escapes / 30 unsafe**, **14 overblocks / 30 safe**;
- path McNemar/Holm end-to-end comparisons remain rejected on both escape and overblock axes;
- shared protocol typing no longer depends on `CrossTenantOracle`;
- shared runner now consumes a challenge definition rather than branching inside measurement logic;
- comparison/statistics/signing logic moved out of the CLI into `coverage/comparison.py`;
- benchmark model types moved to an acyclic shared module so challenge-specific benchmark providers do not create import cycles;
- existing production release authority files remain outside these changes.

## Reference benchmark result

The package-owned deterministic reference benchmark has 60 candidates: 30 oracle-confirmed SAFE and 30 oracle-confirmed UNSAFE. The same fixed benchmark is evaluated against three reference policy revisions:

- revision 1: 30 correct accepts, 0 overblocks, 7 correct blocks, 23 observed escapes;
- revision 2: 26 correct accepts, 4 overblocks, 27 correct blocks, 3 observed escapes;
- revision 3: 9 correct accepts, 21 overblocks, 30 correct blocks, 0 observed escapes;
- all revisions: 0 invalid candidates.

The three points expose a deterministic benchmark frontier: tightening the gate reduces observed escapes while increasingly rejecting oracle-confirmed safe changes. Because the same candidate IDs traverse every policy, the CLI also reports exact paired McNemar diagnostics instead of treating revisions as independent samples. On this fixed corpus the rev1→rev3 null is rejected on both escape and overblock directions, while the smaller rev2→rev3 escape step (`p=0.25`) and rev1→rev2 overblock step (`p=0.125`) are explicitly not rejected at alpha 0.05. Holm-Bonferroni family-wise correction leaves those conclusions unchanged. Wilson intervals and McNemar p-values are scoped diagnostics only: the benchmark is a fixed operator corpus rather than a random sample, so the project does not claim population-wide statistical significance.

## Authority and proof status

The existing release trust plane remains unchanged. Coverage Arena, the oracle, the benchmark generator, and Hunt Lane have zero release authority.

The current `coverage-demo` is explicitly `REFERENCE_OFFLINE` and uses `HMAC_SHA256_TEST_ONLY` signatures so local ordering and measurement behavior are reproducible without cloud credentials. Production Coverage Arena still requires separate Cloud Run Recorder/Oracle/Assessor wiring, purpose-separated Cloud KMS keys, a credentialless candidate sandbox, and a live proof against the real signed-evidence Go Gatekeeper path. No live-cloud Coverage Arena claim is made by this source checkpoint.

## Multi-challenge checkpoint verification

- Python: `245 passed` with AgentSeal on `PYTHONPATH`;
- Coverage-specific: `74 passed`;
- Go vet/race/build: PASS;
- reproducible wheel SHA-256: `7c1c8367ed5fe99e4c7afbe75195ae2936f14a5a7a7f5ad0160d7d47556c136f`;
- multi-challenge reference proof SHA-256: `bc81790397d57036a88a3d21d0f857cf82b0bad666e7be6590d0659f5e87b925`;
- production trust-plane six-file byte comparison against v2.2.6 FINAL: UNCHANGED.
