# Release Sentinel v2.3.0 — verification checkpoint

Generated: 2026-08-22

## Local checkpoint

Coverage Arena was implemented from the clean v2.2.6 FINAL source tree and hardened through repeated adversarial review. This checkpoint adds a second invariant, path traversal containment, without modifying the production release-authority trust plane.

Current verified results:

- Python suite: **245 passed, 0 failed, 0 skipped** using `PYTHONPATH=src:packages/agentseal/src`;
- Coverage-specific suite: **74 passed**;
- existing release trust-kernel hash check: **PASS**;
- separate Coverage measurement-kernel hash check: **PASS**;
- architecture import-cycle and bounded-module checks: **PASS**;
- Go Gatekeeper: `go vet ./...`, `go test -race ./...`, and `go build -trimpath ./...`: **PASS**;
- Python byte compilation and shell syntax checks: **PASS**;
- reproducible wheel build via `pip wheel --no-build-isolation`: two builds with `SOURCE_DATE_EPOCH=1787356800` were byte-identical;
- wheel SHA-256: `7c1c8367ed5fe99e4c7afbe75195ae2936f14a5a7a7f5ad0160d7d47556c136f`;
- wheel contains both challenge manifests and all four SAFE/UNSAFE benchmark data files;
- multi-challenge reference proof artifact: `challenge/verification/COVERAGE_ARENA_REFERENCE_PROOF_2026-08-22.json`;
- proof SHA-256: `bc81790397d57036a88a3d21d0f857cf82b0bad666e7be6590d0659f5e87b925`;
- six production trust-plane files are byte-identical to v2.2.6 FINAL: release engine, evidence model, judge, remediation service, Go verdict, and Go attestation.

## Challenge 1 — cross-tenant authorization

- benchmark manifest SHA-256: `d065f4ea6d8411a0a274b1c73ee632d778cfde39ea21d517b0da7731ecb93cf4`;
- common comparison-scope SHA-256: `9c992a6b2d5ceb160551178108237585074193fa0ebb9bb343f56b49bff32884`;
- population: **30 oracle-confirmed SAFE + 30 oracle-confirmed UNSAFE**;
- policy rev 1: **30 correct accepts, 0 overblocks, 7 correct blocks, 23 escapes, 0 invalid**;
- policy rev 2: **26 correct accepts, 4 overblocks, 27 correct blocks, 3 escapes, 0 invalid**;
- policy rev 3: **9 correct accepts, 21 overblocks, 30 correct blocks, 0 observed escapes, 0 invalid**;
- paired exact McNemar: escape `1→2 20/0 p=1.9073486328125e-06`, `2→3 3/0 p=0.25`, `1→3 23/0 p=2.384185791015625e-07`; overblock `1→2 0/4 p=0.125`, `2→3 0/17 p=1.52587890625e-05`, `1→3 0/21 p=9.5367431640625e-07`;
- six-test Holm-Bonferroni correction leaves the same four nulls rejected and the two smaller adjacent changes non-rejected.

## Challenge 2 — path traversal containment

- challenge id: `path-traversal-containment`;
- benchmark manifest SHA-256: `cdcb780afac3aa5f9b8283d52a3f02cf7e50d3cb170225630abc3673d2021e67`;
- common comparison-scope SHA-256: `6c8491a998730448faf56b7b2c4fce011fe9c38c2b9f9b97da765cdb18dabc4f`;
- population: **30 oracle-confirmed SAFE + 30 oracle-confirmed UNSAFE**;
- oracle scope includes lexical containment, selected encoded traversal, backslash traversal, absolute-path rejection, resolved-target containment, symlink-escape simulation, malformed requests, and prefix collisions;
- policy rev 1: **30 correct accepts, 0 overblocks, 3 correct blocks, 27 escapes, 0 invalid**;
- policy rev 2: **26 correct accepts, 4 overblocks, 24 correct blocks, 6 escapes, 0 invalid**;
- policy rev 3: **16 correct accepts, 14 overblocks, 30 correct blocks, 0 observed escapes, 0 invalid**;
- paired exact McNemar: escape `1→2 21/0 p=9.5367431640625e-07`, `2→3 6/0 p=0.03125`, `1→3 27/0 p=1.4901161193847656e-08`; overblock `1→2 0/4 p=0.125`, `2→3 0/10 p=0.001953125`, `1→3 0/14 p=0.0001220703125`;
- after six-test Holm-Bonferroni correction, the end-to-end escape and overblock changes remain rejected; rev2→rev3 escape and rev1→rev2 overblock remain non-rejected.

## Framework-generalization result

The second challenge is from a different security family and still uses the same shared ordering, classification, scope binding, paired statistics, Holm family correction, and signed comparison receipt. During implementation, two challenge-specific couplings were exposed and removed: shared benchmark types were split into an acyclic module, the oracle protocol was made invariant-agnostic, the reference runner now consumes challenge definitions, and comparison/statistics/signing logic moved out of the CLI into `coverage/comparison.py`.

The challenge-specific semantics remain isolated to challenge/oracle/benchmark/reference-policy providers and data files. No production release-authority code was modified.

## What these local results prove

They verify the deterministic measurement core on **two distinct invariants**, oracle qualification, benchmark determinism, classification math, sealed gate-before-oracle ordering, scope binding, signed comparison receipts, paired exact McNemar diagnostics, Holm-Bonferroni family correction, minimizer budgets, corpus/replay semantics, and Hunt authority boundaries.

They do **not** prove a live production Coverage Arena deployment. Both demos are `REFERENCE_OFFLINE` and use `HMAC_SHA256_TEST_ONLY`. The cloud phase still requires separate Cloud Run Recorder/Oracle/Assessor identities, purpose-separated Cloud KMS keys, credentialless candidate execution, and a live proof against the real signed-evidence Go Gatekeeper path.

## Existing v2.2.6 cloud proof

The prior release cloud proof remains retained at `challenge/verification/GCP_CLOUD_TRUST_PROOF_2026-08-21.txt`. It proves the existing release trust plane, not the new Coverage Arena cloud plane.
