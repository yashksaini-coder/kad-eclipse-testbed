# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project does not yet follow semantic versioning; it is pre-`0.1.0`.

## [Unreleased]

### Added
- `attack::TargetedIdGenerator` — grinds Ed25519 keypairs toward a target
  Kademlia key using a bounded max-heap.
- `TargetedIdGenerator::seed(u64)` — deterministic grinding via a hand-written
  SplitMix64 expanded into 32-byte Ed25519 secrets, so a run reproduces
  exactly. Verified unbiased against OS randomness: on the tight statistics the
  two are indistinguishable (20th-best CPL 10.75 seeded vs 10.79 unseeded;
  mean-of-kept 12.04 vs 12.14, z = −0.88, n = 24 each at 50k trials). Distinct
  seeds also produce disjoint identity sets — 5 seeds × 20 kept gave 100
  distinct peer IDs — so seeds `0..n` are valid independent repetitions.
- `grind --json` — machine-readable output carrying the seed and the CPL of
  every kept identity, not just the best.
- `scripts/phase1_grind.py` — regenerates the Phase 1 result file from seeded
  runs. Result files are now generated rather than hand-transcribed.
- `policy` — subnet grouping with hand-rolled global-routability checks,
  plus `AdmissionLedger` enforcing per-bucket and table-wide caps.
- `filter::SubnetDiversityFilter` — reference `NetworkBehaviour` gating
  insertion on `BucketInserts::Manual`. Explicitly not a stable API.
- `metrics::kl_divergence_cpl` — Cholez-style eclipse detectability estimator.
- `docs/methodology.md` — pre-registered measurement protocol.
- `docs/threat-model.md` — attacker model and prior art.
- `docs/dev-plan.md` — phased plan ordered by value per unit of effort.
- CI jobs `results-regenerate` and a `grind --json` schema assertion, so the
  path from binary to committed result file cannot rot unnoticed.

### Changed
- Bumped `libp2p` 0.56 → 0.57 (`libp2p-kad` 0.48 → 0.49) and the toolchain pin
  1.88.0 → 1.98.1; MSRV raised 1.83 → 1.88 to match kad 0.49. The facade now
  resolves `libp2p-identity` 0.3.0 transitively, inverting the old identity-pin
  note in `Cargo.toml`. `cargo check` is green and the bump introduced no new
  test or clippy failures — but the kad 0.49 `BucketInserts::Manual` event
  contract still needs the by-hand review `CONTRIBUTING.md` requires, since a
  semantic change there would not break compilation.
- `rust-toolchain.toml` is now the single source of truth for the compiler
  version in CI. A `toolchain` job parses its channel and every other job
  consumes that output, so no workflow file names a version of its own.

### Fixed
- CI jobs `clippy`, `test` and `grind-smoke` hardcoded `toolchain: "1.88.0"`
  while `rust-toolchain.toml` pinned `1.98.1`. Those lines were dead — rustup
  honours `rust-toolchain.toml` over whatever the action installs — so CI had
  been running on a compiler none of its own configuration named, and was green
  by accident rather than by design. `fmt` and `docs` used `@stable` with the
  same effect.
- Stale status claims in `README.md`, `CHANGELOG.md` and
  `docs/results/README.md` asserting that nothing had been measured and that
  `make all` was failing. `make all` has been green since `264e4dd`.

### Corrected
- `docs/results/2026-09-29-grind.json` is superseded by
  `docs/results/2026-10-19-grind.json` and now carries a `superseded_by`
  pointer. Two defects, neither of which changed the finding:
  - It reported `best_cpl_bits` from a **single run per trial count**.
    `best_cpl` is the maximum of a geometric sample; measured on this host its
    standard deviation is 1.6–2.3 bits, so two identical configurations can
    differ by 5 bits. The apparent disagreement between the recorded 17/19 and
    the independent reproduction's 16/22 noted in `ae9045a` was never a
    discrepancy — it was the metric. The headline is now `cpl_mean_of_kept`
    (sd ≈ 0.4 bits) and `cpl_20th`, with `cpl_best` kept as colour.
  - Its numbers were hand-transcribed from stdout, which `docs/results/README.md`
    forbids. The replacement is emitted by `scripts/phase1_grind.py`.
- The CPL figures quoted in `ae9045a`'s commit message had no result file
  behind them, also against the rule in `docs/results/README.md`. The
  superseding run records every seed, so any figure is now traceable.

### Not yet implemented
- `testbed::run` returns an error. The scenario matrix is defined; the harness
  is not built. See Phase 4 in `docs/dev-plan.md`.

### Methodology
- `docs/methodology.md` repetition rule amended 2026-10-19, after Phase 1, per
  the `CONTRIBUTING.md` requirement that post-result methodology changes carry a
  stated reason. `n = 10` was picked before any statistic's spread was known.
  The floor is now "enough repetitions for a standard error below 0.2 bits,
  never fewer than 5", with the achieved standard error reported alongside every
  median so a reader can check the choice. Result cells below `n = 10` must say
  why in the file. This loosens the rule for tight statistics and tightens it
  for `cpl_best`, which would need well over 10 — a reason to stop quoting it.
