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
- The scaling claim was wrong. `ae9045a` recorded "each 10x in trials buys
  roughly 2 more bits", read off three single-sample `best_cpl` values
  (17/19/21). Properly measured, the headline statistic gains **+3.72 and +3.40
  bits per 10x**, bracketing the log2(10) ≈ 3.32 that a geometric sample
  predicts. The old figure was not a measurement of the attacker's scaling but
  of three draws from a high-variance statistic that happened to land two apart.
  The agreement with theory now serves as a sanity check on the grinder.

### Fixed (correctness)
- `SubnetDiversityFilter` discarded `add_address`'s `RoutingUpdate` and counted
  every admitted peer in the ledger regardless of whether kad actually seated
  it. `RoutablePeer` is emitted for two reasons — `BucketInserts::Manual` being
  configured **or** the bucket being full — so admission is a request, not a
  conclusion. On the bucket-full path the ledger inflated that subnet's
  occupancy and would then refuse legitimate peers from it, causing exactly the
  harm the filter exists to prevent. The ledger slot is now released when kad
  reports `Pending` or `Failed`. Covered by
  `ledger_releases_when_kad_declines_to_seat_the_peer`, verified to fail without
  the fix.

### Corrected (claims about other projects)
Audit of every statement this repository makes about rust-libp2p. Four were
wrong or unsupportable:
- **"Eclipse-resistance proposals in rust-libp2p have failed on evidence, not
  on merit."** Removed from `README.md` and `docs/methodology.md`. This
  attributed a motive for the closure of issues #4769 and #1352 that the public
  threads do not record. That two issues closed without a defence landing is
  checkable; *why* is not, and is no longer asserted.
- **"As of September 2026 it has had no non-dependabot merge in over five
  weeks."** Removed from `README.md` and `docs/dev-plan.md`. False as of
  2026-10-23: `master` has taken roughly fourteen human merges in the preceding
  ten days from seven or more contributors, including external ones, and
  shipped v0.57.1 on 2026-10-15. The scheduling conclusion it supported —
  nothing here is sequenced behind an upstream decision — stands on its own and
  needs no claim about anyone's velocity.
- **"rust-libp2p — nothing"** in `docs/threat-model.md`'s prior-art list, and
  the README table's "Eclipse testbed on real nodes: none". Scoped to the
  address level, which is what was meant. rust-libp2p has shipped disjoint
  lookup paths — the other S/Kademlia counter — since v0.20.0 and tests it
  against an adversary in `s_kademlia_disjoint_paths` and
  `disjoint_query_does_not_finish_before_all_paths_did`. What is absent is a
  defence on *placement*, not attention to the threat.
- **"an observable implementation detail, not a documented contract"** about
  `BucketInserts::Manual` / `Event::RoutablePeer`, in `README.md` and
  `src/filter.rs`. False: both are documented in kad's public rustdoc, which
  states that under `Manual` peers enter the table only via `add_address` and
  that `RoutablePeer` means the peer has not been added. The real caveats —
  documented behaviour is not a stability guarantee, and a semantic change would
  not fail to compile — are now stated accurately, and the second is why
  `libp2p` is held back from automated dependency bumps.

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
