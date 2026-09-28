# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project does not yet follow semantic versioning; it is pre-`0.1.0`.

## [Unreleased]

### Added
- `attack::TargetedIdGenerator` — grinds Ed25519 keypairs toward a target
  Kademlia key using a bounded max-heap.
- `policy` — subnet grouping with hand-rolled global-routability checks,
  plus `AdmissionLedger` enforcing per-bucket and table-wide caps.
- `filter::SubnetDiversityFilter` — reference `NetworkBehaviour` gating
  insertion on `BucketInserts::Manual`. Explicitly not a stable API.
- `metrics::kl_divergence_cpl` — Cholez-style eclipse detectability estimator.
- `docs/methodology.md` — pre-registered measurement protocol.
- `docs/threat-model.md` — attacker model and prior art.

### Changed
- Bumped `libp2p` 0.56 → 0.57 (`libp2p-kad` 0.48 → 0.49) and the toolchain pin
  1.88.0 → 1.98.1; MSRV raised 1.83 → 1.88 to match kad 0.49. The facade now
  resolves `libp2p-identity` 0.3.0 transitively, inverting the old identity-pin
  note in `Cargo.toml`. `cargo check` is green and the bump introduced no new
  test or clippy failures — but the kad 0.49 `BucketInserts::Manual` event
  contract still needs the by-hand review `CONTRIBUTING.md` requires, since a
  semantic change there would not break compilation.

### Not yet implemented
- `testbed::run` returns an error. The scenario matrix is defined; the harness
  is not built.

### Notes
- The crate compiles (`cargo check` green). `make all` is not yet green: `cargo
  fmt`, one `clippy` lint, and two `policy` tests remain — see Phase 0 in
  `docs/dev-plan.md`.
