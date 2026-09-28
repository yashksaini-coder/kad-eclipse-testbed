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

### Not yet implemented
- `testbed::run` returns an error. The scenario matrix is defined; the harness
  is not built.

### Notes
- Nothing in this repository has been compiled. It was written against the
  `libp2p-kad-v0.48.0` source tree rather than from memory, but `make check` is
  the first task.
