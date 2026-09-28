## What and why

<!-- What changes, and what problem it solves. Not a restatement of the diff. -->

## Type

- [ ] `feat` — new capability
- [ ] `fix` — corrects wrong behaviour
- [ ] `docs`
- [ ] `test`
- [ ] `chore` / `deps`
- [ ] **`measurement`** — changes how a number is computed. Fill the section below.

## Measurement impact

<!-- Required if this touches src/metrics.rs, src/testbed.rs, or methodology.md.
     Delete otherwise. -->

- Metric affected:
- Value before / after:
- Why the new value is more correct (not merely different):
- Does this invalidate an already-published result? If yes, note it in
  `CHANGELOG.md` under `Corrected`.

## Checklist

- [ ] `make all` passes
- [ ] Tests added, and they would fail if the logic were wrong (not just if it panicked)
- [ ] Any dependency on rust-libp2p internals is commented with the version verified against
- [ ] `CHANGELOG.md` updated for user-facing changes
- [ ] No number quoted without a committed file in `docs/results/` behind it
