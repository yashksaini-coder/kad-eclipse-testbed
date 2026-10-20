# Results

Raw JSON, one file per measurement, named `<date>-<phase-or-scenario>.json` and
committed with the seeds it used.

**No number appears in a README, issue, PR, or blog post without a file in this
directory behind it.** That rule is the reason the repository is worth anyone's
attention; the moment it is broken, this becomes another unsubstantiated
proposal on the pile. It applies to commit messages too — `ae9045a` quoted CPL
figures with no file behind them, which is how the rule gets eroded.

Files are **generated, not transcribed**. `scripts/phase1_grind.py` emits the
Phase 1 file from `grind --json`; `testbed run --output` will emit the scenario
files once Phase 4 exists. A hand-copied console paste is not a result.

## Phase 1 — cost of a targeted identity

[`2026-10-19-grind.json`](2026-10-19-grind.json) · regenerate with
`cargo build --release && python3 scripts/phase1_grind.py --out <path>`

Median across seeded repetitions; see the file for IQR, per-rep seeds and the
full environment. `cpl` is common-prefix length with the target in bits — higher
means a closer landing.

| trials | reps | time (s) | mean CPL of kept 20 | 20th-best CPL | best CPL |
|---|---|---|---|---|---|
| 100,000 | 10 | 1.76 | 12.88 (se 0.16) | 12.0 (se 0.15) | 16.0 (se 0.50) |
| 1,000,000 | 10 | 19.14 | 16.60 (se 0.16) | 15.0 (se 0.10) | 20.0 (se 0.89) |
| 10,000,000 † | 5 | 187.03 | 20.00 (se 0.25) | 19.0 (se 0.25) | 25.0 (se 0.81) |

Throughput held at 52,000–57,000 keypairs/sec across all cells, single-threaded
on a 2.1 GHz Xeon vCPU.

Compare against the honest network: for N uniformly distributed peer IDs the
closest honest peer to a random key sits at CPL ≈ log2(N) and the 20th closest
at ≈ log2(N/20). For the Amino DHT's ~11,268 peers that is **13.5** and **9.1**.

So the two claims the file derives, each naming the cell it rests on:

- **1.8 s** (100k cell): all twenty ground identities outrank the honest
  20th-closest peer — they displace the entire honest closest-20 set.
- **19.1 s** (1M cell): the *worst* of the twenty outranks the *closest* honest
  peer in the network. Every honest peer is now further from the key than every
  attacker peer.

Neither claim depends on the provisional 10M cell.

Measured scaling is +3.72 and +3.40 bits per 10× in effort, bracketing the
log2(10) ≈ 3.32 that a geometric sample predicts. That agreement is a sanity
check on the grinder: a large deviation would mean a bug or a non-uniform
keyspace rather than a finding.

### † Why the 10M cell is provisional

Its standard error on the headline statistic is 0.25, above the 0.2 target in
[`../methodology.md`](../methodology.md). At the observed sd of 0.558 it would
need 8 repetitions; it ran 5. The generator flags this automatically — a cell
that misses the bar says so in the file rather than leaving the reader to do
the arithmetic. The medians are indicative; don't quote them to two decimals,
and don't build a claim on them.

### Which statistic to quote

`cpl_mean_of_kept` and `cpl_20th`. **Not `cpl_best`.**

`cpl_best` is the maximum of a geometric sample. Measured on this host its
standard deviation is 1.6–2.3 bits, so two runs of an identical configuration
can differ by 5 bits — which is exactly how the superseded Sep 29 file came to
disagree with its own independent reproduction. `cpl_mean_of_kept` averages the
whole kept set instead of reading off its extreme and lands near 0.4 bits, about
five times tighter. `cpl_best` is colour; the other two are evidence.

This is also why the 10M cell runs 5 repetitions rather than 10. The `n ≥ 10`
rule in [`../methodology.md`](../methodology.md) was written with the noisy
statistic in mind; for the tight ones, 5 gives a standard error under 0.2 bits.

### Seeded runs are unbiased

Worth stating because everything downstream depends on it. A seeded generator
that sampled differently from OS randomness would bias every later result. It
does not: at 50k trials with n = 24 each, 20th-best CPL came out 10.75 seeded
against 10.79 unseeded, and mean-of-kept 12.04 against 12.14 (z = −0.88).
Distinct seeds also give disjoint identity sets — 5 seeds × 20 kept produced 100
distinct peer IDs — so seeds `0..n` are independent repetitions rather than
correlated draws.

Mechanism agrees: Ed25519 key derivation SHA-512s the seed before deriving the
scalar, which destroys any structure the PRNG had.

## Superseded

- [`2026-09-29-grind.json`](2026-09-29-grind.json) — single run per trial count,
  hand-transcribed, led with `cpl_best`. Retained unaltered with a
  `superseded_by` pointer. Its finding was not wrong, only imprecisely measured;
  deleting it would hide the correction rather than record it.
