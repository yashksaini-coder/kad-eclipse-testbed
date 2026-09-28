# Development plan

Phases are ordered by **value per unit of effort**, not by architectural
dependency. Each has an exit criterion and a deliverable that stands alone. If
work stops after any phase, everything before it is still worth something.

That ordering is deliberate. The most valuable measurement in this project does
not require the testbed to exist, and the testbed is the most expensive thing
here. Building in dependency order would put the cheap answer last.

## Who this is for

The primary customer is **py-libp2p**, not rust-libp2p.

py-libp2p `main` currently ships `MAX_PEERS_PER_SUBNET = 2`,
`SUBNET_PREFIX_LEN_V4 = 24`, `SUBNET_PREFIX_LEN_V6 = 48` (PR #1399) and a
table-wide cap defaulting to `0` (PR #1442). Every one of those values was
chosen by argument. go-libp2p uses `/16` and `maxForTable=3`. This repository's
scaffold picked `6`. Three implementations, three answers, no data.

rust-libp2p is option value. As of September 2026 it has had no non-dependabot
merge in over five weeks; `libp2p-kad` has since moved 0.48.0 → 0.49.0 (in
`libp2p 0.57`), which this crate now builds against, but nothing here should be
sequenced behind an upstream decision regardless.

---

## Phase 0 — Make it compile

**Effort:** half a day. **Partly done.**

`cargo check --all-targets` is green against `libp2p 0.57` / `libp2p-kad 0.49.0`
on Rust 1.98.1 — the `NetworkBehaviour` delegation in `src/filter.rs`, flagged
here as the least certain part, compiled without changes. What remains for
`make all`:

- `cargo fmt` — formatting drift in all four `.rs` files
- one `clippy` lint — `large_enum_variant` on `filter::Event` (`Kad(kad::Event)`
  is ≥320 bytes; box it or `#[allow]`)
- two `policy` tests — `groups_public_ipv4_by_prefix` and
  `wider_prefix_collapses_more_peers_into_one_group` assert on RFC 5737
  documentation ranges (203.0.113.0/24, 198.51.100.0/24) that `policy.rs`
  correctly treats as exempt, so `subnet_of` returns `None`. The fixtures need
  genuinely-routable example addresses, not the test-net ranges.

**Exit:** `make all` green. **Deliverable:** a repository that builds and passes
its own gate.

---

## Phase 1 — The premise number

**Effort:** half a day after Phase 0.

`cargo run --release -- grind --trials 10000000`. How many targeted identities
per second, and what common-prefix-length does that buy against a network of
~11k peers?

This is the number that makes the rest of the argument land, and it needs no
network, no testbed, and no defence implemented.

**Exit:** a committed result file and one sentence of the form "an attacker can
produce a full k-bucket of identities targeting any key in N seconds on a
laptop." **Deliverable:** the threat is quantified rather than asserted.

---

## Phase 2 — Honest-peer rejection against the real network

**Effort:** a weekend. **No Rust required.**

This is the highest-value phase and it is deliberately second, because it is
cheap and because it is the one most likely to find a bug in code that is
already merged and shipping.

Q3 in `methodology.md` asks what fraction of legitimate peers a subnet cap
wrongly refuses. That can be answered directly against the Amino DHT rather
than against a synthetic network:

1. Get a crawl snapshot. [Nebula][nebula] (ProbeLab) walks the DHT recursively
   through k-buckets and records the addresses peers advertise; it supports a
   JSON storage backend. Alternatively use ProbeLab's published weekly data.
2. Group peers by `/24` and `/48`, applying the same exemption rules as
   `policy.rs` — only globally-routable addresses count.
3. Count how many peers would be refused under `MAX_PEERS_PER_SUBNET = 2`.
   Repeat for `/16` to get the go-libp2p comparison.
4. Report the distribution, not just the mean. A handful of very large groups
   behind cloud providers will dominate, and that shape is the finding.

**Why this matters more than it looks:** `methodology.md` lists uniform honest
topology as a threat to validity, and notes it biases in the direction that
*flatters* the defence. Real crawl data removes that objection entirely, and
the resulting distribution can seed the testbed's honest network in Phase 4.

**Exit:** a committed dataset and a rejection-rate figure for `/16`, `/24` and
`/48`. **Deliverable:** an answer to Q3 that is about the real network, and a
direct check on whether py-libp2p's shipped defaults are safe.

**Kill condition:** if rejection under `/24` + cap 2 exceeds ~5%, that is a
regression in merged py-libp2p code and it becomes the priority. File it there
before continuing here.

---

## Phase 3 — Cross-implementation conformance vectors

**Effort:** a day.

A shared JSON fixture set of `(multiaddr, expected_subnet_key)` pairs that both
`policy.rs` and py-libp2p's `_subnet_key()` run against.

This exists because the two implementations already diverge — py-libp2p takes
the first globally-routable address, go-libp2p inspects every advertised
address. Without fixtures, any claim that a Rust measurement transfers to the
Python implementation rests on argument. With them, it rests on a passing test.

Vectors should cover: public v4 and v6, RFC1918, CGNAT (100.64/10), loopback,
link-local, unique-local (fc00::/7), IPv4-mapped v6, documentation ranges,
DNS-named, and `/p2p-circuit` relayed.

**Exit:** both implementations pass the same file. **Deliverable:** a small,
genuinely upstream-friendly artifact that is useful to go-libp2p too, and that
costs a reviewer nothing to evaluate.

---

## Phase 4 — In-memory testbed

**Effort:** one to two weeks. The expensive phase.

Implement `testbed::run` per the plan in its doc comment.

- `/memory` transport first. The whole matrix should complete in seconds in one
  process before TCP is considered.
- Wire `identify` into every node. Under `BucketInserts::Manual` this is
  mandatory — without it no peer ever has an address and every arrival is
  `UnroutablePeer`.
- Poll for routing-table convergence rather than sleeping. Fixed sleeps produce
  results that are really measurements of the sleep.
- Seed the honest network's synthetic addresses from the Phase 2 distribution,
  not uniformly.
- Optional: `libp2p-metrics` 0.18 with the `kad` feature exposes
  `routing_updated` and query-result histograms through `prometheus-client`.
  Useful for watching a long run in Grafana. It is **not** the results path —
  committed JSON remains the source of truth.

**Exit:** `baseline` and `diversity` produce a contamination difference.
**Deliverable:** Q1 answered.

**Do not use a hosted APM (Sentry or otherwise) as the results path.** Sampled
or extrapolated aggregates are unusable for reporting ratios, retention is
bounded, and a vendor DSN in the measurement path makes the work
irreproducible by anyone else — which is the one thing this repository cannot
afford to give up.

---

## Phase 5 — Full matrix and statistics

**Effort:** a few days, mostly compute.

All five scenarios, n ≥ 10 repetitions each, seeds recorded. Report median and
IQR. A single run shows whatever you hoped for.

Then the sweep that settles a standing disagreement: `--prefix-v4 16` against
`--prefix-v4 24`, and table-wide `0` / `3` / `6`.

**Exit:** every cell populated, every number backed by a committed file.
**Deliverable:** Q2 answered, and a defensible recommendation for what
py-libp2p's defaults should actually be.

---

## Phase 6 — Publish

**Effort:** a few days.

1. Write it up. Negative results published the same as positive ones, per
   `methodology.md`.
2. If the data supports changing py-libp2p's defaults, open that PR. Known
   maintainers, existing merge history, short path.
3. Fix the stale comment in py-libp2p `common.py` claiming the table-wide cap
   "is tracked as a follow-up and not implemented here" — #1442 implemented it.
   One line, and it is your own comment.
4. Only now, the rust-libp2p question, with numbers attached. Draft is written;
   ask whether a bucket-admission hook is in scope, not for a design review.
5. Consider `discuss.libp2p.io` over a repo issue for the research artifact —
   it reaches go-libp2p and ProbeLab people too, and this is cross-
   implementation work.

---

## Standing rules

- No number appears anywhere without a committed file in `docs/results/`.
- `methodology.md` changes after results exist require a stated reason in
  `CHANGELOG.md`.
- Phases 0–3 are independently publishable. Phase 4 is the only one that can
  swallow weeks, and it is deliberately positioned so that abandoning it still
  leaves three shipped results behind.

## Honest risk

The author's attention is currently on WebRTC-Direct interop in py-libp2p,
which is shipping. This is not. Phases 0–3 are scoped so that the project
produces something publishable within a few weekends; if it stalls after that,
it should stall having answered a real question rather than half-built.

[nebula]: https://github.com/dennis-tra/nebula
