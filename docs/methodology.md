# Methodology

This document is written **before** the measurements exist, deliberately.

The whole strategic argument for this repository is that eclipse-resistance
proposals in libp2p have failed on evidence, not on merit — rust-libp2p issues
[#4769][4769] (Sybil defence) and [#1352][1352] (authenticated stratified
k-buckets) were both closed without landing anything. If the numbers here are
going to carry any weight, the protocol has to be fixed in advance so that
nobody — including the author — can tune the experiment until it says something
convenient.

Changes to this document after the first results land must be recorded in
`CHANGELOG.md` with a stated reason.

## Question

Does capping the number of routing-table entries per IP subnet meaningfully
raise the cost of an eclipse attack on a Kademlia DHT, and at what cost to
honest peers?

Three sub-questions, each with a pre-committed success criterion:

**Q1 — Does it work at all?** Under a fixed attacker budget, does contamination
of the victim's k-closest set fall when the diversity cap is enabled?
*Positive result:* contamination drops by more than 30 percentage points.
*Negative result worth publishing:* it drops by less than 10.

**Q2 — What does it cost the attacker?** How many distinct subnets must the
attacker control to restore the contamination level they achieved without the
cap? *This is the number that translates into money*, since subnets are rented
and CPU is not.

**Q3 — What does it cost honest peers?** What fraction of honest peers are
refused a routing table slot they would otherwise have received? A defence that
rejects a meaningful share of legitimate peers behind large ISPs or cloud
providers is not shippable regardless of how well it scores on Q1.

## Scenario matrix

| Scenario | Disjoint paths | Diversity cap | Periodic refresh |
|---|---|---|---|
| `baseline` | off | off | off |
| `disjoint` | on (d=3) | off | off |
| `diversity` | off | on | off |
| `hardened` | on (d=3) | on | off |
| `hardened-churn` | on (d=3) | on | on (30s) |

`hardened-churn` exists because raising the cost of the initial land grab is
worthless against a static routing table — grind once, squat forever. Periodic
re-randomisation is the part of that argument that needs no spec change.

## Metrics

1. **Contamination ratio** — attacker share of the victim's k-closest set for
   the target key, sampled on a fixed interval via
   `find_closest_local_peers`.
2. **Lookup success rate** — fraction of `GET_VALUE` queries returning the
   honest record.
3. **Time to first eclipse** — wall clock until contamination first reaches
   100%, if it ever does.
4. **Subnets required** — distinct subnets the attacker needed. Answers Q2.
5. **K-L detectability** — divergence of the observed closest-k CPL
   distribution from the geometric distribution expected in a uniformly
   populated network of the same size.

Metric 5 exists because the first four all price the *attacker's* effort and
none of them ask whether an honest node could tell it had been eclipsed. This
matters more than it sounds: a `GET_VALUE` eclipse never has to answer wrong.
The adversarial closest-set can simply report "no record", which is
indistinguishable to the resolver from a key nobody ever published. Detection
approach follows Cholez et al.; see [arXiv:2505.01139][arxiv] for a recent
application to the IPFS DHT.

## Controls and confounds

- **Fixed seeds.** Every run records the seed. A result that does not reproduce
  from its recorded seed is a bug report, not a finding.
- **Repetitions.** Each cell of the matrix runs *n* ≥ 10 times; report median
  and interquartile range, never a single run. DHT convergence is noisy enough
  that a single run will show whatever you hoped for.
- **Attacker budget held constant across scenarios.** Same grind trial count,
  same identity count. Only the defence changes.
- **Honest network size held constant within a sweep.** Contamination is
  sensitive to N; comparing across different N is comparing nothing.
- **Warm-up excluded.** Sampling starts only after the honest network's routing
  tables have converged, detected by polling for stability rather than by
  sleeping for a fixed duration. Fixed sleeps are the standard way this class of
  test produces results that are really just measurements of the sleep.

## Threats to validity

Stated up front so reviewers do not have to find them:

- **Simulated source addresses.** Milestone one assigns synthetic IPs over an
  in-process transport rather than using genuinely distinct network paths.
  This measures the *policy*, not the network. Any claim about real-world
  attacker cost has to wait for milestone two.
- **Uniform honest topology.** Real DHTs have heavily skewed address
  distributions — large cloud providers hold a disproportionate share of peers.
  A uniform honest network will *understate* the honest-peer rejection rate in
  Q3, which is the direction that flatters the defence. Note this in any
  writeup.
- **No churn in the honest set** for scenarios 1–4. Churn interacts with
  ledger release in ways that could plausibly dominate the effect being
  measured.
- **Single target key.** An attacker targeting many keys at once has different
  economics.

## What would falsify the hypothesis

Any of these, and the honest conclusion is that this defence is not worth
maintainer review budget — which is still a publishable result:

- Contamination under `diversity` within 10 points of `baseline`.
- `subnets_required` below roughly 10, i.e. within casual VPS-rental range.
- Honest-peer rejection above 5% under a realistic address distribution.

## Reporting

Raw JSON to `docs/results/<date>-<scenario>.json`, committed. Summary tables in
`docs/results/README.md`. No number appears in a blog post, issue, or PR that is
not backed by a committed result file.

[4769]: https://github.com/libp2p/rust-libp2p/issues/4769
[1352]: https://github.com/libp2p/rust-libp2p/issues/1352
[arxiv]: https://arxiv.org/abs/2505.01139
