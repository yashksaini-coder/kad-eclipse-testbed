#!/usr/bin/env python3
"""Regenerate the Phase 1 grind result file.

Phase 1 asks how cheaply an attacker can mint peer IDs that land closer to a
chosen key than any honest peer in the network. This script answers it the way
``docs/methodology.md`` demands: seeded runs for reproducibility, several
repetitions per trial count, and **median plus interquartile range** rather than
a single run.

Why medians of several statistics rather than one headline number
----------------------------------------------------------------
The obvious statistic — the single best CPL achieved — is the *maximum* of a
geometric sample, and maxima are noisy. Measured on this host, best-CPL has a
standard deviation of roughly 1.6-2.3 bits, so two honest runs of identical
configuration can differ by 5 bits. The ``mean_of_kept`` statistic (the mean CPL
across all ``--keep`` identities) has a standard deviation near 0.4 bits on the
same data: about five times tighter, because it averages the whole kept set
instead of reading off its extreme.

So this script records all three — ``best``, ``cpl_20th`` (the worst kept
identity) and ``mean_of_kept`` — and the write-up should quote ``mean_of_kept``
and ``cpl_20th``. ``best`` is colour, not evidence.

Usage
-----
    python3 scripts/phase1_grind.py --out docs/results/<date>-grind.json

    # faster smoke run
    python3 scripts/phase1_grind.py --plan 100000:3 --out /tmp/smoke.json

Each ``--plan`` entry is ``TRIALS:REPS``. Seeds are derived deterministically
from the trial count and repetition index, so re-running this script reproduces
the same identities and therefore the same numbers.
"""

from __future__ import annotations

import argparse
import json
import math
import platform
import statistics
import subprocess
import sys
from datetime import date, timezone, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BINARY = REPO_ROOT / "target" / "release" / "kad-eclipse-testbed"

# Fixed so the run is reproducible. Changing it changes every number.
TARGET = "kad-eclipse-testbed/phase1-target"
KEEP = 20  # libp2p's k

# Amino DHT size, from ProbeLab's published weekly crawl (unique peer IDs
# discovered). Used only to compute the analytic honest baseline below; Phase 2
# replaces this with a measured address distribution.
AMINO_PEERS = 11268


def seed_for(trials: int, rep: int) -> int:
    """Deterministic, well-spread seed. Distinct seeds give disjoint identity
    sets (verified: 5 seeds x 20 kept = 100 distinct peer IDs), so repetitions
    are independent samples."""
    return (trials * 0x9E3779B1 + rep * 0x85EBCA6B) & 0xFFFF_FFFF_FFFF_FFFF


def run_once(binary: Path, trials: int, seed: int) -> dict:
    proc = subprocess.run(
        [
            str(binary),
            "grind",
            "--target", TARGET,
            "--trials", str(trials),
            "--keep", str(KEEP),
            "--seed", str(seed),
            "--json",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(proc.stdout)


def summarise(values: list[float], ndigits: int = 2) -> dict:
    """Median, IQR, achieved standard error, and the raw values.

    ``methodology.md`` requires the median and IQR rather than a bare mean, and
    (as amended after Phase 1) the achieved standard error alongside it, so a
    reader can check whether the repetition count was sufficient instead of
    trusting it. ``raw`` is included so every summary statistic here can be
    recomputed from the file without re-running anything.
    """
    ordered = sorted(values)
    n = len(ordered)
    if n >= 4:
        q1, q3 = statistics.quantiles(ordered, n=4, method="inclusive")[0::2]
    else:
        q1, q3 = ordered[0], ordered[-1]
    sd = statistics.stdev(ordered) if n > 1 else 0.0
    return {
        "median": round(statistics.median(ordered), ndigits),
        "iqr": [round(q1, ndigits), round(q3, ndigits)],
        "min": round(ordered[0], ndigits),
        "max": round(ordered[-1], ndigits),
        "sd": round(sd, 3),
        "stderr": round(sd / (n**0.5), 3) if n > 1 else None,
        "n": n,
        "raw": [round(v, ndigits) for v in values],
    }


#: methodology.md: repetitions must achieve a standard error below this, on the
#: headline statistic, and never fewer than 5 reps.
STDERR_TARGET = 0.2
HEADLINE_STAT = "cpl_mean_of_kept"


def flag_undersampled(result: dict) -> dict:
    """Mark cells that missed the standard-error target.

    The repetition count is chosen up front but the achieved spread is only
    known afterwards, so the file has to say which cells actually cleared the
    bar. Without this the reader has to do the arithmetic to discover that a
    cell is provisional, which in practice means nobody does.

    Also records the reps that *would* have been needed, so re-running with an
    adequate plan is a lookup rather than a calculation.
    """
    provisional = []
    for cell in result["statistics"]["by_trials"]:
        stat = cell[HEADLINE_STAT]
        se = stat.get("stderr")
        if se is None or se <= STDERR_TARGET:
            continue
        needed = math.ceil((stat["sd"] / STDERR_TARGET) ** 2)
        cell["provisional"] = (
            f"Under-sampled: {HEADLINE_STAT} standard error {se} exceeds the "
            f"{STDERR_TARGET} target in docs/methodology.md. At the observed sd "
            f"of {stat['sd']}, {needed} repetitions would be needed; this cell "
            f"ran {cell['reps']}. Treat the medians here as indicative and do "
            f"not quote them to two decimals."
        )
        cell["reps_needed_for_stderr_target"] = needed
        provisional.append(cell["trials"])

    if provisional:
        result["provisional_cells"] = {
            "trials": provisional,
            "note": (
                "These cells did not reach the standard-error target. The "
                "headline findings must not depend on them; see `findings` for "
                "which cell each claim rests on."
            ),
        }
    return result


def derive_findings(result: dict) -> dict:
    """Compute the phase's claims from the measured cells.

    Derived rather than written by hand so the prose cannot drift from the
    numbers, and so each claim names the cell it rests on — which matters when
    some cells are provisional.
    """
    cells = result["statistics"]["by_trials"]
    base = result["honest_baseline"]
    closest = base["expected_cpl_closest_honest_peer"]
    twentieth = base["expected_cpl_20th_closest_honest_peer"]
    n_peers = base["n_peers"]
    keep = result["keep"]

    findings = []

    def first_where(pred):
        return next((c for c in sorted(cells, key=lambda c: c["trials"]) if pred(c)), None)

    # The strong claim: every kept identity closer than every honest peer.
    c = first_where(lambda c: c["cpl_20th"]["median"] > closest)
    if c:
        findings.append(
            {
                "claim": (
                    f"All {keep} ground identities land closer to the target than "
                    f"every one of the ~{n_peers:,} honest peers in the network."
                ),
                "evidence": (
                    f"At {c['trials']:,} trials the worst kept identity sits at CPL "
                    f"{c['cpl_20th']['median']} (IQR {c['cpl_20th']['iqr']}, "
                    f"se {c['cpl_20th']['stderr']}), above the closest honest peer's "
                    f"expected CPL of {closest}."
                ),
                "cost": f"{c['elapsed_s']['median']} s of one core, single-threaded",
                "rests_on_cell": c["trials"],
                "cell_is_provisional": "provisional" in c,
            }
        )

    # The weaker, cheaper claim: displaces the honest closest-k set.
    c = first_where(lambda c: c["cpl_20th"]["median"] > twentieth)
    if c:
        findings.append(
            {
                "claim": (
                    f"All {keep} ground identities outrank the honest {keep}th-closest "
                    f"peer, i.e. they would displace the entire honest closest-{keep} "
                    f"set for this key."
                ),
                "evidence": (
                    f"At {c['trials']:,} trials the worst kept identity sits at CPL "
                    f"{c['cpl_20th']['median']} against an expected {twentieth} for the "
                    f"honest {keep}th-closest."
                ),
                "cost": f"{c['elapsed_s']['median']} s of one core, single-threaded",
                "rests_on_cell": c["trials"],
                "cell_is_provisional": "provisional" in c,
            }
        )

    # Scaling. Theory: the grinder is sampling a geometric distribution, so each
    # 10x in trials should buy log2(10) ~= 3.32 bits. Worth stating because it
    # means cost grows exponentially in the bits gained.
    ordered = sorted(cells, key=lambda c: c["trials"])
    steps = []
    for prev, nxt in zip(ordered, ordered[1:]):
        ratio = nxt["trials"] / prev["trials"]
        gained = nxt[HEADLINE_STAT]["median"] - prev[HEADLINE_STAT]["median"]
        steps.append(
            {
                "from_trials": prev["trials"],
                "to_trials": nxt["trials"],
                "bits_gained": round(gained, 2),
                "bits_per_10x": round(gained / math.log10(ratio), 2),
            }
        )
    if steps:
        findings.append(
            {
                "claim": (
                    "Each 10x in grinding effort buys roughly log2(10) ~= 3.32 more "
                    "bits of common prefix, as a geometric sample predicts — so the "
                    "attacker's cost is exponential in the depth reached."
                ),
                "evidence": steps,
                "note": (
                    "Measured against theory, not fitted. A large deviation here "
                    "would indicate a bug in the grinder or a non-uniform keyspace."
                ),
            }
        )

    result["findings"] = findings
    return result


def analytic_baseline() -> dict:
    """Expected CPL of honest peers, for comparison.

    For N uniformly distributed IDs the count sharing >= j leading bits with a
    random target is N * 2^-j. Setting that to 1 gives the closest honest peer
    at j = log2(N); setting it to 20 gives the 20th closest at j = log2(N/20).
    """
    return {
        "network": "Amino DHT",
        "source": "ProbeLab weekly crawl - unique peer IDs discovered",
        "n_peers": AMINO_PEERS,
        "expected_cpl_closest_honest_peer": round(math.log2(AMINO_PEERS), 1),
        "expected_cpl_20th_closest_honest_peer": round(math.log2(AMINO_PEERS / 20), 1),
        "derivation": (
            "For N uniformly distributed IDs, the number with CPL >= j to a random "
            "target is N * 2^-j. Closest: j = log2(N). 20th closest: j = log2(N/20)."
        ),
        "caveat": (
            "Analytic, not crawled. Assumes uniform ID distribution, which holds "
            "for honest peers because peer IDs are hashes. Phase 2 replaces the "
            "address side of this with real crawl data."
        ),
    }


def rustc_version() -> str:
    try:
        out = subprocess.run(
            ["rustc", "--version"], capture_output=True, text=True, check=True
        )
        return out.stdout.strip()
    except Exception:
        return "unknown"


def pinned_channel() -> str:
    path = REPO_ROOT / "rust-toolchain.toml"
    try:
        for line in path.read_text().splitlines():
            if line.strip().startswith("channel"):
                return line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return "unknown"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--plan",
        action="append",
        default=None,
        help="TRIALS:REPS, repeatable. Default: 100000:10 1000000:10 10000000:5",
    )
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--binary", type=Path, default=DEFAULT_BINARY)
    args = parser.parse_args()

    plan = args.plan or ["100000:10", "1000000:10", "10000000:5"]
    parsed = []
    for entry in plan:
        trials_s, _, reps_s = entry.partition(":")
        parsed.append((int(trials_s), int(reps_s or "10")))

    if not args.binary.exists():
        print(
            f"binary not found at {args.binary} - run `cargo build --release` first",
            file=sys.stderr,
        )
        return 1

    by_trials = []
    for trials, reps in parsed:
        print(f"trials={trials} reps={reps} ...", file=sys.stderr, flush=True)
        best, worst, mean_kept, rate, elapsed, seeds = [], [], [], [], [], []
        for rep in range(reps):
            seed = seed_for(trials, rep)
            out = run_once(args.binary, trials, seed)
            cpls = [k["cpl"] for k in out["kept"]]
            if len(cpls) != KEEP:
                print(
                    f"  warning: kept {len(cpls)} identities, expected {KEEP}",
                    file=sys.stderr,
                )
            best.append(max(cpls))
            worst.append(min(cpls))
            mean_kept.append(statistics.mean(cpls))
            rate.append(out["rate_keypairs_per_s"])
            elapsed.append(out["elapsed_s"])
            seeds.append(seed)
            print(
                f"  rep {rep}: best={max(cpls)} worst={min(cpls)} "
                f"mean={statistics.mean(cpls):.2f}",
                file=sys.stderr,
                flush=True,
            )

        cell = {
            "trials": trials,
            "reps": reps,
            "seeds": seeds,
        }
        by_trials.append(
            {
                **cell,
                "cpl_mean_of_kept": summarise(mean_kept),
                "cpl_20th": summarise(worst),
                "cpl_best": summarise(best),
                "rate_keypairs_per_s": summarise(rate, 0),
                "elapsed_s": summarise(elapsed, 3),
            }
        )

    result = {
        "phase": 1,
        "question": (
            "How cheaply can an attacker produce peer IDs closer to a chosen key "
            "than the entire honest network?"
        ),
        "recorded": date.today().isoformat(),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "generated_by": "scripts/phase1_grind.py",
        "reproduce": (
            "cargo build --release && python3 scripts/phase1_grind.py --out <path>"
        ),
        "target": TARGET,
        "keep": KEEP,
        "environment": {
            "rustc": rustc_version(),
            "pinned_channel": pinned_channel(),
            "platform": platform.platform(),
            "processor": platform.processor() or "unknown",
            "threads": 1,
            "profile": "release",
            "libp2p": "0.57.0",
            "libp2p_kad": "0.49.0",
        },
        "statistics": {
            "note": (
                "Median and IQR per docs/methodology.md. Quote cpl_mean_of_kept and "
                "cpl_20th; cpl_best is a maximum and is roughly 5x noisier."
            ),
            "by_trials": by_trials,
        },
        "honest_baseline": analytic_baseline(),
        "caveats": [
            "Single-threaded. Grinding is embarrassingly parallel, so a real "
            "attacker multiplies throughput by core count and again by renting "
            "machines. Every cost figure here is therefore an upper bound on the "
            "attacker's time.",
            "cpl_best is the maximum of a geometric sample; on this host its "
            "standard deviation is 1.6-2.3 bits. Two identical configurations can "
            "differ by 5 bits. Do not quote it as a point estimate.",
            "The honest baseline is analytic, not crawled. Phase 2 replaces the "
            "address distribution with real Amino DHT data.",
            "Measured on whatever rustc the environment reports above. If that "
            "differs from pinned_channel, re-run on the pinned toolchain before "
            "citing externally - the numbers have not been shown to be "
            "toolchain-independent.",
        ],
    }

    result = flag_undersampled(result)
    result = derive_findings(result)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    print(f"wrote {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
