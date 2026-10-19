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


def analytic_baseline() -> dict:
    """Expected CPL of honest peers, for comparison.

    For N uniformly distributed IDs the count sharing >= j leading bits with a
    random target is N * 2^-j. Setting that to 1 gives the closest honest peer
    at j = log2(N); setting it to 20 gives the 20th closest at j = log2(N/20).
    """
    import math

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
        if reps < 10:
            cell["reps_below_10_because"] = (
                "methodology.md sets the floor at enough repetitions for a "
                "standard error below 0.2 bits, never fewer than 5. Check "
                "cpl_mean_of_kept.stderr below: if it exceeds 0.2 this cell is "
                "under-sampled and needs more reps."
            )
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

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    print(f"wrote {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
