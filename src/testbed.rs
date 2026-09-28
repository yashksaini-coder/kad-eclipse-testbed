//! The testbed: five scenarios, real rust-libp2p nodes.
//!
//! # Scenario matrix
//!
//! | Scenario        | `disjoint_query_paths` | `SubnetDiversityFilter` | periodic refresh |
//! |-----------------|------------------------|-------------------------|------------------|
//! | `baseline`      | false                  | off                     | off              |
//! | `disjoint`      | true                   | off                     | off              |
//! | `diversity`     | false                  | on                      | off              |
//! | `hardened`      | true                   | on                      | off              |
//! | `hardened-churn`| true                   | on                      | **on**           |
//!
//! The fifth row is Valentyn Kit's point applied without the crypto-puzzle:
//! whatever raises the cost of the initial land grab, a static routing table
//! means the attacker grinds once and squats forever. Periodic bucket
//! re-randomisation is the part of that argument that does not need a spec
//! change, so it deserves its own row rather than being folded into `hardened`.

use std::{str::FromStr, time::Duration};

use libp2p::kad;
use serde::{Deserialize, Serialize};

use crate::policy::DiversityPolicy;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Scenario {
    Baseline,
    Disjoint,
    Diversity,
    Hardened,
    HardenedChurn,
}

impl Scenario {
    pub const ALL: [Scenario; 5] = [
        Scenario::Baseline,
        Scenario::Disjoint,
        Scenario::Diversity,
        Scenario::Hardened,
        Scenario::HardenedChurn,
    ];

    pub fn name(&self) -> &'static str {
        match self {
            Scenario::Baseline => "baseline",
            Scenario::Disjoint => "disjoint",
            Scenario::Diversity => "diversity",
            Scenario::Hardened => "hardened",
            Scenario::HardenedChurn => "hardened-churn",
        }
    }

    pub fn disjoint_query_paths(&self) -> bool {
        matches!(
            self,
            Scenario::Disjoint | Scenario::Hardened | Scenario::HardenedChurn
        )
    }

    pub fn diversity_enabled(&self) -> bool {
        matches!(
            self,
            Scenario::Diversity | Scenario::Hardened | Scenario::HardenedChurn
        )
    }

    pub fn refresh_interval(&self) -> Option<Duration> {
        matches!(self, Scenario::HardenedChurn).then(|| Duration::from_secs(30))
    }
}

impl FromStr for Scenario {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "baseline" => Ok(Scenario::Baseline),
            "disjoint" => Ok(Scenario::Disjoint),
            "diversity" => Ok(Scenario::Diversity),
            "hardened" => Ok(Scenario::Hardened),
            "hardened-churn" | "churn" => Ok(Scenario::HardenedChurn),
            other => Err(format!("unknown scenario: {other}")),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RunConfig {
    pub scenario: Scenario,
    pub honest_peers: usize,
    pub attacker_peers: usize,
    pub trials: usize,
    pub policy: DiversityPolicy,
    pub lookups: usize,
}

impl RunConfig {
    /// Build the Kademlia config for this scenario.
    ///
    /// `disjoint_query_paths` only has an effect in combination with
    /// `set_parallelism` — the number of disjoint paths *equals* the parallelism
    /// value, so leaving parallelism at the default of 3 while enabling disjoint
    /// paths gives d=3, not d=2. Set it explicitly so the run is legible.
    pub fn kad_config(&self) -> kad::Config {
        let mut cfg = kad::Config::default();
        if self.scenario.disjoint_query_paths() {
            cfg.set_parallelism(std::num::NonZeroUsize::new(3).expect("3 != 0"));
            cfg.disjoint_query_paths(true);
        }
        if let Some(interval) = self.scenario.refresh_interval() {
            cfg.set_periodic_bootstrap_interval(Some(interval));
        }
        cfg
    }

    pub fn effective_policy(&self) -> DiversityPolicy {
        if self.scenario.diversity_enabled() {
            self.policy
        } else {
            DiversityPolicy::disabled()
        }
    }
}

/// Run one scenario end to end.
///
/// # Implementation plan (not yet built)
///
/// 1. Spin `honest_peers` swarms on `/memory` transport first — the whole matrix
///    should run in one process in a few seconds before TCP is introduced. TCP
///    with distinct source IPs needs either network namespaces or a `Transport`
///    shim that rewrites the observed address, which is milestone two, not a
///    blocker for the first numbers.
/// 2. Wire `identify` into every node. Under `BucketInserts::Manual` this is
///    mandatory: without it no peer ever has an address and every arrival is
///    `UnroutablePeer`.
/// 3. Bootstrap the honest set, wait for routing tables to settle. Reuse the
///    readiness-polling idea from py-libp2p #1457 rather than sleeping — this
///    class of test flakes badly on fixed sleeps.
/// 4. Grind `attacker_peers` identities against the target key with
///    `TargetedIdGenerator`, assign them synthetic source addresses drawn from
///    `subnets_required` distinct subnets, and join them.
/// 5. Sample contamination via `Behaviour::find_closest_local_peers(target, self)`
///    on a designated victim node on a fixed interval.
/// 6. Issue `lookups` GET_VALUE queries for a record the honest set published;
///    count how many return it.
/// 7. Compute the K-L score over the victim's k-closest CPLs each sample.
pub async fn run(_config: RunConfig) -> anyhow::Result<crate::metrics::ScenarioMetrics> {
    anyhow::bail!(
        "testbed::run is not implemented yet — see the implementation plan in the \
         doc comment. The filter, the grinder and the metrics are usable now; \
         `kad-eclipse-testbed grind` exercises the attack side standalone."
    )
}
