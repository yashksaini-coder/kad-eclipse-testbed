//! The five metrics.
//!
//! The first three are from the original design. The fourth and fifth exist
//! because of review feedback:
//!
//! - `subnets_required` answers "does the diversity cap raise the *operational*
//!   cost, not just the CPU cost" — and is the number that settles the /16 vs
//!   /24 disagreement between go-libp2p and py-libp2p empirically.
//! - `kl_detectability` answers ANP2's objection that none of the original
//!   configs measured whether an honest node could *tell* it had been eclipsed.
//!   A `GET_VALUE` eclipse never has to answer wrong: the adversarial closest-set
//!   can simply report "no record", which to the resolver is indistinguishable
//!   from a key nobody published.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioMetrics {
    pub scenario: String,
    /// Fraction of the victim's k-closest-to-target set held by attacker peers.
    pub contamination_ratio: f64,
    /// Fraction of lookups that returned the honest record.
    pub lookup_success_rate: f64,
    /// Wall-clock until contamination first hit 100%, if it ever did.
    pub time_to_first_eclipse_ms: Option<u64>,
    /// Distinct subnets the attacker needed to place its identities.
    /// Under `baseline` this is 1; under a working diversity policy it is
    /// `ceil(k / max_per_subnet_per_bucket)`.
    pub subnets_required: usize,
    /// Fraction of eclipsed lookups a resolver could have flagged via the
    /// K-L divergence test. See [`kl_divergence_cpl`].
    pub kl_detectability: f64,
    pub attacker_identities: usize,
    pub honest_peers: usize,
    pub rejected_by_filter: u64,
}

/// K-L divergence between the observed common-prefix-length distribution of the
/// k closest peers to a target and the distribution expected in a uniformly
/// populated network of `network_size` nodes.
///
/// Rationale: in a healthy DHT, node IDs are uniformly distributed, so the CPL
/// between a target and a randomly placed node is geometric — `P(CPL = j) =
/// 2^-(j+1)`. Grinding IDs toward a target produces an excess of high-CPL nodes
/// that shows up as divergence from that baseline. This is the detection
/// approach of Cholez et al., which the 2025 analysis of active Sybil attacks on
/// the IPFS DHT (arXiv:2505.01139) applies to Kubo.
///
/// Returns divergence in bits. Zero means indistinguishable from a healthy
/// network; the threshold above which a resolver should flag is empirical and is
/// one of the things the testbed is meant to establish.
///
/// TODO(v0.2): the estimator below is the coarse version — a geometric prior
/// conditioned only on `network_size`. The paper's formulation conditions on the
/// *expected* k-closest order statistics, which is tighter at small k. Validate
/// against their reported numbers before quoting a threshold anywhere public.
pub fn kl_divergence_cpl(observed_cpls: &[u32], network_size: usize) -> f64 {
    if observed_cpls.is_empty() || network_size == 0 {
        return 0.0;
    }

    let n = observed_cpls.len() as f64;
    let max_cpl = observed_cpls.iter().copied().max().unwrap_or(0) as usize;

    // Expected CPL of the closest node in a network of N is ~log2(N); shift the
    // geometric prior so it is anchored there rather than at zero.
    let anchor = (network_size as f64).log2().floor().max(0.0) as usize;

    let mut counts = vec![0usize; max_cpl + 2];
    for &c in observed_cpls {
        counts[c as usize] += 1;
    }

    let mut kl = 0.0;
    for (cpl, &count) in counts.iter().enumerate() {
        if count == 0 {
            continue;
        }
        let p_obs = count as f64 / n;
        // Geometric tail beyond the anchor, floored so we never divide by zero.
        let excess = cpl.saturating_sub(anchor) as i32;
        let p_exp = (2f64.powi(-(excess + 1))).max(1e-12);
        kl += p_obs * (p_obs / p_exp).log2();
    }
    kl.max(0.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn healthy_network_scores_near_zero() {
        // A spread of CPLs around log2(1024) = 10, roughly geometric.
        let observed: Vec<u32> = vec![10, 10, 11, 11, 12, 13, 10, 11];
        let kl = kl_divergence_cpl(&observed, 1024);
        assert!(kl < 2.0, "healthy network scored {kl}, expected < 2.0");
    }

    #[test]
    fn ground_ids_score_high() {
        // Every peer sitting at CPL 40 in a 1024-node network is impossible by
        // chance and should light up loudly.
        let observed: Vec<u32> = vec![40; 20];
        let kl = kl_divergence_cpl(&observed, 1024);
        assert!(kl > 10.0, "eclipsed set scored {kl}, expected > 10.0");
    }

    #[test]
    fn empty_input_is_zero() {
        assert_eq!(kl_divergence_cpl(&[], 1024), 0.0);
        assert_eq!(kl_divergence_cpl(&[10], 0), 0.0);
    }
}
