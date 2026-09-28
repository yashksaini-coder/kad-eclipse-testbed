//! # kad-eclipse-testbed
//!
//! An empirical eclipse-attack testbed for rust-libp2p's Kademlia, plus a
//! reusable subnet-diversity admission filter.
//!
//! ## The gap this exists to fill
//!
//! | | py-libp2p | rust-libp2p |
//! |---|---|---|
//! | Disjoint lookup paths | missing | present, opt-in, off by default |
//! | IP/subnet diversity in k-buckets | **shipped** (PR #1399) | **missing** |
//! | Eclipse testbed on real nodes | simulation only | none |
//!
//! rust-libp2p's `kbucket_inserts` strategy chooses between `OnConnected` and
//! `Manual` — it says nothing about where a peer's addresses live. An attacker
//! holding one /24 full of ground-out peer IDs meets no additional resistance at
//! the routing layer.
//!
//! ## The threat model in one paragraph
//!
//! A libp2p peer ID is `multihash(pubkey)` with no further constraint, so IDs
//! are free to mint. Kademlia routes by XOR distance, so an attacker can grind
//! keypairs, keep the ones landing closest to a target key `T`, join normally,
//! and occupy the "closest to `T`" slots in every honest routing table. Every
//! message they then send is validly signed. Record authentication does not
//! touch this — the attack is in the routing layer, not the record layer.
//!
//! S/Kademlia's two counters are crypto-puzzle IDs and disjoint lookup paths.
//! The first needs an ecosystem-wide spec change and is out of scope for any one
//! implementation. The second is in scope but, as reviewers pointed out, is a
//! *traversal* defence: once the closest-k slots for `T` are all attacker-held,
//! no path is adversary-free at any `d`. Subnet diversity is the counter that
//! touches placement rather than traversal — it cannot stop the ID being minted,
//! but it can stop the ID being seated.
//!
//! ## Layout
//!
//! - [`attack`] — grinding peer IDs toward a target key
//! - [`policy`] — subnet grouping and the admission ledger
//! - [`filter`] — the [`filter::SubnetDiversityFilter`] reference implementation
//! - [`metrics`] — the five measures, including K-L eclipse detectability
//! - [`testbed`] — the five-scenario matrix
//!
//! ## Status
//!
//! `attack`, `policy`, `filter` and `metrics` are implemented. `testbed::run`
//! is a stub with a written implementation plan.

pub mod attack;
pub mod filter;
pub mod metrics;
pub mod policy;
pub mod testbed;

pub use filter::{Event, SubnetDiversityFilter};
pub use policy::{DiversityPolicy, DiversityStats, RejectReason};

/// The `k` value this crate assumes, matching libp2p's `K_VALUE`.
pub const K_VALUE: usize = 20;
