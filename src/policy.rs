//! Subnet grouping policy and the admission ledger.
//!
//! This mirrors the semantics shipped in py-libp2p `libp2p/kad_dht/routing_table.py`
//! (PR #1399) so that measurements taken here transfer to the Python
//! implementation, and deliberately diverges from go-libp2p in one place — see
//! [`DiversityPolicy`] docs.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use libp2p::{multiaddr::Protocol, Multiaddr, PeerId};
use serde::{Deserialize, Serialize};

/// How peers are grouped into subnets, and how many of each group are allowed.
///
/// # Prefix length defaults
///
/// `v4 = 24`, `v6 = 48`.
///
/// go-libp2p's `peerdiversity` groups IPv4 by /16, which is stricter. py-libp2p
/// #1399 shipped /24, on the argument that a cloud tenant's addresses are
/// scattered across /24s anyway so a /16 cap mostly punishes honest peers behind
/// large ISPs. That disagreement is unresolved and is exactly what the testbed
/// exists to settle — run `--prefix-v4 16` against `--prefix-v4 24` and report
/// the delta in `subnets_required` and `contamination_ratio`.
///
/// The v6 default is /48, **not** /64. A single residential /56 delegation hands
/// one subscriber 256 distinct /64s and a /48 delegation hands over 65,536, so a
/// /64 cap of 2 is very close to no cap at all. /48 is the site-delegation
/// boundary. (Raised by ANP2 Network in review of the design writeup; py-libp2p
/// shipped /48 for the same reason.)
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct DiversityPolicy {
    pub prefix_len_v4: u8,
    pub prefix_len_v6: u8,
    /// Max peers sharing one subnet within a single k-bucket. `0` disables.
    ///
    /// Equivalent to py-libp2p's `MAX_PEERS_PER_SUBNET`.
    pub max_per_subnet_per_bucket: usize,
    /// Max peers sharing one subnet across the *entire* routing table. `0` disables.
    ///
    /// go-libp2p enforces both; py-libp2p #1399 shipped per-bucket only and
    /// #1442 is adding this. Keep both here so the Rust and Python numbers are
    /// comparable once #1442 lands.
    pub max_per_subnet_table_wide: usize,
}

impl Default for DiversityPolicy {
    fn default() -> Self {
        Self {
            prefix_len_v4: 24,
            prefix_len_v6: 48,
            max_per_subnet_per_bucket: 2,
            max_per_subnet_table_wide: 6,
        }
    }
}

impl DiversityPolicy {
    /// A policy that admits everything — the `baseline` testbed config.
    pub fn disabled() -> Self {
        Self {
            max_per_subnet_per_bucket: 0,
            max_per_subnet_table_wide: 0,
            ..Self::default()
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.max_per_subnet_per_bucket > 0 || self.max_per_subnet_table_wide > 0
    }

    /// Group a multiaddr into its subnet, or `None` if the peer is *exempt*.
    ///
    /// Exempt means: no globally-routable IP component. DNS-named peers, relayed
    /// peers (`/p2p-circuit`), loopback, RFC1918, CGNAT, link-local and
    /// unique-local addresses all fall through. Exempt peers are never counted
    /// and never rejected.
    ///
    /// **Divergence from go-libp2p**, carried over from py-libp2p #1399: go
    /// inspects *every* address a peer advertises and rejects if any group is
    /// saturated. We take the first globally-routable address only. Cheaper, and
    /// it avoids a peer being penalised for advertising a stale public address it
    /// no longer listens on — but it is also weaker, because an attacker can
    /// order their advertised addresses to put an exempt one first.
    ///
    /// TODO(v0.2): make this configurable (`FirstRoutable` vs `AllAddresses`) and
    /// measure whether the ordering attack is exploitable in the testbed. That
    /// is a publishable number on its own.
    pub fn subnet_of(&self, addr: &Multiaddr) -> Option<IpNet> {
        for proto in addr.iter() {
            let ip = match proto {
                Protocol::Ip4(v4) => IpAddr::V4(v4),
                Protocol::Ip6(v6) => match v6.to_ipv4_mapped() {
                    Some(v4) => IpAddr::V4(v4),
                    None => IpAddr::V6(v6),
                },
                _ => continue,
            };
            if !is_globally_routable(&ip) {
                continue;
            }
            return self.group(ip);
        }
        None
    }

    fn group(&self, ip: IpAddr) -> Option<IpNet> {
        match ip {
            IpAddr::V4(v4) => Ipv4Net::new(v4, self.prefix_len_v4)
                .ok()
                .map(|n| IpNet::V4(n.trunc())),
            IpAddr::V6(v6) => Ipv6Net::new(v6, self.prefix_len_v6)
                .ok()
                .map(|n| IpNet::V6(n.trunc())),
        }
    }
}

/// Hand-rolled because `Ipv4Addr::is_global` / `Ipv6Addr::is_global` are still
/// unstable. Mirrors Python's `ipaddress.ip_address(..).is_global`, which is what
/// py-libp2p `_subnet_key()` relies on — keep the two in sync when either moves.
pub fn is_globally_routable(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_global_v4(v4),
        IpAddr::V6(v6) => is_global_v6(v6),
    }
}

fn is_global_v4(ip: &Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
        || ip.is_multicast()
        // 100.64.0.0/10 — CGNAT (RFC 6598)
        || (a == 100 && (64..128).contains(&b))
        // 192.0.0.0/24 — IETF protocol assignments
        || (a == 192 && b == 0 && c == 0)
        // 198.18.0.0/15 — benchmarking
        || (a == 198 && (b == 18 || b == 19))
        // 240.0.0.0/4 — reserved
        || a >= 240)
}

fn is_global_v6(ip: &Ipv6Addr) -> bool {
    let seg = ip.segments();
    !(ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        // fc00::/7 — unique local
        || (seg[0] & 0xfe00) == 0xfc00
        // fe80::/10 — link local
        || (seg[0] & 0xffc0) == 0xfe80
        // 2001:db8::/32 — documentation
        || (seg[0] == 0x2001 && seg[1] == 0x0db8))
}

/// Why a peer was refused admission to the routing table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RejectReason {
    /// The peer's subnet already holds `max_per_subnet_per_bucket` peers in the
    /// bucket this peer would land in.
    BucketSubnetFull,
    /// The peer's subnet already holds `max_per_subnet_table_wide` peers across
    /// the whole table.
    TableSubnetFull,
}

/// Tracks which subnets currently occupy which buckets.
///
/// Bucket index is `Distance::ilog2()`, i.e. the common-prefix-length bucket the
/// peer falls into. `None` means distance zero (self), which never happens for a
/// remote peer but is representable.
#[derive(Debug, Default)]
pub struct AdmissionLedger {
    by_peer: HashMap<PeerId, (IpNet, Option<u32>)>,
    table_wide: HashMap<IpNet, usize>,
    per_bucket: HashMap<(Option<u32>, IpNet), usize>,
}

impl AdmissionLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Decide whether `peer` may enter `bucket`, and record it if so.
    ///
    /// Idempotent: re-admitting an already-tracked peer is a no-op success, so
    /// an address update for a resident peer never double-counts.
    pub fn try_admit(
        &mut self,
        peer: PeerId,
        subnet: IpNet,
        bucket: Option<u32>,
        policy: &DiversityPolicy,
    ) -> Result<(), RejectReason> {
        if self.by_peer.contains_key(&peer) {
            return Ok(());
        }

        if policy.max_per_subnet_table_wide > 0 {
            let n = self.table_wide.get(&subnet).copied().unwrap_or(0);
            if n >= policy.max_per_subnet_table_wide {
                return Err(RejectReason::TableSubnetFull);
            }
        }

        if policy.max_per_subnet_per_bucket > 0 {
            let n = self
                .per_bucket
                .get(&(bucket, subnet))
                .copied()
                .unwrap_or(0);
            if n >= policy.max_per_subnet_per_bucket {
                return Err(RejectReason::BucketSubnetFull);
            }
        }

        self.by_peer.insert(peer, (subnet, bucket));
        *self.table_wide.entry(subnet).or_insert(0) += 1;
        *self.per_bucket.entry((bucket, subnet)).or_insert(0) += 1;
        Ok(())
    }

    /// Drop a peer from the ledger. Call this on eviction and on removal, or the
    /// counts leak and the filter slowly starves the routing table.
    pub fn release(&mut self, peer: &PeerId) {
        let Some((subnet, bucket)) = self.by_peer.remove(peer) else {
            return;
        };
        if let Some(n) = self.table_wide.get_mut(&subnet) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                self.table_wide.remove(&subnet);
            }
        }
        if let Some(n) = self.per_bucket.get_mut(&(bucket, subnet)) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                self.per_bucket.remove(&(bucket, subnet));
            }
        }
    }

    pub fn tracked_peers(&self) -> usize {
        self.by_peer.len()
    }

    pub fn distinct_subnets(&self) -> usize {
        self.table_wide.len()
    }

    /// Snapshot for reporting. The analogue of go-libp2p's
    /// `GetRoutingTableDiversityStats`, and the shape worth porting into
    /// py-libp2p's `RoutingTableDiagnostics` (PR #1332) alongside #1442.
    pub fn stats(&self) -> DiversityStats {
        let mut per_subnet: Vec<(IpNet, usize)> =
            self.table_wide.iter().map(|(k, v)| (*k, *v)).collect();
        per_subnet.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.to_string().cmp(&b.0.to_string())));
        DiversityStats {
            tracked_peers: self.by_peer.len(),
            distinct_subnets: self.table_wide.len(),
            largest_subnet_share: per_subnet.first().map(|(_, n)| *n).unwrap_or(0),
            per_subnet,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiversityStats {
    pub tracked_peers: usize,
    pub distinct_subnets: usize,
    pub largest_subnet_share: usize,
    pub per_subnet: Vec<(IpNet, usize)>,
}
