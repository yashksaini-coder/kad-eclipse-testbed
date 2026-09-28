//! Tests for the grouping and admission rules.
//!
//! These are the cheap, fast tests. They do not need a swarm — which is
//! deliberate: the routing-table behaviour they cover is exactly what
//! py-libp2p's equivalents test, so a divergence here is a signal the two
//! implementations have drifted.

use ipnet::IpNet;
use kad_eclipse_testbed::policy::{AdmissionLedger, DiversityPolicy, RejectReason};
use libp2p::{Multiaddr, PeerId};

fn addr(s: &str) -> Multiaddr {
    s.parse().expect("valid multiaddr")
}

fn net(s: &str) -> IpNet {
    s.parse().expect("valid subnet")
}

#[test]
fn groups_public_ipv4_by_prefix() {
    let policy = DiversityPolicy::default();
    assert_eq!(
        policy.subnet_of(&addr("/ip4/203.0.113.7/tcp/4001")),
        Some(net("203.0.113.0/24"))
    );
}

#[test]
fn wider_prefix_collapses_more_peers_into_one_group() {
    // The /16 vs /24 question, expressed as a test rather than an argument.
    let narrow = DiversityPolicy {
        prefix_len_v4: 24,
        ..DiversityPolicy::default()
    };
    let wide = DiversityPolicy {
        prefix_len_v4: 16,
        ..DiversityPolicy::default()
    };
    let a = addr("/ip4/198.51.100.1/tcp/4001");
    let b = addr("/ip4/198.51.200.1/tcp/4001");

    assert_ne!(narrow.subnet_of(&a), narrow.subnet_of(&b));
    assert_eq!(wide.subnet_of(&a), wide.subnet_of(&b));
}

#[test]
fn private_loopback_and_cgnat_are_exempt() {
    let policy = DiversityPolicy::default();
    for a in [
        "/ip4/127.0.0.1/tcp/4001",
        "/ip4/10.0.0.4/tcp/4001",
        "/ip4/192.168.1.9/tcp/4001",
        "/ip4/172.16.5.5/tcp/4001",
        "/ip4/100.64.3.1/tcp/4001", // CGNAT
        "/ip4/169.254.1.1/tcp/4001", // link-local
    ] {
        assert_eq!(policy.subnet_of(&addr(a)), None, "{a} should be exempt");
    }
}

#[test]
fn dns_and_relayed_peers_are_exempt() {
    let policy = DiversityPolicy::default();
    assert_eq!(policy.subnet_of(&addr("/dns4/bootstrap.example/tcp/4001")), None);
    assert_eq!(policy.subnet_of(&addr("/ip4/10.0.0.1/tcp/4001/p2p-circuit")), None);
}

#[test]
fn ipv6_groups_at_the_delegation_boundary_not_the_interface() {
    let policy = DiversityPolicy::default(); // /48
    let a = addr("/ip6/2001:db9:abcd:0001::1/tcp/4001");
    let b = addr("/ip6/2001:db9:abcd:ffff::9/tcp/4001");
    // Two different /64s inside one /48 must collapse to one group, otherwise a
    // single subscriber delegation defeats the cap outright.
    assert_eq!(policy.subnet_of(&a), policy.subnet_of(&b));
    assert!(policy.subnet_of(&a).is_some());
}

#[test]
fn ipv6_documentation_range_is_exempt() {
    let policy = DiversityPolicy::default();
    assert_eq!(policy.subnet_of(&addr("/ip6/2001:db8::1/tcp/4001")), None);
}

#[test]
fn per_bucket_cap_rejects_the_third_peer_in_one_subnet() {
    let policy = DiversityPolicy {
        max_per_subnet_per_bucket: 2,
        max_per_subnet_table_wide: 0,
        ..DiversityPolicy::default()
    };
    let mut ledger = AdmissionLedger::new();
    let subnet = net("203.0.113.0/24");

    assert!(ledger
        .try_admit(PeerId::random(), subnet, Some(7), &policy)
        .is_ok());
    assert!(ledger
        .try_admit(PeerId::random(), subnet, Some(7), &policy)
        .is_ok());
    assert_eq!(
        ledger.try_admit(PeerId::random(), subnet, Some(7), &policy),
        Err(RejectReason::BucketSubnetFull)
    );
}

#[test]
fn the_cap_is_per_bucket_not_global() {
    let policy = DiversityPolicy {
        max_per_subnet_per_bucket: 2,
        max_per_subnet_table_wide: 0,
        ..DiversityPolicy::default()
    };
    let mut ledger = AdmissionLedger::new();
    let subnet = net("203.0.113.0/24");

    for bucket in [Some(3), Some(4), Some(5)] {
        assert!(ledger.try_admit(PeerId::random(), subnet, bucket, &policy).is_ok());
        assert!(ledger.try_admit(PeerId::random(), subnet, bucket, &policy).is_ok());
    }
    assert_eq!(ledger.tracked_peers(), 6);
}

#[test]
fn table_wide_cap_catches_what_the_bucket_cap_misses() {
    // This is the hole PR #1442 closes in py-libp2p: an attacker spreading two
    // peers per bucket across many buckets stays under a per-bucket cap while
    // taking a large share of the table.
    let policy = DiversityPolicy {
        max_per_subnet_per_bucket: 2,
        max_per_subnet_table_wide: 4,
        ..DiversityPolicy::default()
    };
    let mut ledger = AdmissionLedger::new();
    let subnet = net("203.0.113.0/24");

    assert!(ledger.try_admit(PeerId::random(), subnet, Some(1), &policy).is_ok());
    assert!(ledger.try_admit(PeerId::random(), subnet, Some(1), &policy).is_ok());
    assert!(ledger.try_admit(PeerId::random(), subnet, Some(2), &policy).is_ok());
    assert!(ledger.try_admit(PeerId::random(), subnet, Some(2), &policy).is_ok());

    // Different bucket, so the per-bucket cap has nothing to say — but the table
    // is already 4 deep in this subnet.
    assert_eq!(
        ledger.try_admit(PeerId::random(), subnet, Some(3), &policy),
        Err(RejectReason::TableSubnetFull)
    );
}

#[test]
fn release_frees_the_slot() {
    let policy = DiversityPolicy {
        max_per_subnet_per_bucket: 1,
        max_per_subnet_table_wide: 0,
        ..DiversityPolicy::default()
    };
    let mut ledger = AdmissionLedger::new();
    let subnet = net("203.0.113.0/24");
    let resident = PeerId::random();

    assert!(ledger.try_admit(resident, subnet, Some(9), &policy).is_ok());
    assert!(ledger
        .try_admit(PeerId::random(), subnet, Some(9), &policy)
        .is_err());

    ledger.release(&resident);
    assert!(ledger
        .try_admit(PeerId::random(), subnet, Some(9), &policy)
        .is_ok());
}

#[test]
fn readmitting_a_resident_peer_does_not_double_count() {
    // An address update for a peer already in the table must not consume a
    // second slot, or a churny honest peer evicts itself.
    let policy = DiversityPolicy {
        max_per_subnet_per_bucket: 1,
        ..DiversityPolicy::default()
    };
    let mut ledger = AdmissionLedger::new();
    let subnet = net("203.0.113.0/24");
    let peer = PeerId::random();

    assert!(ledger.try_admit(peer, subnet, Some(2), &policy).is_ok());
    assert!(ledger.try_admit(peer, subnet, Some(2), &policy).is_ok());
    assert_eq!(ledger.tracked_peers(), 1);
    assert_eq!(ledger.stats().largest_subnet_share, 1);
}

#[test]
fn disabled_policy_admits_everything() {
    let policy = DiversityPolicy::disabled();
    let mut ledger = AdmissionLedger::new();
    let subnet = net("203.0.113.0/24");

    for _ in 0..50 {
        assert!(ledger.try_admit(PeerId::random(), subnet, Some(0), &policy).is_ok());
    }
    assert!(!policy.is_enabled());
}
