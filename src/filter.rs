//! [`SubnetDiversityFilter`] — a [`NetworkBehaviour`] that wraps
//! [`libp2p::kad::Behaviour`] and enforces per-subnet caps *before* insertion.
//!
//! # Status: reference implementation, not a stable API
//!
//! This exists so the testbed has something to measure and so a future
//! upstream proposal has a working demonstration to point at. It is **not**
//! intended as a dependency for other crates, and its API carries no stability
//! guarantee.
//!
//! The reason is structural. This wrapper depends on the *event semantics* of
//! [`kad::BucketInserts::Manual`] — specifically that
//! [`kad::Event::RoutablePeer`] means "kad is asking permission". That is an
//! observable implementation detail, not a documented contract, so a kad minor
//! release could change its meaning without breaking compilation. Silent
//! semantic drift is the worst failure mode available to a security component,
//! which is why the durable version of this belongs behind an explicit hook
//! inside `libp2p-kad` rather than in a wrapper outside it.
//!
//! Compare go-libp2p, which puts `peerdiversity` *inside* `go-libp2p-kbucket`
//! as a filter hook rather than wrapping the routing table from outside. See
//! `docs/threat-model.md` for the full argument.
//!
//! # Why this is not a `RoutingUpdated` listener
//!
//! The obvious design is to watch for [`kad::Event::RoutingUpdated`] and call
//! [`kad::Behaviour::remove_peer`] when a subnet is over quota. That is post-hoc,
//! and it loses information you cannot get back: by the time `RoutingUpdated`
//! fires, the peer is already resident, and its `old_peer` field may name the
//! honest peer it just evicted. Removing the attacker afterwards leaves the
//! bucket with a hole where an honest peer used to be — the attacker got a free
//! eviction. Repeat that and the attacker degrades the table without ever
//! holding a slot.
//!
//! Instead this filter configures the inner behaviour with
//! [`kad::BucketInserts::Manual`]. Under `Manual`, kad emits
//! [`kad::Event::RoutablePeer`] and **does not insert**; insertion happens only
//! via an explicit [`kad::Behaviour::add_address`] call. That turns the filter
//! into real admission control, and matches both go-libp2p's
//! `peerdiversity.PeerIPGroupFilter::Allow` and the reject-don't-eviction
//! semantics already shipped in py-libp2p #1399.
//!
//! # What you take on by using `Manual`
//!
//! Manual mode means *this filter* owns the whole insertion policy, not just the
//! diversity part. In particular the identify protocol must be wired up, or no
//! peer ever gets an address and every peer arrives as
//! [`kad::Event::UnroutablePeer`]. See `src/testbed.rs` for the wiring.

use std::{
    collections::VecDeque,
    task::{Context, Poll},
};

use ipnet::IpNet;
use libp2p::{
    core::{transport::PortUse, Endpoint},
    kad::{self, store::RecordStore, BucketInserts, KBucketKey},
    swarm::{
        ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler, THandlerInEvent,
        THandlerOutEvent, ToSwarm,
    },
    Multiaddr, PeerId,
};

use crate::policy::{AdmissionLedger, DiversityPolicy, DiversityStats, RejectReason};

/// Events emitted by [`SubnetDiversityFilter`].
#[derive(Debug)]
pub enum Event {
    /// Passthrough of an inner Kademlia event.
    Kad(kad::Event),
    /// A peer was refused a routing table slot on diversity grounds.
    ///
    /// This event is the point of the whole crate: it is what makes the
    /// filter *measurable* rather than merely effective. Count these per
    /// scenario to get `subnets_required`.
    PeerRejected {
        peer: PeerId,
        subnet: IpNet,
        bucket: Option<u32>,
        reason: RejectReason,
    },
}

pub struct SubnetDiversityFilter<TStore> {
    inner: kad::Behaviour<TStore>,
    local_key: KBucketKey<PeerId>,
    policy: DiversityPolicy,
    ledger: AdmissionLedger,
    pending: VecDeque<Event>,
    rejected_count: u64,
}

impl<TStore> SubnetDiversityFilter<TStore>
where
    TStore: RecordStore + Send + 'static,
{
    /// Wrap a Kademlia behaviour. `config` is mutated to force
    /// [`BucketInserts::Manual`] — any `set_kbucket_inserts` the caller set is
    /// overridden, deliberately.
    pub fn new(
        local_peer_id: PeerId,
        store: TStore,
        mut config: kad::Config,
        policy: DiversityPolicy,
    ) -> Self {
        config.set_kbucket_inserts(BucketInserts::Manual);
        Self {
            inner: kad::Behaviour::with_config(local_peer_id, store, config),
            local_key: KBucketKey::from(local_peer_id),
            policy,
            ledger: AdmissionLedger::new(),
            pending: VecDeque::new(),
            rejected_count: 0,
        }
    }

    pub fn kad(&mut self) -> &mut kad::Behaviour<TStore> {
        &mut self.inner
    }

    pub fn policy(&self) -> &DiversityPolicy {
        &self.policy
    }

    pub fn diversity_stats(&self) -> DiversityStats {
        self.ledger.stats()
    }

    pub fn rejected_count(&self) -> u64 {
        self.rejected_count
    }

    /// Bucket index a peer would land in: `ilog2` of the XOR distance from us.
    ///
    /// Uses `KBucketDistance::ilog2()`, which is only reachable because kad 0.47
    /// (PR 5705) made `Distance`'s inner `U256` public. Before that this needed
    /// a hand-rolled XOR over `hashed_bytes()`.
    fn bucket_index(&self, peer: &PeerId) -> Option<u32> {
        self.local_key.distance(&KBucketKey::from(*peer)).ilog2()
    }

    /// The admission decision. Returns `Some(event)` if the caller should surface
    /// a rejection, `None` if the peer was admitted (or is exempt).
    fn consider(&mut self, peer: PeerId, address: Multiaddr) -> Option<Event> {
        if !self.policy.is_enabled() {
            self.inner.add_address(&peer, address);
            return None;
        }

        // Exempt: DNS-named, relayed, or non-globally-routable. Admit, don't count.
        let Some(subnet) = self.policy.subnet_of(&address) else {
            self.inner.add_address(&peer, address);
            return None;
        };

        let bucket = self.bucket_index(&peer);
        match self.ledger.try_admit(peer, subnet, bucket, &self.policy) {
            Ok(()) => {
                self.inner.add_address(&peer, address);
                None
            }
            Err(reason) => {
                self.rejected_count += 1;
                tracing::debug!(%peer, %subnet, ?bucket, ?reason, "refused routing table slot");
                Some(Event::PeerRejected {
                    peer,
                    subnet,
                    bucket,
                    reason,
                })
            }
        }
    }

    /// Translate one inner event. `None` means "consumed, poll again".
    fn on_inner_event(&mut self, ev: kad::Event) -> Option<Event> {
        // Keep the ledger honest about evictions kad performed on its own.
        // Done before the `match` so `ev` can be moved below without the borrow
        // checker objecting to a `ref` binding still being live.
        if let kad::Event::RoutingUpdated {
            old_peer: Some(old),
            ..
        } = &ev
        {
            self.ledger.release(old);
        }

        match ev {
            // Manual mode: kad is asking us whether to insert.
            kad::Event::RoutablePeer { peer, address } => self.consider(peer, address),

            // Bucket is full; kad is holding the peer as a pending replacement.
            // Same decision — if the subnet is saturated we do not want this peer
            // taking the slot when the pending entry is applied.
            kad::Event::PendingRoutablePeer { peer, address } => self.consider(peer, address),

            other => Some(Event::Kad(other)),
        }
    }
}

impl<TStore> NetworkBehaviour for SubnetDiversityFilter<TStore>
where
    TStore: RecordStore + Send + 'static,
{
    type ConnectionHandler = <kad::Behaviour<TStore> as NetworkBehaviour>::ConnectionHandler;
    type ToSwarm = Event;

    fn handle_pending_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        self.inner
            .handle_pending_inbound_connection(connection_id, local_addr, remote_addr)
    }

    fn handle_established_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        local_addr: &Multiaddr,
        remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.inner
            .handle_established_inbound_connection(connection_id, peer, local_addr, remote_addr)
    }

    fn handle_pending_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        maybe_peer: Option<PeerId>,
        addresses: &[Multiaddr],
        effective_role: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        self.inner.handle_pending_outbound_connection(
            connection_id,
            maybe_peer,
            addresses,
            effective_role,
        )
    }

    fn handle_established_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        addr: &Multiaddr,
        role_override: Endpoint,
        port_use: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.inner.handle_established_outbound_connection(
            connection_id,
            peer,
            addr,
            role_override,
            port_use,
        )
    }

    fn on_swarm_event(&mut self, event: FromSwarm) {
        // Release ledger entries for peers that fully disconnect, otherwise the
        // subnet counters ratchet upward and the table starves.
        //
        // NOTE: this is *not* the same as leaving the routing table — kad keeps
        // disconnected peers as routing entries. Releasing here is the
        // conservative choice for v0.1 (it can only under-count, never
        // over-reject) but it does mean a churny honest peer frees its slot
        // early. TODO(v0.2): drive release off routing table removal instead,
        // which needs kad to expose an eviction event it currently does not.
        if let FromSwarm::ConnectionClosed(cc) = &event {
            if cc.remaining_established == 0 {
                self.ledger.release(&cc.peer_id);
            }
        }
        self.inner.on_swarm_event(event)
    }

    fn on_connection_handler_event(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        self.inner
            .on_connection_handler_event(peer_id, connection_id, event)
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        loop {
            if let Some(ev) = self.pending.pop_front() {
                return Poll::Ready(ToSwarm::GenerateEvent(ev));
            }

            match self.inner.poll(cx) {
                Poll::Ready(ToSwarm::GenerateEvent(ev)) => {
                    if let Some(out) = self.on_inner_event(ev) {
                        self.pending.push_back(out);
                    }
                    // Loop: consume() may have called add_address, which can
                    // queue further inner events we want to drain now.
                }
                // GenerateEvent is handled above, so the closure is unreachable.
                Poll::Ready(other) => {
                    return Poll::Ready(other.map_out(|_| unreachable!("handled above")))
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}
