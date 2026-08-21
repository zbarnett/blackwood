//! The per-node routing state machine.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::key::PublicKey;
use crate::message::{Envelope, Message, Packet};
use crate::tree::{Announcement, distance};

/// Why a packet could not be handed to the network.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SendError {
    /// Either the destination's position in the tree is unknown, or no linked
    /// peer stands closer to it than this node does.
    NoRoute,
}

impl fmt::Display for SendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoRoute => f.write_str("no route to destination"),
        }
    }
}

impl std::error::Error for SendError {}

/// One node's complete routing state.
///
/// A node is a pure state machine: every method takes an event and returns the
/// messages the event produced. It never blocks, never reads a clock, and never
/// touches the operating system.
#[derive(Clone, Debug)]
pub struct Node {
    key: PublicKey,
    /// This node's own announcement. It is the sole author of this value.
    announcement: Announcement,
    /// Peers reachable over a direct link.
    peers: BTreeSet<PublicKey>,
    /// The announcements of every *other* node this one has heard of.
    infos: BTreeMap<PublicKey, Announcement>,
    delivered: Vec<Packet>,
}

impl Node {
    /// Creates an isolated node, which necessarily believes it is its own root.
    pub fn new(key: PublicKey) -> Self {
        Self {
            key,
            announcement: Announcement::root_of(key, 0),
            peers: BTreeSet::new(),
            infos: BTreeMap::new(),
            delivered: Vec::new(),
        }
    }

    /// This node's address.
    pub fn key(&self) -> PublicKey {
        self.key
    }

    /// The root of the spanning tree this node currently believes in.
    pub fn root(&self) -> PublicKey {
        self.announcement.root()
    }

    /// This node's parent, or `None` while it believes it is the root.
    pub fn parent(&self) -> Option<PublicKey> {
        self.announcement.parent()
    }

    /// The path of keys from the root down to this node.
    pub fn path(&self) -> &[PublicKey] {
        self.announcement.path()
    }

    /// The peers this node holds a link to.
    pub fn peers(&self) -> impl Iterator<Item = PublicKey> + '_ {
        self.peers.iter().copied()
    }

    /// Brings up a link to `peer`.
    ///
    /// The new peer is sent everything this node knows, which is what makes a
    /// fresh link converge without any separate handshake.
    pub fn add_peer(&mut self, peer: PublicKey) -> Vec<Envelope> {
        let mut out = Vec::new();
        if peer == self.key || !self.peers.insert(peer) {
            return out;
        }
        for info in self.known() {
            out.push(Envelope {
                to: peer,
                message: Message::Announce(info.clone()),
            });
        }
        self.reparent(&mut out);
        out
    }

    /// Tears down the link to `peer`.
    ///
    /// Ironwood expires what it learned through a lost peer on a timer. This
    /// core has no clock, so announcements reached through `peer` linger until
    /// something newer replaces them; routing towards a departed node fails by
    /// dropping the packet at the dead end.
    pub fn remove_peer(&mut self, peer: PublicKey) -> Vec<Envelope> {
        let mut out = Vec::new();
        if self.peers.remove(&peer) {
            self.reparent(&mut out);
        }
        out
    }

    /// Hands this node a `message` that arrived from `from`.
    ///
    /// Messages from a node that is not a peer are ignored.
    pub fn handle(&mut self, from: PublicKey, message: Message) -> Vec<Envelope> {
        let mut out = Vec::new();
        if !self.peers.contains(&from) {
            return out;
        }
        match message {
            Message::Announce(announcement) => self.receive_announce(from, announcement, &mut out),
            Message::Packet(packet) => self.forward(packet, &mut out),
        }
        out
    }

    /// Originates a packet addressed to `dst`.
    pub fn send(&mut self, dst: PublicKey, payload: Vec<u8>) -> Result<Vec<Envelope>, SendError> {
        let packet = Packet {
            src: self.key,
            dst,
            payload,
        };
        if dst == self.key {
            self.delivered.push(packet);
            return Ok(Vec::new());
        }
        let peer = self.next_hop(&dst).ok_or(SendError::NoRoute)?;
        Ok(vec![Envelope {
            to: peer,
            message: Message::Packet(packet),
        }])
    }

    /// Takes the packets addressed to this node that have arrived so far.
    pub fn take_delivered(&mut self) -> Vec<Packet> {
        std::mem::take(&mut self.delivered)
    }

    /// Every announcement this node holds, its own included.
    fn known(&self) -> impl Iterator<Item = &Announcement> {
        std::iter::once(&self.announcement).chain(self.infos.values())
    }

    fn receive_announce(
        &mut self,
        from: PublicKey,
        announcement: Announcement,
        out: &mut Vec<Envelope>,
    ) {
        let author = announcement.author();
        // A node is the only authority on where it sits, so an announcement
        // about ourselves is at best a stale echo of our own.
        if author == self.key {
            return;
        }
        if self
            .infos
            .get(&author)
            .is_some_and(|known| !announcement.supersedes(known))
        {
            return;
        }
        self.infos.insert(author, announcement.clone());
        // Only news travels. Gossip therefore terminates: each hop strictly
        // advances some author's announcement, and that cannot rise forever.
        self.gossip(Message::Announce(announcement), Some(from), out);
        self.reparent(out);
    }

    /// Reconsiders which peer to sit below, announcing the move if it changed.
    fn reparent(&mut self, out: &mut Vec<Envelope>) {
        let best = self.best_position();
        if best.path() != self.announcement.path() {
            self.announcement = best.with_seq(self.announcement.seq() + 1);
            self.gossip(Message::Announce(self.announcement.clone()), None, out);
        }
    }

    /// The most preferred position available: below some peer, or self-rooted.
    fn best_position(&self) -> Announcement {
        // The sequence number is irrelevant to the comparison; the caller
        // stamps the winner with the right one.
        let seq = self.announcement.seq();
        let mut best = Announcement::root_of(self.key, seq);
        for peer in &self.peers {
            let Some(info) = self.infos.get(peer) else {
                continue;
            };
            let Some(candidate) = info.extend(self.key, seq) else {
                continue;
            };
            if candidate.preference_cmp(&best) == Ordering::Less {
                best = candidate;
            }
        }
        best
    }

    fn gossip(&self, message: Message, except: Option<PublicKey>, out: &mut Vec<Envelope>) {
        for &peer in &self.peers {
            if Some(peer) != except {
                out.push(Envelope {
                    to: peer,
                    message: message.clone(),
                });
            }
        }
    }

    fn forward(&mut self, packet: Packet, out: &mut Vec<Envelope>) {
        if packet.dst == self.key {
            self.delivered.push(packet);
            return;
        }
        // Without a next hop this is a dead end. Ironwood would report the
        // broken path back through the tree and look the destination up again;
        // this core drops the packet, which is that minus the recovery.
        if let Some(peer) = self.next_hop(&packet.dst) {
            out.push(Envelope {
                to: peer,
                message: Message::Packet(packet),
            });
        }
    }

    /// The peer that stands strictly closer to `dst`, if one does.
    ///
    /// Requiring strict progress is what makes forwarding loop-free without any
    /// per-packet state: distance to the destination falls at every hop and
    /// cannot fall below zero, so a packet either arrives or is dropped.
    fn next_hop(&self, dst: &PublicKey) -> Option<PublicKey> {
        let dst_path = self.infos.get(dst)?.path();
        let mut shortest = distance(self.announcement.path(), dst_path);
        let mut best = None;
        for &peer in &self.peers {
            let Some(info) = self.infos.get(&peer) else {
                continue;
            };
            let hop = distance(info.path(), dst_path);
            if hop < shortest {
                shortest = hop;
                best = Some(peer);
            }
        }
        best
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::KEY_LEN;

    fn key(n: u8) -> PublicKey {
        PublicKey::new([n; KEY_LEN])
    }

    #[test]
    fn a_new_node_is_its_own_root() {
        let node = Node::new(key(7));
        assert_eq!(node.root(), key(7));
        assert_eq!(node.parent(), None);
        assert_eq!(node.path(), [key(7)]);
    }

    #[test]
    fn adding_a_peer_offers_it_everything_known() {
        let mut node = Node::new(key(2));
        let out = node.add_peer(key(1));
        assert_eq!(out.len(), 1, "only its own announcement is known so far");
        assert_eq!(out[0].to, key(1));
        assert_eq!(
            out[0].message,
            Message::Announce(Announcement::root_of(key(2), 0))
        );
    }

    #[test]
    fn a_node_will_not_peer_with_itself() {
        let mut node = Node::new(key(1));
        assert!(node.add_peer(key(1)).is_empty());
        assert_eq!(node.peers().count(), 0);
    }

    #[test]
    fn messages_from_strangers_are_ignored() {
        let mut node = Node::new(key(2));
        let stranger = Announcement::root_of(key(1), 0);
        assert!(node.handle(key(1), Message::Announce(stranger)).is_empty());
        assert_eq!(node.root(), key(2), "the tree did not move");
    }

    #[test]
    fn a_node_adopts_a_peer_holding_a_smaller_key_as_its_root() {
        let mut node = Node::new(key(2));
        node.add_peer(key(1));
        node.handle(key(1), Message::Announce(Announcement::root_of(key(1), 0)));

        assert_eq!(node.root(), key(1));
        assert_eq!(node.parent(), Some(key(1)));
        assert_eq!(node.path(), [key(1), key(2)]);
    }

    #[test]
    fn a_node_keeps_a_smaller_key_than_its_peer() {
        let mut node = Node::new(key(1));
        node.add_peer(key(2));
        node.handle(key(2), Message::Announce(Announcement::root_of(key(2), 0)));

        assert_eq!(node.root(), key(1), "the smaller key stays the root");
        assert_eq!(node.parent(), None);
    }

    #[test]
    fn sending_to_an_unknown_destination_fails() {
        let mut node = Node::new(key(1));
        assert_eq!(node.send(key(9), b"hi".to_vec()), Err(SendError::NoRoute));
    }

    #[test]
    fn sending_to_oneself_delivers_locally() {
        let mut node = Node::new(key(1));
        assert_eq!(node.send(key(1), b"hi".to_vec()), Ok(Vec::new()));
        assert_eq!(
            node.take_delivered(),
            vec![Packet {
                src: key(1),
                dst: key(1),
                payload: b"hi".to_vec(),
            }]
        );
    }

    #[test]
    fn stale_announcements_are_not_gossiped_on() {
        let mut node = Node::new(key(2));
        node.add_peer(key(1));
        node.add_peer(key(3));

        let fresh = Announcement::root_of(key(1), 5);
        assert!(!node.handle(key(1), Message::Announce(fresh)).is_empty());

        let stale = Announcement::root_of(key(1), 4);
        assert!(
            node.handle(key(1), Message::Announce(stale)).is_empty(),
            "old news must not be forwarded, or gossip would never settle"
        );
    }
}
