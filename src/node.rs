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

/// How long announcements live, and how often a node renews its own.
///
/// Both are durations in whatever unit the caller counts `now` in. The core
/// never interprets them and never reads a clock of its own; it only subtracts
/// one instant it was handed from another.
///
/// `refresh` must be comfortably smaller than `expiry`. A node's announcement
/// has to be reissued, and the reissue flooded, several times over before its
/// peers would otherwise give up on it. Set them too close together and a
/// perfectly healthy network forgets nodes it is about to hear from again.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Timing {
    /// How long a node leaves its own announcement alone before reissuing it.
    pub refresh: u64,
    /// How long an announcement from elsewhere is kept without being reissued.
    pub expiry: u64,
}

impl Timing {
    /// Ironwood's choice — reissue every second, forget after three — for a
    /// caller counting in milliseconds.
    pub const DEFAULT: Self = Self {
        refresh: 1_000,
        expiry: 3_000,
    };
}

impl Default for Timing {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// An announcement about another node, and when this node last heard it.
///
/// The instant is local: it records when the announcement *arrived here*, not
/// when its author made it. Nothing therefore requires two nodes to agree about
/// what time it is, only that each one's own clock runs forwards.
#[derive(Clone, Debug)]
struct Info {
    announcement: Announcement,
    heard_at: u64,
}

/// One node's complete routing state.
///
/// A node is a pure state machine: every method takes an event and returns the
/// messages the event produced. It never blocks, never touches the operating
/// system, and never reads a clock. Time enters only as the `now` argument the
/// caller passes in — an opaque count in the caller's own unit, which is only
/// ever subtracted from a later `now`, so its origin is arbitrary but it must
/// not go backwards.
#[derive(Clone, Debug)]
pub struct Node {
    key: PublicKey,
    timing: Timing,
    /// This node's own announcement. It is the sole author of this value.
    announcement: Announcement,
    /// When this node last issued the announcement above.
    announced_at: u64,
    /// Peers reachable over a direct link.
    peers: BTreeSet<PublicKey>,
    /// What this node has heard about every *other* node, and when.
    infos: BTreeMap<PublicKey, Info>,
    delivered: Vec<Packet>,
}

impl Node {
    /// Creates an isolated node, which necessarily believes it is its own root.
    pub fn new(now: u64, key: PublicKey) -> Self {
        Self::with_timing(now, key, Timing::DEFAULT)
    }

    /// Creates an isolated node that keeps and reissues state on its own
    /// schedule rather than [`Timing::DEFAULT`].
    pub fn with_timing(now: u64, key: PublicKey, timing: Timing) -> Self {
        Self {
            key,
            timing,
            announcement: Announcement::root_of(key, 0),
            announced_at: now,
            peers: BTreeSet::new(),
            infos: BTreeMap::new(),
            delivered: Vec::new(),
        }
    }

    /// This node's address.
    pub fn key(&self) -> PublicKey {
        self.key
    }

    /// The schedule this node keeps state on.
    pub fn timing(&self) -> Timing {
        self.timing
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

    /// The other nodes this one currently holds an announcement for.
    ///
    /// This is what expiry shrinks and gossip grows, and it is exactly the set
    /// of destinations [`send`](Self::send) can name.
    pub fn known(&self) -> impl Iterator<Item = PublicKey> + '_ {
        self.infos.keys().copied()
    }

    /// Moves this node's clock to `now`, expiring and reissuing state.
    ///
    /// Three things happen, in that order. Announcements not heard again within
    /// [`Timing::expiry`] are forgotten, which is how a node that vanished
    /// stops being remembered as a route to nowhere. Losing them may have cost
    /// this node its parent, so it reconsiders where it sits. Finally, if its
    /// own announcement has stood for [`Timing::refresh`] without being
    /// reissued, it reissues it, which is what stops peers forgetting *it*.
    ///
    /// This is the only method that involves the passage of time, and a node
    /// that is never ticked behaves exactly as though it did not exist: state
    /// then changes only when a message arrives or a link moves.
    pub fn tick(&mut self, now: u64) -> Vec<Envelope> {
        let mut out = Vec::new();
        let expiry = self.timing.expiry;
        self.infos
            .retain(|_, info| now.saturating_sub(info.heard_at) < expiry);
        self.reparent(now, &mut out);
        if now.saturating_sub(self.announced_at) >= self.timing.refresh {
            let unchanged = self.announcement.clone();
            self.announce(now, unchanged, &mut out);
        }
        out
    }

    /// Brings up a link to `peer`.
    ///
    /// The new peer is sent everything this node knows, which is what makes a
    /// fresh link converge without any separate handshake.
    pub fn add_peer(&mut self, now: u64, peer: PublicKey) -> Vec<Envelope> {
        let mut out = Vec::new();
        if peer == self.key || !self.peers.insert(peer) {
            return out;
        }
        for info in self.announcements() {
            out.push(Envelope {
                to: peer,
                message: Message::Announce(info.clone()),
            });
        }
        self.reparent(now, &mut out);
        out
    }

    /// Tears down the link to `peer`.
    ///
    /// What this node learned *through* `peer` is not withdrawn here, because
    /// it cannot tell which of those routes were only reachable that way. Those
    /// announcements are left to expire on their own, which is what
    /// [`tick`](Self::tick) is for. Until they do, routing towards a departed
    /// node fails by dropping the packet at the dead end.
    pub fn remove_peer(&mut self, now: u64, peer: PublicKey) -> Vec<Envelope> {
        let mut out = Vec::new();
        if self.peers.remove(&peer) {
            self.reparent(now, &mut out);
        }
        out
    }

    /// Hands this node a `message` that arrived from `from`.
    ///
    /// Messages from a node that is not a peer are ignored.
    pub fn handle(&mut self, now: u64, from: PublicKey, message: Message) -> Vec<Envelope> {
        let mut out = Vec::new();
        if !self.peers.contains(&from) {
            return out;
        }
        match message {
            Message::Announce(announcement) => {
                self.receive_announce(now, from, announcement, &mut out)
            }
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
    fn announcements(&self) -> impl Iterator<Item = &Announcement> {
        std::iter::once(&self.announcement)
            .chain(self.infos.values().map(|info| &info.announcement))
    }

    /// What this node last heard about `key`, if it still holds it.
    fn info(&self, key: &PublicKey) -> Option<&Announcement> {
        self.infos.get(key).map(|info| &info.announcement)
    }

    fn receive_announce(
        &mut self,
        now: u64,
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
            .info(&author)
            .is_some_and(|known| !announcement.supersedes(known))
        {
            return;
        }
        // Only an announcement that was accepted restarts the expiry clock. A
        // repeat of one already held is not evidence its author is still there,
        // and treating it as such would let an echo keep a dead node alive.
        self.infos.insert(
            author,
            Info {
                announcement: announcement.clone(),
                heard_at: now,
            },
        );
        // Only news travels. Gossip therefore terminates: each hop strictly
        // advances some author's announcement, and that cannot rise forever.
        self.gossip(Message::Announce(announcement), Some(from), out);
        self.reparent(now, out);
    }

    /// Reconsiders which peer to sit below, announcing the move if it changed.
    fn reparent(&mut self, now: u64, out: &mut Vec<Envelope>) {
        let best = self.best_position();
        if best.path() != self.announcement.path() {
            self.announce(now, best, out);
        }
    }

    /// Takes up `position`, stamps it with a fresh sequence number, and tells
    /// every peer.
    fn announce(&mut self, now: u64, position: Announcement, out: &mut Vec<Envelope>) {
        // Saturating rather than wrapping: sequence numbers only mean anything
        // while they increase, and reissues make them climb with the clock
        // rather than only with topology. The ceiling is unreachable, but a
        // node stuck at it going quiet beats one that starts over at zero.
        let seq = self.announcement.seq().saturating_add(1);
        self.announcement = position.with_seq(seq);
        self.announced_at = now;
        self.gossip(Message::Announce(self.announcement.clone()), None, out);
    }

    /// The most preferred position available: below some peer, or self-rooted.
    fn best_position(&self) -> Announcement {
        // The sequence number is irrelevant to the comparison; the caller
        // stamps the winner with the right one.
        let seq = self.announcement.seq();
        let mut best = Announcement::root_of(self.key, seq);
        for peer in &self.peers {
            let Some(info) = self.info(peer) else {
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
        let dst_path = self.info(dst)?.path();
        let mut shortest = distance(self.announcement.path(), dst_path);
        let mut best = None;
        for &peer in &self.peers {
            let Some(info) = self.info(&peer) else {
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

    /// A node linked to a peer holding a smaller key, having just heard where
    /// that peer sits, so it has taken up a position below it.
    fn node_below_a_peer(now: u64) -> Node {
        let mut node = Node::new(0, key(2));
        node.add_peer(0, key(1));
        node.handle(
            now,
            key(1),
            Message::Announce(Announcement::root_of(key(1), 0)),
        );
        node
    }

    #[test]
    fn a_new_node_is_its_own_root() {
        let node = Node::new(0, key(7));
        assert_eq!(node.root(), key(7));
        assert_eq!(node.parent(), None);
        assert_eq!(node.path(), [key(7)]);
    }

    #[test]
    fn adding_a_peer_offers_it_everything_known() {
        let mut node = Node::new(0, key(2));
        let out = node.add_peer(0, key(1));
        assert_eq!(out.len(), 1, "only its own announcement is known so far");
        assert_eq!(out[0].to, key(1));
        assert_eq!(
            out[0].message,
            Message::Announce(Announcement::root_of(key(2), 0))
        );
    }

    #[test]
    fn a_node_will_not_peer_with_itself() {
        let mut node = Node::new(0, key(1));
        assert!(node.add_peer(0, key(1)).is_empty());
        assert_eq!(node.peers().count(), 0);
    }

    #[test]
    fn messages_from_strangers_are_ignored() {
        let mut node = Node::new(0, key(2));
        let stranger = Announcement::root_of(key(1), 0);
        assert!(
            node.handle(0, key(1), Message::Announce(stranger))
                .is_empty()
        );
        assert_eq!(node.root(), key(2), "the tree did not move");
    }

    #[test]
    fn a_node_adopts_a_peer_holding_a_smaller_key_as_its_root() {
        let node = node_below_a_peer(0);
        assert_eq!(node.root(), key(1));
        assert_eq!(node.parent(), Some(key(1)));
        assert_eq!(node.path(), [key(1), key(2)]);
    }

    #[test]
    fn a_node_keeps_a_smaller_key_than_its_peer() {
        let mut node = Node::new(0, key(1));
        node.add_peer(0, key(2));
        node.handle(
            0,
            key(2),
            Message::Announce(Announcement::root_of(key(2), 0)),
        );

        assert_eq!(node.root(), key(1), "the smaller key stays the root");
        assert_eq!(node.parent(), None);
    }

    #[test]
    fn sending_to_an_unknown_destination_fails() {
        let mut node = Node::new(0, key(1));
        assert_eq!(node.send(key(9), b"hi".to_vec()), Err(SendError::NoRoute));
    }

    #[test]
    fn sending_to_oneself_delivers_locally() {
        let mut node = Node::new(0, key(1));
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
        let mut node = Node::new(0, key(2));
        node.add_peer(0, key(1));
        node.add_peer(0, key(3));

        let fresh = Announcement::root_of(key(1), 5);
        assert!(!node.handle(0, key(1), Message::Announce(fresh)).is_empty());

        let stale = Announcement::root_of(key(1), 4);
        assert!(
            node.handle(0, key(1), Message::Announce(stale)).is_empty(),
            "old news must not be forwarded, or gossip would never settle"
        );
    }

    #[test]
    fn an_announcement_that_is_never_reissued_expires() {
        let mut node = node_below_a_peer(0);
        assert_eq!(node.known().count(), 1);

        let out = node.tick(Timing::DEFAULT.expiry);

        assert_eq!(node.known().count(), 0, "the announcement was forgotten");
        assert_eq!(node.root(), key(2), "and with it, the route to the root");
        assert_eq!(node.parent(), None);
        assert!(
            out.iter().any(|envelope| envelope.to == key(1)),
            "the peer is told this node moved"
        );
    }

    #[test]
    fn a_reissued_announcement_survives() {
        let expiry = Timing::DEFAULT.expiry;
        let mut node = node_below_a_peer(0);

        // The author reissues just before the deadline, one sequence number on.
        node.handle(
            expiry - 1,
            key(1),
            Message::Announce(Announcement::root_of(key(1), 1)),
        );
        node.tick(expiry);

        assert_eq!(node.root(), key(1), "the reissue kept it alive");
        assert_eq!(node.known().count(), 1);
    }

    #[test]
    fn a_repeat_does_not_restart_the_expiry_clock() {
        let expiry = Timing::DEFAULT.expiry;
        let mut node = node_below_a_peer(0);

        // The same announcement over again, rather than a newer one.
        node.handle(
            expiry - 1,
            key(1),
            Message::Announce(Announcement::root_of(key(1), 0)),
        );
        node.tick(expiry);

        assert_eq!(
            node.root(),
            key(2),
            "an echo is not evidence its author is still there"
        );
    }

    #[test]
    fn a_node_reissues_its_own_announcement_on_schedule() {
        let refresh = Timing::DEFAULT.refresh;
        let mut node = Node::new(0, key(1));
        node.add_peer(0, key(2));

        assert!(node.tick(refresh - 1).is_empty(), "not due yet");

        let out = node.tick(refresh);
        assert_eq!(out.len(), 1, "one peer, one reissue");
        assert_eq!(out[0].to, key(2));
        assert_eq!(
            out[0].message,
            Message::Announce(Announcement::root_of(key(1), 1)),
            "a fresh sequence number on an unchanged path"
        );
        assert_eq!(node.path(), [key(1)], "reissuing does not move the tree");
    }

    #[test]
    fn a_node_that_starts_over_is_believed_once_the_old_one_has_expired() {
        let expiry = Timing::DEFAULT.expiry;
        let mut node = node_below_a_peer(0);

        // The peer had climbed to a high sequence number before it went quiet.
        node.handle(
            1,
            key(1),
            Message::Announce(Announcement::root_of(key(1), 500)),
        );
        node.tick(expiry + 1);
        assert_eq!(node.known().count(), 0);

        // It comes back having started over at zero. Without expiry that would
        // have looked like ancient news and been thrown away.
        node.handle(
            expiry + 1,
            key(1),
            Message::Announce(Announcement::root_of(key(1), 0)),
        );
        assert_eq!(node.root(), key(1), "the returning node is believed");
        assert_eq!(node.parent(), Some(key(1)));
    }

    #[test]
    fn a_node_with_a_custom_schedule_keeps_to_it() {
        let timing = Timing {
            refresh: 10,
            expiry: 40,
        };
        let mut node = Node::with_timing(0, key(2), timing);
        node.add_peer(0, key(1));
        node.handle(
            0,
            key(1),
            Message::Announce(Announcement::root_of(key(1), 0)),
        );

        node.tick(39);
        assert_eq!(node.root(), key(1), "not yet due to expire");
        node.tick(40);
        assert_eq!(node.root(), key(2), "expired on the caller's own scale");
    }
}
