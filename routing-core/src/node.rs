//! The per-node routing state machine.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;

use crate::key::PublicKey;
use crate::message::{Envelope, Found, Lookup, Message, Nonce, Packet, Traffic};
use crate::signature::Signer;
use crate::summary::Summary;
use crate::tree::{Announcement, Consent, Cost, Hop, distance};

/// Why a packet could not be handed to the network.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SendError {
    /// Nothing here knows where the destination sits.
    ///
    /// A node holds the coordinates of its peers and of whoever it has already
    /// looked up; for anything else, ask the network with [`Node::lookup`] and
    /// try again once the answer has arrived.
    Unknown,
    /// The destination's position is known, but no linked peer stands closer to
    /// it than this node does, so the packet has nowhere to go but backwards.
    NoRoute,
}

impl fmt::Display for SendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown => f.write_str("destination has not been looked up"),
            Self::NoRoute => f.write_str("no route to destination"),
        }
    }
}

impl std::error::Error for SendError {}

/// Something a peer said that no honest node could have said.
///
/// These are not disagreements. A node whose view is out of date says wrong
/// things constantly and that is what soft state is for; every fault here is
/// either a signature that does not check out or a message that no
/// implementation of this protocol would ever send. Nothing an honest peer
/// does under any timing, any topology change, or any amount of staleness
/// produces one — which is what makes acting on them safe. A rule that fired
/// on stale routing state instead would be a way for one node to make two
/// others drop each other.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Fault {
    /// An announcement about somebody other than the peer that sent it.
    ///
    /// Announcements cross one link and describe their sender. Relaying one is
    /// not a thing this protocol does.
    AnnouncementAboutAnother,
    /// An announcement with a hop that was not signed by the node it names, or
    /// that sits on a consent that node never gave.
    ForgedAnnouncement,
    /// A consent that was not this peer agreeing to carry this node.
    MisdirectedConsent,
    /// An answer to a search that its own subject did not vouch for.
    ///
    /// Every node on an answer's way home checks it before passing it on, so
    /// an answer that does not hold together cannot have travelled: whoever
    /// handed this one over is where it was made up.
    ForgedAnswer,
}

impl fmt::Display for Fault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AnnouncementAboutAnother => f.write_str("announced a position for another node"),
            Self::ForgedAnnouncement => f.write_str("announced a position nobody signed for"),
            Self::MisdirectedConsent => f.write_str("gave a consent meant for somebody else"),
            Self::ForgedAnswer => f.write_str("answered a search with something unsigned"),
        }
    }
}

/// A peer dropped for committing a [`Fault`], and what it did.
///
/// The routing state is gone by the time a caller sees this — the node stops
/// forwarding to the peer, stops sitting below it, and stops summarising over
/// the link, all before returning. The link itself belongs to whoever brought
/// it up, which is why this is reported as well as acted on: closing the
/// socket, refusing the next handshake, or deciding it was a bad build and
/// bringing it back are all the caller's to make.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Eviction {
    /// The peer that was dropped.
    pub peer: PublicKey,
    /// What it did.
    pub fault: Fault,
}

impl fmt::Display for Eviction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} {}", self.peer, self.fault)
    }
}

/// What became of an announcement handed to [`Node::remember`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Remembered {
    /// Taken up: it was news, and it checked out.
    Stored,
    /// Set aside, and nobody is at fault: this node is its author, or it is a
    /// repeat or an older copy of something already held.
    Ignored,
    /// Refused, and whoever sent it is at fault.
    Forged,
}

/// How long announcements live, and how often a node renews its own.
///
/// Both are durations in whatever unit the caller counts `now` in. The core
/// never interprets them and never reads a clock of its own; it only subtracts
/// one instant it was handed from another. That is exactly why there is no
/// default: a number of its own choosing would be a number in a unit it has no
/// way of knowing, so every [`Node`] is handed one and somebody chose it.
///
/// `refresh` must be comfortably smaller than `expiry`. A node's announcement
/// has to be reissued several times over before its peers would otherwise give
/// up on it. Set them too close together and a perfectly healthy network
/// forgets nodes it is about to hear from again.
///
/// `expiry` also bounds how long a looked-up position is kept. A conversation
/// that outlives it costs another lookup, which is the price of not keeping
/// what nobody is using.
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
    ///
    /// Named for the unit rather than for being usual, since the numbers mean
    /// nothing without it: a caller counting in seconds that reached for this
    /// would be asking to forget nothing for the best part of an hour.
    pub const MILLISECONDS: Self = Self {
        refresh: 1_000,
        expiry: 3_000,
    };
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

/// What a node keeps about one link.
///
/// A fixed amount, whatever the network beyond it looks like. The peer's own
/// position is not here but among the announcements the node holds, since that
/// is where routing reads it from.
#[derive(Clone, Debug)]
struct Peer {
    /// What crossing the link costs.
    cost: Cost,
    /// What the peer says lies on its side of it.
    beyond: Summary,
    /// What this node last said lies on its own side, or `None` if it has said
    /// nothing because the link is not part of the tree. Keeping it is what
    /// lets a node speak only when something has changed, and so fall quiet.
    told: Option<Summary>,
    /// The peer's agreement that this node may sit below it, and at what
    /// price, or `None` while none has arrived. Without one this node cannot
    /// take up a position below the peer at all, however attractive it looks.
    consent: Option<Consent>,
}

/// A search this node has asked and not yet had an answer to.
///
/// Keeping it is what tells an answer from an assertion. Without it any peer
/// could push positions into this node unbidden, and the map they land in is
/// the one thing here that grows with use.
#[derive(Clone, Copy, Debug)]
struct Pending {
    /// The node being looked for.
    target: PublicKey,
    /// When the search went out, so that unanswered ones do not accumulate.
    asked_at: u64,
}

/// One node's complete routing state.
///
/// A node is a pure state machine: every method takes an event and returns the
/// messages the event produced. It never blocks, never touches the operating
/// system, and never reads a clock. Time enters only as the `now` argument the
/// caller passes in — an opaque count in the caller's own unit, which is only
/// ever subtracted from a later `now`, so its origin is arbitrary but it must
/// not go backwards.
///
/// What it holds is a fixed amount per link, its own position, and the
/// positions of the nodes it is currently talking to. Nothing here grows with
/// the size of the network.
///
/// The `S` is the cryptography it speaks with: a node signs everything it says
/// about itself and checks everything it is told about anybody else, but this
/// crate supplies no algorithm of its own. See [`Signer`].
#[derive(Clone, Debug)]
pub struct Node<S> {
    /// What this node signs as. Its public half is `key`, kept beside it
    /// because routing asks for it constantly and asks the signer once.
    signer: S,
    key: PublicKey,
    timing: Timing,
    /// This node's own announcement. It is the sole author of this value.
    announcement: Announcement,
    /// When this node last issued the announcement above.
    announced_at: u64,
    /// The links this node holds.
    peers: BTreeMap<PublicKey, Peer>,
    /// Where other nodes sit: every peer, since a peer announces itself across
    /// the link, and whoever else has been looked up and not yet forgotten.
    infos: BTreeMap<PublicKey, Info>,
    /// The searches this node has outstanding, by the nonce each went out
    /// with. Expiry bounds it exactly as it bounds `infos`.
    pending: BTreeMap<Nonce, Pending>,
    delivered: Vec<Packet>,
    evicted: Vec<Eviction>,
}

impl<S: Signer> Node<S> {
    /// Creates an isolated node, which necessarily believes it is its own root.
    ///
    /// Its address is whatever key `signer` speaks for, so an identity and the
    /// means of proving it arrive together and cannot come apart. `timing` says
    /// how long state lives, counted in the same unit as `now` — see [`Timing`]
    /// for why the core will not pick it.
    pub fn new(now: u64, signer: S, timing: Timing) -> Self {
        let key = signer.public_key();
        let announcement = Announcement::root_of(&signer, 0);
        Self {
            signer,
            key,
            timing,
            announcement,
            announced_at: now,
            peers: BTreeMap::new(),
            infos: BTreeMap::new(),
            pending: BTreeMap::new(),
            delivered: Vec::new(),
            evicted: Vec::new(),
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

    /// The path from the root down to this node, priced link by link.
    pub fn path(&self) -> &[Hop] {
        self.announcement.path()
    }

    /// What the walk from this node up to the root costs.
    pub fn cost_to_root(&self) -> u64 {
        self.announcement.cost_to_root()
    }

    /// The peers this node holds a link to, and what each link costs.
    pub fn peers(&self) -> impl Iterator<Item = (PublicKey, Cost)> + '_ {
        self.peers.iter().map(|(&peer, state)| (peer, state.cost))
    }

    /// What this node last told `peer` lies on its own side of their link.
    ///
    /// `None` when the link is not part of the spanning tree, since that is the
    /// only sort a summary crosses.
    pub fn summary_for(&self, peer: PublicKey) -> Option<Summary> {
        self.peers.get(&peer).and_then(|state| state.told)
    }

    /// The other nodes this one currently holds a position for.
    ///
    /// Its peers, and whoever it has looked up and not yet forgotten. It is
    /// exactly the set of destinations [`send`](Self::send) can name without
    /// asking the network first, and expiry is what keeps it from growing.
    pub fn known(&self) -> impl Iterator<Item = PublicKey> + '_ {
        self.infos.keys().copied()
    }

    /// Moves this node's clock to `now`, expiring and reissuing state.
    ///
    /// Three things happen, in that order. Positions not heard again within
    /// [`Timing::expiry`] are forgotten, which is how a node that vanished
    /// stops being remembered as a route to nowhere. Losing them may have cost
    /// this node its parent or changed what it can reach, so it reconsiders
    /// both. Finally, if its own announcement has stood for [`Timing::refresh`]
    /// without being reissued, it reissues it, which is what stops its peers
    /// forgetting *it*.
    ///
    /// This is the only method that involves the passage of time, and a node
    /// that is never ticked behaves exactly as though it did not exist: state
    /// then changes only when a message arrives or a link moves.
    pub fn tick(&mut self, now: u64) -> Vec<Envelope> {
        let mut out = Vec::new();
        let expiry = self.timing.expiry;
        self.infos
            .retain(|_, info| now.saturating_sub(info.heard_at) < expiry);
        // A search nobody answered is forgotten on the same schedule. Its
        // answer arriving afterwards is not an answer any more, which costs
        // the asker a question it was free to ask again.
        self.pending
            .retain(|_, asked| now.saturating_sub(asked.asked_at) < expiry);
        self.settle(now, &mut out);
        if now.saturating_sub(self.announced_at) >= self.timing.refresh {
            // The same walk over again, freshly stamped and signed. What stops
            // a peer forgetting this node is that the number climbed, not that
            // anything moved. The signer is this node's own, so the restamp
            // cannot be refused.
            if let Some(reissued) = self.announcement.with_seq(&self.signer, self.next_seq()) {
                self.announce(now, reissued, &mut out);
            }
        }
        out
    }

    /// Brings up a link to `peer`, costing `cost` to cross.
    ///
    /// The peer is told where this node sits and given leave to sit below it
    /// at `cost`, and nothing else: that is all it needs in order to decide
    /// whether to, and it learns the rest of the network the way anybody does,
    /// by asking.
    ///
    /// Calling this for a link that is already up re-prices it instead, which
    /// is how a caller that keeps measuring its links reports what it found.
    pub fn add_peer(&mut self, now: u64, peer: PublicKey, cost: Cost) -> Vec<Envelope> {
        let mut out = Vec::new();
        if peer == self.key {
            return out;
        }
        match self.peers.get_mut(&peer) {
            Some(state) => {
                if state.cost == cost {
                    return out;
                }
                state.cost = cost;
            }
            None => {
                self.peers.insert(
                    peer,
                    Peer {
                        cost,
                        beyond: Summary::new(),
                        told: None,
                        consent: None,
                    },
                );
                out.push(Envelope {
                    to: peer,
                    message: Message::Announce(self.announcement.clone()),
                });
            }
        }
        // Either way the peer is owed this node's agreement to carry it, at
        // the price this node has just put on the link. A re-priced link is a
        // different bargain, so the old consent is withdrawn by being
        // replaced: the peer cannot go on announcing the old number, because
        // the number is part of what was signed.
        out.push(Envelope {
            to: peer,
            message: Message::Consent(Consent::issue(&self.signer, peer, cost)),
        });
        self.settle(now, &mut out);
        out
    }

    /// Tears down the link to `peer`.
    ///
    /// What this node learned *through* `peer` is not withdrawn here, because
    /// it cannot tell which of those positions were only reachable that way.
    /// They are left to expire on their own, which is what [`tick`](Self::tick)
    /// is for. Until they do, routing towards a departed node fails by dropping
    /// the packet at the dead end.
    pub fn remove_peer(&mut self, now: u64, peer: PublicKey) -> Vec<Envelope> {
        let mut out = Vec::new();
        if self.peers.remove(&peer).is_some() {
            self.settle(now, &mut out);
        }
        out
    }

    /// Hands this node a `message` that arrived from `from`.
    ///
    /// Messages from a node that is not a peer are ignored.
    pub fn handle(&mut self, now: u64, from: PublicKey, message: Message) -> Vec<Envelope> {
        let mut out = Vec::new();
        if !self.peers.contains_key(&from) {
            return out;
        }
        match message {
            Message::Announce(announcement) => {
                self.receive_announce(now, from, announcement, &mut out)
            }
            Message::Summary(summary) => self.receive_summary(now, from, summary, &mut out),
            Message::Consent(consent) => self.receive_consent(now, from, consent, &mut out),
            Message::Lookup(lookup) => self.receive_lookup(from, lookup, &mut out),
            Message::Found(found) => self.receive_found(now, from, found, &mut out),
            Message::Traffic(traffic) => self.forward(traffic, &mut out),
        }
        out
    }

    /// Originates a packet addressed to `dst`.
    ///
    /// Fails with [`SendError::Unknown`] unless this node holds `dst`'s
    /// position, which it does for a peer and for anything it has looked up
    /// recently. That position travels with the packet, since no node further
    /// along the way holds it either.
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
        let dst_path = self.info(&dst).ok_or(SendError::Unknown)?.path().to_vec();
        let peer = self.next_hop(&dst_path).ok_or(SendError::NoRoute)?;
        Ok(vec![Envelope {
            to: peer,
            message: Message::Traffic(Traffic { dst_path, packet }),
        }])
    }

    /// Asks the network where `target` sits.
    ///
    /// The search goes to every tree neighbour whose summary admits the target
    /// might lie beyond it, and each of those does the same, so it fans out
    /// down the branches that could hold it and no others. A summary never
    /// misses a key it holds, so on a settled tree a search cannot fail to find
    /// a node that is there; one that claims a key it does not hold costs the
    /// search a detour and nothing more.
    ///
    /// The answer arrives later, as a message like any other, and is what makes
    /// a subsequent [`send`](Self::send) to `target` work.
    ///
    /// `nonce` must be fresh and unguessable, and comes from the caller for the
    /// same reason `now` does: this crate touches no operating system and so
    /// has no randomness of its own. The node being looked for signs it, which
    /// is the only part of an answer that a recording of an older one cannot
    /// supply — a signature says who, and the nonce is what makes it say when.
    /// The search is remembered until it is answered or expires, so an answer
    /// nobody asked for is not mistaken for one.
    ///
    /// A search that finds nothing simply goes unanswered, and this node is
    /// free to ask again with a new nonce.
    pub fn lookup(&mut self, now: u64, target: PublicKey, nonce: Nonce) -> Vec<Envelope> {
        let mut out = Vec::new();
        if target == self.key {
            return out;
        }
        self.pending.insert(
            nonce,
            Pending {
                target,
                asked_at: now,
            },
        );
        self.search(
            &Lookup {
                target,
                nonce,
                trail: vec![self.key],
            },
            &mut out,
        );
        out
    }

    /// Takes the packets addressed to this node that have arrived so far.
    pub fn take_delivered(&mut self) -> Vec<Packet> {
        std::mem::take(&mut self.delivered)
    }

    /// Takes the peers dropped for misbehaving since this was last asked.
    ///
    /// The routing state is already gone: a node evicts a peer the moment it
    /// catches it, in the same call that caught it, and the envelopes that
    /// call returns are the network being told about the hole. What is left
    /// for the caller is the link itself, which the core never held — see
    /// [`Eviction`].
    pub fn take_evicted(&mut self) -> Vec<Eviction> {
        std::mem::take(&mut self.evicted)
    }

    /// The consent this node holds from `peer`, if any has arrived.
    ///
    /// It is what lets this node sit below that peer, and the price in it is
    /// the one its own hop would carry. `None` means the peer has not yet
    /// agreed to carry this node, which is a position it cannot take up.
    pub fn consent_from(&self, peer: PublicKey) -> Option<Consent> {
        self.peers.get(&peer).and_then(|state| state.consent)
    }

    /// What this node last heard about `key`, if it still holds it.
    fn info(&self, key: &PublicKey) -> Option<&Announcement> {
        self.infos.get(key).map(|info| &info.announcement)
    }

    /// Whether an announcement is worth looking at twice: not this node's own,
    /// and not something already held in a form that supersedes it.
    ///
    /// Only news restarts the expiry clock. A repeat of a position already held
    /// is not evidence its author is still there, and treating it as such would
    /// let an echo keep a dead node alive.
    fn is_news(&self, announcement: &Announcement) -> bool {
        // A node is the only authority on where it sits, so anything arriving
        // about this one is at best a stale echo of its own.
        announcement.author() != self.key
            && !self
                .info(&announcement.author())
                .is_some_and(|known| !announcement.supersedes(known))
    }

    /// Takes note of where another node says it sits, saying what became of it.
    ///
    /// Everything that enters here came off a link, so this is where a forgery
    /// stops: each hop has to be signed by the node it names and agreed to by
    /// the node above it, which no amount of relaying can arrange for a node
    /// that never sat there. Cheaper questions are asked first, but nothing is
    /// kept or acted on until this one is answered.
    fn remember(&mut self, now: u64, announcement: Announcement) -> Remembered {
        if !self.is_news(&announcement) {
            return Remembered::Ignored;
        }
        if !announcement.verify::<S>() {
            return Remembered::Forged;
        }
        self.keep(now, announcement);
        Remembered::Stored
    }

    /// The same, for an announcement whose signatures the caller has already
    /// checked — which the answer to a search has, on every hop of its way
    /// home. Reports whether it was news.
    fn remember_checked(&mut self, now: u64, announcement: Announcement) -> bool {
        let news = self.is_news(&announcement);
        if news {
            self.keep(now, announcement);
        }
        news
    }

    /// Files an announcement that has passed everything.
    fn keep(&mut self, now: u64, announcement: Announcement) {
        self.infos.insert(
            announcement.author(),
            Info {
                announcement,
                heard_at: now,
            },
        );
    }

    /// Drops a peer that has said something no honest node could say, and
    /// notes it for the caller to find with [`take_evicted`](Self::take_evicted).
    ///
    /// Everything the peer was holding up goes with it: this node stops
    /// forwarding to it, stops sitting below it if it was the parent, and
    /// stops summarising over the link, all of which `settle` says out loud.
    /// What it learned *through* the peer is left to expire, exactly as
    /// [`remove_peer`](Self::remove_peer) leaves it.
    fn evict(&mut self, now: u64, peer: PublicKey, fault: Fault, out: &mut Vec<Envelope>) {
        if self.peers.remove(&peer).is_none() {
            return;
        }
        self.evicted.push(Eviction { peer, fault });
        self.settle(now, out);
    }

    fn receive_announce(
        &mut self,
        now: u64,
        from: PublicKey,
        announcement: Announcement,
        out: &mut Vec<Envelope>,
    ) {
        // An announcement crosses exactly one link and describes whoever sent
        // it. Nothing relays one, so a node hears about its peers and about
        // nobody else, which is the whole of what keeps this state constant —
        // and a peer sending one about anybody else is not a peer running this
        // protocol.
        if announcement.author() != from {
            self.evict(now, from, Fault::AnnouncementAboutAnother, out);
            return;
        }
        match self.remember(now, announcement) {
            Remembered::Stored => self.settle(now, out),
            Remembered::Ignored => {}
            Remembered::Forged => self.evict(now, from, Fault::ForgedAnnouncement, out),
        }
    }

    fn receive_consent(
        &mut self,
        now: u64,
        from: PublicKey,
        consent: Consent,
        out: &mut Vec<Envelope>,
    ) {
        // A consent names both ends, so one meant for somebody else — or
        // coming from somebody other than the node that signed it — is not a
        // thing an honest peer would hand over. Its signature needs no
        // checking here: a `Consent` cannot be built without one that checks
        // out, so the only question left is who it is between.
        if consent.parent() != from || consent.child() != self.key {
            self.evict(now, from, Fault::MisdirectedConsent, out);
            return;
        }
        let Some(state) = self.peers.get_mut(&from) else {
            return;
        };
        // Only a change is worth working through, the same as a summary: a
        // peer reissuing the bargain it already offered ends here.
        if state.consent == Some(consent) {
            return;
        }
        state.consent = Some(consent);
        self.settle(now, out);
    }

    fn receive_summary(
        &mut self,
        now: u64,
        from: PublicKey,
        summary: Summary,
        out: &mut Vec<Envelope>,
    ) {
        let Some(state) = self.peers.get_mut(&from) else {
            return;
        };
        // Only a change is worth working through, which is what brings the
        // exchange to rest: a summary that says nothing new ends here.
        if state.beyond == summary {
            return;
        }
        state.beyond = summary;
        self.settle(now, out);
    }

    fn receive_lookup(&mut self, from: PublicKey, mut lookup: Lookup, out: &mut Vec<Envelope>) {
        // A search that has already been here has gone round in a circle, which
        // a half-settled tree can arrange. Refusing it is the rule that keeps
        // the tree acyclic, applied to a walk rather than to a path.
        if lookup.trail.contains(&self.key) {
            return;
        }
        if lookup.target == self.key {
            // Signing the search's own nonce is what makes this evidence
            // rather than a claim: the walk below is as old as its signatures
            // allow, but nobody could have produced this part in advance.
            out.push(Envelope {
                to: from,
                message: Message::Found(Found::answer(
                    &self.signer,
                    self.announcement.clone(),
                    lookup.nonce,
                    lookup.trail,
                )),
            });
            return;
        }
        lookup.trail.push(self.key);
        self.search(&lookup, out);
    }

    fn receive_found(
        &mut self,
        now: u64,
        from: PublicKey,
        mut found: Found,
        out: &mut Vec<Envelope>,
    ) {
        // The trail is the way home and this node should be standing on the end
        // of it. Anything else is the answer to a search that never came
        // through here, and this node is not on its way anywhere.
        if found.trail.pop() != Some(self.key) {
            return;
        }
        match found.trail.last() {
            // Somebody else asked, and this node is a step on the way back.
            // Nothing is passed on unchecked, which is what makes the check
            // worth acting on: every node between the answer and its asker
            // asks the same question, so one that does not hold together
            // cannot have travelled, and whoever handed it over made it up.
            Some(&back) if self.peers.contains_key(&back) => {
                if !found.verify::<S>() {
                    self.evict(now, from, Fault::ForgedAnswer, out);
                    return;
                }
                out.push(Envelope {
                    to: back,
                    message: Message::Found(found),
                });
            }
            // The trail is spent, so this node is the one that asked — if it
            // asked at all. An answer to a question nobody here put, or to a
            // different question than the nonce says, is not an answer, and
            // recognising that is what stops a peer pushing positions into
            // this node unbidden. Those cheap questions come first, so that
            // arriving unbidden costs a signature check nothing.
            None => {
                let Some(pending) = self.pending.get(&found.nonce) else {
                    return;
                };
                if pending.target != found.announcement.author() {
                    return;
                }
                if !found.verify::<S>() {
                    self.evict(now, from, Fault::ForgedAnswer, out);
                    return;
                }
                // Answered, so the question is closed. Asking again means a
                // new nonce, which is what stops one answer serving twice.
                self.pending.remove(&found.nonce);
                if self.remember_checked(now, found.announcement) {
                    self.settle(now, out);
                }
            }
            // The link the search came in over has gone down since. Dropping
            // the answer costs the asker a retry it was free to make anyway.
            Some(_) => {}
        }
    }

    /// Passes a search on to every tree neighbour that might hold its target.
    fn search(&self, lookup: &Lookup, out: &mut Vec<Envelope>) {
        for (&peer, state) in &self.peers {
            if !lookup.trail.contains(&peer)
                && self.is_tree_neighbour(peer)
                && state.beyond.contains(lookup.target)
            {
                out.push(Envelope {
                    to: peer,
                    message: Message::Lookup(lookup.clone()),
                });
            }
        }
    }

    /// Reconsiders where this node sits and what lies on its side of each tree
    /// link, saying whatever changed.
    fn settle(&mut self, now: u64, out: &mut Vec<Envelope>) {
        self.reparent(now, out);
        self.resummarise(out);
    }

    /// The sequence number to stamp the next announcement with.
    ///
    /// Saturating rather than wrapping: sequence numbers only mean anything
    /// while they increase, and reissues make them climb with the clock rather
    /// than only with topology. The ceiling is unreachable, but a node stuck at
    /// it going quiet beats one that starts over at zero.
    fn next_seq(&self) -> u64 {
        self.announcement.seq().saturating_add(1)
    }

    /// Reconsiders which peer to sit below, announcing the move if it changed.
    fn reparent(&mut self, now: u64, out: &mut Vec<Envelope>) {
        let best = self.best_position(self.next_seq());
        // Only a different walk counts as moving. Comparing the announcements
        // whole would count every restamp above as a move, and the network
        // would spend itself telling itself that nothing had happened.
        if !best.same_position(&self.announcement) {
            self.announce(now, best, out);
        }
    }

    /// Takes up `position` and tells every peer.
    fn announce(&mut self, now: u64, position: Announcement, out: &mut Vec<Envelope>) {
        self.announcement = position;
        self.announced_at = now;
        let message = Message::Announce(self.announcement.clone());
        for &peer in self.peers.keys() {
            out.push(Envelope {
                to: peer,
                message: message.clone(),
            });
        }
    }

    /// The most preferred position available: below some peer, or self-rooted.
    ///
    /// Every candidate is signed as it is built, since a position this node
    /// cannot sign is not one it could take up — and every candidate below a
    /// peer needs that peer's consent for the same reason. A node with nowhere
    /// it is welcome is the root of its own tree, which is where every node
    /// starts.
    fn best_position(&self, seq: u64) -> Announcement {
        let mut best = Announcement::root_of(&self.signer, seq);
        for (peer, state) in &self.peers {
            let Some(info) = self.info(peer) else {
                continue;
            };
            // No consent, no position. The price in it is the peer's, not this
            // node's, so what a candidate costs to reach is what the node
            // carrying it said it would cost.
            let Some(consent) = &state.consent else {
                continue;
            };
            let Some(candidate) = info.extend(&self.signer, consent, seq) else {
                continue;
            };
            if candidate.preference_cmp(&best) == Ordering::Less {
                best = candidate;
            }
        }
        best
    }

    /// Whether the link to `peer` is part of the spanning tree.
    ///
    /// Summaries cross tree links and no others. Folding them together around a
    /// cycle would carry every key back to where it came from, until every
    /// summary claimed the whole network and none of them pruned anything. Over
    /// a tree the fixed point is exactly "what lies on the far side of this
    /// link", and a walk guided by them cannot come back on itself.
    fn is_tree_neighbour(&self, peer: PublicKey) -> bool {
        self.parent() == Some(peer)
            || self
                .info(&peer)
                .is_some_and(|info| info.parent() == Some(self.key))
    }

    /// What this node would tell `peer` lies on its own side of their link:
    /// itself, and whatever the other tree links say lies beyond them.
    ///
    /// Leaving out what `peer` said is the whole of it. Without that, each of
    /// the two would hand the other back the other's own subtree, and they
    /// would end up agreeing that everything was on both sides.
    fn summary_beyond(&self, peer: PublicKey) -> Summary {
        let mut summary = Summary::new();
        summary.insert(self.key);
        for (&other, state) in &self.peers {
            if other != peer && self.is_tree_neighbour(other) {
                summary.union(&state.beyond);
            }
        }
        summary
    }

    /// Works out what to say over each tree link, and says it where it changed.
    fn resummarise(&mut self, out: &mut Vec<Envelope>) {
        // Every link is decided before any is written back, because deciding
        // one means reading all the others and no link can be held mutably
        // while that happens. One entry per peer, in the order they iterate.
        let wanted: Vec<Option<Summary>> = self
            .peers
            .keys()
            .map(|&peer| {
                self.is_tree_neighbour(peer)
                    .then(|| self.summary_beyond(peer))
            })
            .collect();
        for ((&peer, state), summary) in self.peers.iter_mut().zip(wanted) {
            if state.told == summary {
                continue;
            }
            state.told = summary;
            // A link that has just left the tree is told nothing rather than
            // told it holds nothing: the far end works out the same thing from
            // its own side and stops summarising back.
            if let Some(summary) = summary {
                out.push(Envelope {
                    to: peer,
                    message: Message::Summary(summary),
                });
            }
        }
    }

    fn forward(&mut self, traffic: Traffic, out: &mut Vec<Envelope>) {
        if traffic.packet.dst == self.key {
            self.delivered.push(traffic.packet);
            return;
        }
        // Without a next hop this is a dead end. Ironwood would report the
        // broken path back through the tree and look the destination up again;
        // this core drops the packet, which is that minus the recovery.
        if let Some(peer) = self.next_hop(&traffic.dst_path) {
            out.push(Envelope {
                to: peer,
                message: Message::Traffic(traffic),
            });
        }
    }

    /// The peer to hand a packet bound for `dst_path` to, if any is worth
    /// handing it to.
    ///
    /// Only a peer strictly closer to the destination than this node qualifies.
    /// Requiring strict progress is what makes forwarding loop-free without any
    /// per-packet state: distance to the destination falls at every hop and
    /// cannot fall below zero, so a packet either arrives or is dropped. The
    /// destination's path rides along in the packet rather than being looked up
    /// here, so every node on the route measures against the same target.
    ///
    /// Among the peers that qualify, the cheapest wins: the link's own cost
    /// plus the walk left after crossing it. That sum is exactly what the
    /// packet pays if it follows the tree from there, so it is an upper bound
    /// on the real price, and weighing it is what stops a node posting a packet
    /// down an expensive shortcut to save one cheap hop.
    fn next_hop(&self, dst_path: &[Hop]) -> Option<PublicKey> {
        let here = distance(self.announcement.path(), dst_path);
        let mut best: Option<(u64, PublicKey)> = None;
        for (&peer, state) in &self.peers {
            let Some(info) = self.info(&peer) else {
                continue;
            };
            let remaining = distance(info.path(), dst_path);
            if remaining >= here {
                continue;
            }
            let total = state.cost.get().saturating_add(remaining);
            if best.is_none_or(|(cheapest, _)| total < cheapest) {
                best = Some((total, peer));
            }
        }
        best.map(|(_, peer)| peer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::KEY_LEN;
    use crate::message::NONCE_LEN;
    use crate::stand_in::StandIn;

    fn key(n: u8) -> PublicKey {
        PublicKey::new([n; KEY_LEN])
    }

    fn signer(n: u8) -> StandIn {
        StandIn::for_key(key(n))
    }

    fn cost(n: u64) -> Cost {
        Cost::new(n).expect("a test cost is never zero")
    }

    /// An announcement for the node at the end of `root` + `steps`, each hop
    /// signed by the node that added it and consented to by the one above.
    fn announcement(root: u8, steps: &[(u8, u64)]) -> Announcement {
        let mut announcement = Announcement::root_of(&signer(root), 0);
        let mut above = root;
        for &(node, price) in steps {
            let consent = Consent::issue(&signer(above), key(node), cost(price));
            announcement = announcement
                .extend(&signer(node), &consent, 0)
                .expect("the test path holds distinct keys");
            above = node;
        }
        announcement
    }

    fn path(root: u8, steps: &[(u8, u64)]) -> Vec<Hop> {
        announcement(root, steps).path().to_vec()
    }

    /// The walk a path describes, with the stamps and signatures set aside.
    fn walk(path: &[Hop]) -> Vec<(PublicKey, u64)> {
        path.iter().map(|hop| (hop.key, hop.cost)).collect()
    }

    /// What the node at the end of `root` + `steps` says about itself.
    fn announce(root: u8, steps: &[(u8, u64)]) -> Message {
        Message::Announce(announcement(root, steps))
    }

    /// `parent` agreeing to carry `child` over a link it prices at `price`.
    fn consent_from(parent: u8, child: u8, price: u64) -> Message {
        Message::Consent(Consent::issue(&signer(parent), key(child), cost(price)))
    }

    fn nonce(n: u8) -> Nonce {
        Nonce::new([n; NONCE_LEN])
    }

    /// An answer to a search, signed over `nonce` by the node it describes,
    /// with `trail` as what is left of its way home.
    fn answer(seed: u8, trail: &[u8], root: u8, steps: &[(u8, u64)]) -> Message {
        let announcement = announcement(root, steps);
        Message::Found(Found::answer(
            &StandIn::for_key(announcement.author()),
            announcement,
            nonce(seed),
            trail.iter().map(|&n| key(n)).collect(),
        ))
    }

    /// The answer to a search `node` really made, arriving back home.
    ///
    /// It asks first, because an answer to a question nobody put is not one.
    fn found(node: &mut Node<StandIn>, root: u8, steps: &[(u8, u64)]) -> Message {
        let target = announcement(root, steps).author();
        node.lookup(0, target, nonce(0));
        answer(0, &[node.key().as_bytes()[0]], root, steps)
    }

    fn summary_of(keys: &[u8]) -> Summary {
        let mut summary = Summary::new();
        for &n in keys {
            summary.insert(key(n));
        }
        summary
    }

    /// A node linked to a peer holding a smaller key, having just heard where
    /// that peer sits, so it has taken up a position below it.
    fn node_below_a_peer(now: u64) -> Node<StandIn> {
        let mut node = Node::new(0, signer(2), Timing::MILLISECONDS);
        node.add_peer(0, key(1), Cost::UNIT);
        node.handle(now, key(1), consent_from(1, 2, 1));
        node.handle(now, key(1), announce(1, &[]));
        node
    }

    /// The middle of the line `1 - 2 - 3`: the root above, one child below,
    /// and the child claiming that 3 and 7 lie beyond it.
    fn middle_of_a_line() -> Node<StandIn> {
        let mut node = Node::new(0, signer(2), Timing::MILLISECONDS);
        node.add_peer(0, key(1), Cost::UNIT);
        node.add_peer(0, key(3), Cost::UNIT);
        node.handle(0, key(1), consent_from(1, 2, 1));
        node.handle(0, key(3), consent_from(3, 2, 1));
        node.handle(0, key(1), announce(1, &[]));
        node.handle(0, key(3), announce(1, &[(2, 1), (3, 1)]));
        node.handle(0, key(3), Message::Summary(summary_of(&[3, 7])));
        node
    }

    fn announces(out: &[Envelope]) -> Vec<PublicKey> {
        out.iter()
            .filter(|envelope| matches!(envelope.message, Message::Announce(_)))
            .map(|envelope| envelope.to)
            .collect()
    }

    #[test]
    fn a_new_node_is_its_own_root() {
        let node = Node::new(0, signer(7), Timing::MILLISECONDS);
        assert_eq!(node.key(), key(7), "its address is what it signs as");
        assert_eq!(node.root(), key(7));
        assert_eq!(node.parent(), None);
        assert_eq!(node.path(), path(7, &[]));
    }

    #[test]
    fn a_node_signs_where_it_says_it_sits() {
        let node = node_below_a_peer(0);
        let announcement = Announcement::new::<StandIn>(node.path().to_vec());
        assert!(
            announcement.is_ok(),
            "a node's own announcement must check out: {announcement:?}"
        );
    }

    #[test]
    fn adding_a_peer_tells_it_where_this_node_sits() {
        let mut node = Node::new(0, signer(2), Timing::MILLISECONDS);
        let out = node.add_peer(0, key(1), Cost::UNIT);
        assert_eq!(out.len(), 2, "where it sits, and leave to sit below it");
        assert!(out.iter().all(|envelope| envelope.to == key(1)));
        assert_eq!(
            out[0].message,
            Message::Announce(Announcement::root_of(&signer(2), 0))
        );
        assert_eq!(
            out[1].message,
            Message::Consent(Consent::issue(&signer(2), key(1), Cost::UNIT)),
            "priced at what this node measured, since it is the one carrying"
        );
    }

    #[test]
    fn a_node_will_not_sit_below_a_peer_that_has_not_agreed() {
        let mut node = Node::new(0, signer(2), Timing::MILLISECONDS);
        node.add_peer(0, key(1), Cost::UNIT);
        node.handle(0, key(1), announce(1, &[]));

        assert_eq!(node.parent(), None, "a better position, and not on offer");
        assert_eq!(node.root(), key(2), "so it is still its own root");
        assert_eq!(node.consent_from(key(1)), None);

        node.handle(0, key(1), consent_from(1, 2, 1));
        assert_eq!(node.parent(), Some(key(1)), "now it is");
    }

    #[test]
    fn a_node_announces_the_price_its_parent_named() {
        // Both ends measured the link and disagreed about it. What the child
        // announces is the parent's number, because the parent is the one
        // that has to carry the traffic — a child free to pick would pick
        // nothing, and advertise the cheapest walk in the neighbourhood.
        let mut node = Node::new(0, signer(2), Timing::MILLISECONDS);
        node.add_peer(0, key(1), cost(1));
        node.handle(0, key(1), consent_from(1, 2, 9));
        node.handle(0, key(1), announce(1, &[]));

        assert_eq!(node.cost_to_root(), 9, "the parent's price, not its own");
        assert_eq!(walk(node.path()), [(key(1), 0), (key(2), 9)]);
    }

    #[test]
    fn re_pricing_a_link_offers_the_peer_a_new_bargain() {
        let mut node = Node::new(0, signer(2), Timing::MILLISECONDS);
        node.add_peer(0, key(1), Cost::UNIT);

        let out = node.add_peer(1, key(1), cost(10));

        assert_eq!(
            out,
            vec![Envelope {
                to: key(1),
                message: Message::Consent(Consent::issue(&signer(2), key(1), cost(10))),
            }],
            "the price is part of what was agreed, so it is agreed again"
        );
    }

    #[test]
    fn a_node_will_not_peer_with_itself() {
        let mut node = Node::new(0, signer(1), Timing::MILLISECONDS);
        assert!(node.add_peer(0, key(1), Cost::UNIT).is_empty());
        assert_eq!(node.peers().count(), 0);
    }

    #[test]
    fn messages_from_strangers_are_ignored() {
        let mut node = Node::new(0, signer(2), Timing::MILLISECONDS);
        assert!(node.handle(0, key(1), announce(1, &[])).is_empty());
        assert_eq!(node.root(), key(2), "the tree did not move");
        assert_eq!(
            node.known().count(),
            0,
            "nor was a position filed away for somebody there is no link to"
        );
    }

    #[test]
    fn a_node_adopts_a_peer_holding_a_smaller_key_as_its_root() {
        let node = node_below_a_peer(0);
        assert_eq!(node.root(), key(1));
        assert_eq!(node.parent(), Some(key(1)));
        assert_eq!(walk(node.path()), [(key(1), 0), (key(2), 1)]);
    }

    #[test]
    fn a_node_keeps_a_smaller_key_than_its_peer() {
        let mut node = Node::new(0, signer(1), Timing::MILLISECONDS);
        node.add_peer(0, key(2), Cost::UNIT);
        node.handle(0, key(2), announce(2, &[]));

        assert_eq!(node.root(), key(1), "the smaller key stays the root");
        assert_eq!(node.parent(), None);
    }

    #[test]
    fn a_node_refuses_to_sit_below_a_walk_that_runs_through_it() {
        // 3 still believes it sits below this node, and by way of a root this
        // node would much rather answer to than itself. Taking the offer would
        // make the two of them each other's parent, and the cycle would stand
        // until something outside it happened to break. Because an
        // announcement carries the whole walk, the question is settled here
        // and now, out of what this node can see on its own.
        let mut node = Node::new(0, signer(2), Timing::MILLISECONDS);
        node.add_peer(0, key(3), Cost::UNIT);
        node.handle(0, key(3), announce(1, &[(2, 1), (3, 1)]));

        assert_eq!(node.root(), key(2), "a tree of one beats a cycle of two");
        assert_eq!(node.parent(), None);
        assert!(
            node.known().any(|known| known == key(3)),
            "the offer was refused, not the node that made it"
        );
    }

    #[test]
    fn a_node_will_not_be_told_where_it_sits() {
        // A search answered with this node's own position, arriving back at
        // it: an echo of something it said, or somebody else's idea of where
        // it belongs. A node is the only authority on that, so either way
        // there is nothing here to learn — and it never asked, which stops it
        // one step earlier still.
        let mut node = node_below_a_peer(0);
        let before = node.path().to_vec();

        node.handle(1, key(1), answer(0, &[2], 1, &[(9, 1), (2, 1)]));

        assert_eq!(node.path(), before, "still where it put itself");
        assert!(!node.known().any(|known| known == key(2)));
        assert!(node.take_evicted().is_empty(), "and nobody is at fault");
    }

    #[test]
    fn an_answer_to_a_question_nobody_asked_is_refused() {
        // Perfectly signed, and about a node this one would be glad to know
        // where to find. But nothing here asked, so this is a peer pushing a
        // position rather than answering for one — and what it is pushing
        // into is the only thing a node holds that grows with use.
        let mut node = middle_of_a_line();

        let out = node.handle(0, key(3), answer(0, &[2], 1, &[(2, 1), (3, 1), (7, 1)]));

        assert!(out.is_empty());
        assert!(!node.known().any(|known| known == key(7)));
        assert_eq!(node.send(key(7), b"hi".to_vec()), Err(SendError::Unknown));
    }

    #[test]
    fn an_answer_to_a_different_question_is_refused() {
        // The nonce is one this node really is waiting on, and the answer
        // really is signed. It is just not an answer to what was asked, which
        // is how a stale position for somebody else would arrive if the nonce
        // did not tie a question to its answer.
        let mut node = middle_of_a_line();
        node.lookup(0, key(7), nonce(0));

        node.handle(0, key(3), answer(0, &[2], 1, &[(2, 1), (3, 1), (9, 1)]));

        assert!(!node.known().any(|known| known == key(9)));
    }

    #[test]
    fn an_answer_signed_for_another_search_is_refused() {
        // The recording of an older answer, replayed at a node that is
        // waiting on this target. Everything in it checks out except the one
        // thing that cannot be recorded in advance.
        let mut node = middle_of_a_line();
        node.lookup(0, key(7), nonce(1));

        let out = node.handle(0, key(3), answer(0, &[2], 1, &[(2, 1), (3, 1), (7, 1)]));

        assert!(out.is_empty(), "no nonce of this node's matches it");
        assert!(!node.known().any(|known| known == key(7)));
    }

    #[test]
    fn an_answer_serves_the_one_search_that_asked_for_it() {
        let mut node = middle_of_a_line();
        node.lookup(0, key(7), nonce(0));
        node.handle(0, key(3), answer(0, &[2], 1, &[(2, 1), (3, 1), (7, 1)]));
        assert!(node.known().any(|known| known == key(7)));

        node.tick(Timing::MILLISECONDS.expiry);
        assert!(!node.known().any(|known| known == key(7)), "it expired");

        // The same answer over again. The question it belonged to is closed,
        // so replaying it is not a way to keep a position alive.
        node.handle(
            Timing::MILLISECONDS.expiry,
            key(3),
            answer(0, &[2], 1, &[(2, 1), (3, 1), (7, 1)]),
        );
        assert!(!node.known().any(|known| known == key(7)));
    }

    #[test]
    fn a_search_nobody_answered_is_forgotten() {
        let mut node = middle_of_a_line();
        node.lookup(0, key(7), nonce(0));
        node.tick(Timing::MILLISECONDS.expiry);

        node.handle(
            Timing::MILLISECONDS.expiry,
            key(3),
            answer(0, &[2], 1, &[(2, 1), (3, 1), (7, 1)]),
        );

        assert!(
            !node.known().any(|known| known == key(7)),
            "an answer this late is to a question no longer being asked"
        );
    }

    #[test]
    fn an_announcement_about_anyone_but_its_sender_is_refused() {
        let mut node = node_below_a_peer(0);
        // The peer describing some third node. Nothing relays announcements,
        // so this could only be a mistake or a lie.
        assert!(node.handle(0, key(1), announce(1, &[(9, 1)])).is_empty());
        assert_eq!(
            node.known().collect::<Vec<_>>(),
            vec![key(1)],
            "a node hears about its peers and nobody else"
        );
        assert_eq!(
            node.take_evicted(),
            vec![Eviction {
                peer: key(1),
                fault: Fault::AnnouncementAboutAnother,
            }],
            "and a peer that relays one is not running this protocol"
        );
        assert_eq!(node.peers().count(), 0, "so it is not a peer any more");
        assert_eq!(node.parent(), None, "and nothing sits below it");
    }

    #[test]
    fn a_position_that_does_not_check_out_is_not_believed() {
        let mut node = Node::new(0, signer(3), Timing::MILLISECONDS);
        node.add_peer(0, key(2), Cost::UNIT);

        // 2's genuine announcement, with the price of its link to the root
        // rubbed out and a cheaper one written in. That would make 2 a better
        // parent than it has earned, and cost every packet routed through it.
        let mut tampered = path(1, &[(2, 5)]);
        tampered[1].cost = 1;

        let out = node.handle(
            0,
            key(2),
            Message::Announce(Announcement::unchecked(tampered)),
        );

        assert!(out.is_empty());
        assert_eq!(node.known().count(), 0, "nothing was taken on trust");
        assert_eq!(node.parent(), None, "and nothing was sat below");
        assert_eq!(
            node.take_evicted(),
            vec![Eviction {
                peer: key(2),
                fault: Fault::ForgedAnnouncement,
            }],
            "no honest node produces a walk that does not check out"
        );
        assert_eq!(node.peers().count(), 0);
    }

    #[test]
    fn a_consent_meant_for_somebody_else_costs_the_peer_its_link() {
        let mut node = node_below_a_peer(0);
        node.add_peer(0, key(3), Cost::UNIT);

        // 3 hands over the agreement 1 gave to this node. It checks out
        // perfectly — it just is not 3 agreeing to carry anybody.
        node.handle(0, key(3), consent_from(1, 2, 1));

        assert_eq!(
            node.take_evicted(),
            vec![Eviction {
                peer: key(3),
                fault: Fault::MisdirectedConsent,
            }]
        );
        assert_eq!(node.consent_from(key(3)), None);
    }

    #[test]
    fn a_consent_for_another_node_costs_the_peer_its_link() {
        let mut node = node_below_a_peer(0);
        node.add_peer(0, key(3), Cost::UNIT);

        // 3 really did sign this, and it really is 3's to give — to 9.
        node.handle(0, key(3), consent_from(3, 9, 1));

        assert_eq!(
            node.take_evicted(),
            vec![Eviction {
                peer: key(3),
                fault: Fault::MisdirectedConsent,
            }]
        );
    }

    #[test]
    fn evicting_a_peer_says_so_to_the_rest() {
        // The evicted peer was this node's parent, so losing it moves the
        // node — and every other peer has to hear where it moved to. An
        // eviction is a link going down, and behaves like one.
        let mut node = middle_of_a_line();
        assert_eq!(node.parent(), Some(key(1)));

        let out = node.handle(0, key(1), announce(1, &[(9, 1)]));

        assert_eq!(node.parent(), None, "its parent is gone");
        assert_eq!(node.root(), key(2));
        assert_eq!(announces(&out), vec![key(3)], "and 3 is told");
        assert_eq!(node.take_evicted().len(), 1);
    }

    #[test]
    fn a_peer_that_is_merely_out_of_date_is_left_alone() {
        // The rule has to be one no honest peer can trip. Stale positions,
        // repeats, announcements that arrive out of order and answers to
        // questions this node has forgotten are all ordinary, and none of
        // them is anybody's fault.
        let mut node = middle_of_a_line();

        node.handle(0, key(1), announce(1, &[]));
        node.handle(0, key(3), announce(1, &[(2, 1), (3, 1)]));
        node.handle(0, key(3), Message::Summary(summary_of(&[3, 7])));
        node.handle(0, key(1), consent_from(1, 2, 1));
        node.handle(0, key(3), answer(9, &[2], 1, &[(2, 1), (3, 1), (7, 1)]));
        node.tick(Timing::MILLISECONDS.expiry);

        assert!(
            node.take_evicted().is_empty(),
            "nothing here is a fault, however wrong or late it is"
        );
    }

    #[test]
    fn an_answer_carrying_a_position_that_does_not_check_out_is_not_believed() {
        let mut node = middle_of_a_line();

        // A search for 7 comes back with 7 placed somewhere it never signed
        // for — the cheapest lie a node relaying an answer could tell.
        let mut tampered = path(1, &[(2, 1), (3, 1), (7, 1)]);
        tampered[3].cost = 9;

        let forged = Announcement::unchecked(tampered);
        let bad = Found::answer(
            &StandIn::for_key(key(7)),
            forged,
            nonce(0),
            vec![key(2)],
        );
        node.lookup(0, key(7), nonce(0));

        node.handle(0, key(3), Message::Found(bad));

        assert!(
            !node.known().any(|known| known == key(7)),
            "an answer is checked exactly as an announcement is"
        );
        assert_eq!(node.send(key(7), b"hi".to_vec()), Err(SendError::Unknown));
        assert_eq!(
            node.take_evicted(),
            vec![Eviction {
                peer: key(3),
                fault: Fault::ForgedAnswer,
            }],
            "and whoever handed it over made it up"
        );
    }

    #[test]
    fn a_stale_announcement_changes_nothing() {
        let mut node = Node::new(0, signer(2), Timing::MILLISECONDS);
        node.add_peer(0, key(1), Cost::UNIT);
        node.handle(0, key(1), consent_from(1, 2, 1));

        let fresh = Announcement::root_of(&signer(1), 5);
        assert!(!node.handle(0, key(1), Message::Announce(fresh)).is_empty());

        let stale = Announcement::root_of(&signer(1), 4);
        assert!(node.handle(0, key(1), Message::Announce(stale)).is_empty());
    }

    #[test]
    fn sending_to_a_node_that_has_not_been_looked_up_fails() {
        let mut node = Node::new(0, signer(1), Timing::MILLISECONDS);
        assert_eq!(node.send(key(9), b"hi".to_vec()), Err(SendError::Unknown));
    }

    #[test]
    fn sending_to_oneself_delivers_locally() {
        let mut node = Node::new(0, signer(1), Timing::MILLISECONDS);
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
    fn a_packet_carries_the_position_it_is_forwarded_by() {
        let mut node = node_below_a_peer(0);
        let out = node
            .send(key(1), b"up".to_vec())
            .expect("a peer's position is always known");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].to, key(1));
        assert_eq!(
            out[0].message,
            Message::Traffic(Traffic {
                dst_path: path(1, &[]),
                packet: Packet {
                    src: key(2),
                    dst: key(1),
                    payload: b"up".to_vec(),
                },
            })
        );
    }

    #[test]
    fn a_packet_passing_through_is_handed_on_exactly_as_it_arrived() {
        // The coordinates it is travelling by are the sender's and stay the
        // sender's. A node in the middle re-addresses nothing: it picks the
        // next hop and passes the packet along untouched, which is what has
        // every node on the route measuring against the same target.
        let mut node = middle_of_a_line();
        let traffic = Traffic {
            dst_path: path(1, &[(2, 1), (3, 1)]),
            packet: Packet {
                src: key(1),
                dst: key(3),
                payload: b"onwards".to_vec(),
            },
        };

        let out = node.handle(0, key(1), Message::Traffic(traffic.clone()));

        assert_eq!(out.len(), 1);
        assert_eq!(out[0].to, key(3));
        assert_eq!(out[0].message, Message::Traffic(traffic));
        assert!(
            node.take_delivered().is_empty(),
            "carrying a packet is not being addressed by it"
        );
    }

    #[test]
    fn a_packet_that_has_arrived_is_delivered_rather_than_forwarded() {
        let mut node = middle_of_a_line();
        let packet = Packet {
            src: key(1),
            dst: key(2),
            payload: b"for you".to_vec(),
        };

        let out = node.handle(
            0,
            key(1),
            Message::Traffic(Traffic {
                dst_path: path(1, &[(2, 1)]),
                packet: packet.clone(),
            }),
        );

        assert!(out.is_empty(), "it goes no further");
        assert_eq!(node.take_delivered(), vec![packet]);
    }

    #[test]
    fn a_packet_at_a_dead_end_is_dropped() {
        // 3 has gone and nothing has expired yet, so a packet for it still
        // arrives here addressed to a position nothing leads to any more. No
        // peer stands closer than this node does. Ironwood would report the
        // broken path back through the tree; this core does the same minus
        // the recovery, which is to stop.
        let mut node = middle_of_a_line();
        node.remove_peer(0, key(3));

        let out = node.handle(
            0,
            key(1),
            Message::Traffic(Traffic {
                dst_path: path(1, &[(2, 1), (3, 1)]),
                packet: Packet {
                    src: key(1),
                    dst: key(3),
                    payload: b"nobody home".to_vec(),
                },
            }),
        );

        assert!(out.is_empty(), "dropped, rather than handed backwards");
        assert!(
            node.take_delivered().is_empty(),
            "and not delivered to the wrong node either"
        );
    }

    #[test]
    fn a_peer_exactly_as_far_away_is_not_progress() {
        // 3 has not caught up: it still announces itself below this node,
        // which has since gone off on its own. Measured against 4's
        // coordinates, the two of them are the same distance away — and being
        // no worse is not the test. Handing the packet over on equal terms is
        // how it comes straight back, and it is only strictness that keeps
        // the distance falling at every hop.
        let mut node = Node::new(0, signer(2), Timing::MILLISECONDS);
        node.add_peer(0, key(3), Cost::UNIT);
        node.handle(0, key(3), announce(1, &[(2, 1), (3, 1)]));
        let answer = found(&mut node, 1, &[(2, 1), (4, 1)]);
        node.handle(0, key(3), answer);

        assert_eq!(node.root(), key(2), "this node sits outside that walk now");
        assert_eq!(
            distance(node.path(), &path(1, &[(2, 1), (4, 1)])),
            distance(&path(1, &[(2, 1), (3, 1)]), &path(1, &[(2, 1), (4, 1)])),
            "a dead heat, which is the case the rule is strict about"
        );
        assert_eq!(node.send(key(4), b"hi".to_vec()), Err(SendError::NoRoute));
    }

    #[test]
    fn a_packet_with_nowhere_closer_to_go_is_refused_at_the_source() {
        // 4 sat below this node until its link went down, and its position is
        // still held. Every peer this node has is further from 4 than it is
        // itself, so there is no hop that makes progress. Saying so beats
        // posting the packet to a peer that would only drop it.
        let mut node = node_below_a_peer(0);
        let answer = found(&mut node, 1, &[(2, 1), (4, 1)]);
        node.handle(0, key(1), answer);
        assert!(node.known().any(|known| known == key(4)));

        assert_eq!(
            node.send(key(4), b"hi".to_vec()),
            Err(SendError::NoRoute),
            "the position is known and unreachable, which is not the same as unknown"
        );
    }

    #[test]
    fn an_announcement_that_is_never_reissued_expires() {
        let mut node = node_below_a_peer(0);
        assert_eq!(node.known().count(), 1);

        let out = node.tick(Timing::MILLISECONDS.expiry);

        assert_eq!(node.known().count(), 0, "the announcement was forgotten");
        assert_eq!(node.root(), key(2), "and with it, the route to the root");
        assert_eq!(node.parent(), None);
        assert_eq!(announces(&out), vec![key(1)], "the peer is told it moved");
    }

    #[test]
    fn a_reissued_announcement_survives() {
        let expiry = Timing::MILLISECONDS.expiry;
        let mut node = node_below_a_peer(0);

        // The author reissues just before the deadline, one sequence number on.
        node.handle(
            expiry - 1,
            key(1),
            Message::Announce(Announcement::root_of(&signer(1), 1)),
        );
        node.tick(expiry);

        assert_eq!(node.root(), key(1), "the reissue kept it alive");
        assert_eq!(node.known().count(), 1);
    }

    #[test]
    fn a_repeat_does_not_restart_the_expiry_clock() {
        let expiry = Timing::MILLISECONDS.expiry;
        let mut node = node_below_a_peer(0);

        // The same announcement over again, rather than a newer one.
        node.handle(
            expiry - 1,
            key(1),
            Message::Announce(Announcement::root_of(&signer(1), 0)),
        );
        node.tick(expiry);

        assert_eq!(
            node.root(),
            key(2),
            "an echo is not evidence its author is still there"
        );
    }

    #[test]
    fn a_looked_up_position_is_forgotten_like_any_other() {
        let mut node = Node::new(0, signer(5), Timing::MILLISECONDS);
        node.add_peer(0, key(2), Cost::UNIT);
        node.handle(0, key(2), consent_from(2, 5, 1));
        node.handle(0, key(2), announce(1, &[(2, 1)]));
        let answer = found(&mut node, 1, &[(2, 1), (4, 1)]);
        node.handle(0, key(2), answer);
        assert!(node.known().any(|known| known == key(4)));

        node.tick(Timing::MILLISECONDS.expiry);

        assert!(
            !node.known().any(|known| known == key(4)),
            "nothing reissues an answer, so it goes when its time is up"
        );
        assert_eq!(
            node.send(key(4), b"hi".to_vec()),
            Err(SendError::Unknown),
            "and the next packet has to ask again"
        );
    }

    #[test]
    fn a_node_reissues_its_own_announcement_on_schedule() {
        let refresh = Timing::MILLISECONDS.refresh;
        let mut node = Node::new(0, signer(1), Timing::MILLISECONDS);
        node.add_peer(0, key(2), Cost::UNIT);

        assert!(node.tick(refresh - 1).is_empty(), "not due yet");

        let out = node.tick(refresh);
        assert_eq!(out.len(), 1, "one peer, one reissue");
        assert_eq!(out[0].to, key(2));
        assert_eq!(
            out[0].message,
            Message::Announce(Announcement::root_of(&signer(1), 1)),
            "the same walk, signed afresh for a new sequence number"
        );
        assert_eq!(walk(node.path()), [(key(1), 0)], "the tree did not move");
    }

    #[test]
    fn a_node_that_starts_over_is_believed_once_the_old_one_has_expired() {
        let expiry = Timing::MILLISECONDS.expiry;
        let mut node = node_below_a_peer(0);

        // The peer had climbed to a high sequence number before it went quiet.
        node.handle(
            1,
            key(1),
            Message::Announce(Announcement::root_of(&signer(1), 500)),
        );
        node.tick(expiry + 1);
        assert_eq!(node.known().count(), 0);

        // It comes back having started over at zero. Without expiry that would
        // have looked like ancient news and been thrown away.
        node.handle(
            expiry + 1,
            key(1),
            Message::Announce(Announcement::root_of(&signer(1), 0)),
        );
        assert_eq!(node.root(), key(1), "the returning node is believed");
        assert_eq!(node.parent(), Some(key(1)));
    }

    #[test]
    fn a_node_keeps_to_the_schedule_it_was_given() {
        let timing = Timing {
            refresh: 10,
            expiry: 40,
        };
        let mut node = Node::new(0, signer(2), timing);
        node.add_peer(0, key(1), Cost::UNIT);
        node.handle(0, key(1), consent_from(1, 2, 1));
        node.handle(0, key(1), announce(1, &[]));

        node.tick(39);
        assert_eq!(node.root(), key(1), "not yet due to expire");
        node.tick(40);
        assert_eq!(node.root(), key(2), "expired on the caller's own scale");
    }

    #[test]
    fn a_node_sits_below_whichever_peer_offers_the_cheapest_walk_to_the_root() {
        let mut node = Node::new(0, signer(4), Timing::MILLISECONDS);
        node.add_peer(0, key(1), cost(10));
        node.add_peer(0, key(2), cost(1));
        node.handle(0, key(1), consent_from(1, 4, 10));
        node.handle(0, key(2), consent_from(2, 4, 1));
        node.handle(0, key(1), announce(1, &[]));
        node.handle(0, key(2), announce(1, &[(2, 1)]));

        assert_eq!(node.root(), key(1));
        assert_eq!(
            node.parent(),
            Some(key(2)),
            "two cheap links beat one expensive one, though the root is a peer"
        );
        assert_eq!(walk(node.path()), [(key(1), 0), (key(2), 1), (key(4), 1)]);
        assert_eq!(node.cost_to_root(), 2);
    }

    #[test]
    fn a_peer_re_pricing_its_side_moves_a_node() {
        let mut node = Node::new(0, signer(4), Timing::MILLISECONDS);
        node.add_peer(0, key(1), Cost::UNIT);
        node.add_peer(0, key(2), Cost::UNIT);
        node.handle(0, key(1), consent_from(1, 4, 1));
        node.handle(0, key(2), consent_from(2, 4, 1));
        node.handle(0, key(1), announce(1, &[]));
        node.handle(0, key(2), announce(1, &[(2, 1)]));
        assert_eq!(node.parent(), Some(key(1)), "one hop to the root");

        // The root measures that link again and finds it much worse, so the
        // bargain it is offering changes. The price is the parent's to set,
        // and a node cannot go on announcing one it is no longer being
        // offered, because the price is part of what was signed.
        let out = node.handle(1, key(1), consent_from(1, 4, 10));

        assert_eq!(node.parent(), Some(key(2)), "the long way round is cheaper");
        assert_eq!(node.cost_to_root(), 2);
        assert_eq!(
            announces(&out),
            vec![key(1), key(2)],
            "both peers are told where this node moved to"
        );
    }

    #[test]
    fn re_pricing_a_link_to_what_it_already_cost_changes_nothing() {
        let mut node = node_below_a_peer(0);
        let before = node.path().to_vec();

        assert!(
            node.add_peer(1, key(1), Cost::UNIT).is_empty(),
            "nothing changed, so there is nothing to say"
        );
        assert_eq!(node.path(), before);
    }

    #[test]
    fn losing_a_parent_re_roots_a_node_and_tells_the_peers_it_has_left() {
        let mut node = middle_of_a_line();
        assert_eq!(node.parent(), Some(key(1)));

        let out = node.remove_peer(0, key(1));

        assert_eq!(
            node.root(),
            key(2),
            "with the link went the way to the root"
        );
        assert_eq!(node.parent(), None);
        assert_eq!(
            announces(&out),
            vec![key(3)],
            "the peer still there is told at once, rather than waiting to notice"
        );
        assert!(
            node.known().any(|known| known == key(1)),
            "nothing is withdrawn here, since a node cannot tell what was only reachable that way"
        );
    }

    #[test]
    fn removing_a_link_that_was_never_up_changes_nothing() {
        let mut node = node_below_a_peer(0);
        let before = node.path().to_vec();

        assert!(node.remove_peer(1, key(8)).is_empty());
        assert_eq!(node.path(), before);
        assert_eq!(node.peers().count(), 1);
    }

    #[test]
    fn a_node_stays_put_when_the_walk_above_it_is_merely_restamped() {
        let mut node = node_below_a_peer(0);
        let before = node.path().to_vec();

        // The parent reissues from the same place. Its announcement is a new
        // value, but the walk it describes is the one this node already sits
        // on, and saying so again would only make work for everybody below.
        let out = node.handle(
            1,
            key(1),
            Message::Announce(
                announcement(1, &[])
                    .with_seq(&signer(1), 9)
                    .expect("author"),
            ),
        );

        assert!(
            announces(&out).is_empty(),
            "nothing moved, so nothing was said"
        );
        assert_eq!(node.path(), before);
    }

    /// A node holding key 5, linked to both 2 and 3 — each of them a child of
    /// the root — and told that 4 sits below 2, away from 3.
    fn node_choosing_between_two_peers(to_two: u64, to_three: u64) -> Node<StandIn> {
        let mut node = Node::new(0, signer(5), Timing::MILLISECONDS);
        node.add_peer(0, key(2), cost(to_two));
        node.add_peer(0, key(3), cost(to_three));
        node.handle(0, key(2), consent_from(2, 5, to_two));
        node.handle(0, key(3), consent_from(3, 5, to_three));
        node.handle(0, key(2), announce(1, &[(2, 1)]));
        node.handle(0, key(3), announce(1, &[(3, 1)]));
        let answer = found(&mut node, 1, &[(2, 1), (4, 1)]);
        node.handle(0, key(2), answer);
        node
    }

    fn first_hop(out: &[Envelope]) -> PublicKey {
        out.first().expect("the packet went somewhere").to
    }

    #[test]
    fn a_packet_crosses_a_shortcut_only_while_it_is_worth_crossing() {
        let mut cheap = node_choosing_between_two_peers(1, 2);
        assert_eq!(cheap.parent(), Some(key(2)));
        let out = cheap
            .send(key(4), b"hi".to_vec())
            .expect("a route is known");
        assert_eq!(
            first_hop(&out),
            key(2),
            "2 is one cheap hop from the destination"
        );

        // The same network with that one link made expensive. 2 is still the
        // peer nearest the destination, but reaching it now costs more than
        // walking the tree the long way round.
        let mut dear = node_choosing_between_two_peers(10, 1);
        assert_eq!(dear.parent(), Some(key(3)));
        let out = dear.send(key(4), b"hi".to_vec()).expect("a route is known");
        assert_eq!(
            first_hop(&out),
            key(3),
            "three cheap hops beat one costing ten"
        );
    }

    #[test]
    fn a_node_summarises_its_own_side_of_each_tree_link() {
        let node = middle_of_a_line();

        let upwards = node.summary_for(key(1)).expect("the parent is a tree link");
        assert!(upwards.contains(key(2)), "itself");
        assert!(upwards.contains(key(3)), "and what its child claimed");
        assert!(upwards.contains(key(7)), "however far beyond the child");
    }

    #[test]
    fn a_summary_leaves_out_what_the_peer_it_goes_to_said() {
        let node = middle_of_a_line();

        let downwards = node.summary_for(key(3)).expect("the child is a tree link");
        assert!(downwards.contains(key(2)), "itself");
        assert!(
            !downwards.contains(key(3)) && !downwards.contains(key(7)),
            "handing 3 back its own subtree would put everything on both sides"
        );
    }

    #[test]
    fn a_link_outside_the_tree_carries_no_summary() {
        let mut node = middle_of_a_line();
        // A fourth node, linked but sitting elsewhere in the tree: neither this
        // node's parent nor one of its children.
        node.add_peer(0, key(8), Cost::UNIT);
        node.handle(0, key(8), announce(1, &[(6, 1), (8, 1)]));

        assert_eq!(node.summary_for(key(8)), None);
        assert!(node.summary_for(key(1)).is_some());
    }

    #[test]
    fn a_summary_that_says_nothing_new_ends_where_it_arrives() {
        // This is what brings the exchange to rest. Every summary that lands
        // has a node working out afresh what to tell everybody else, so one
        // that repeats what its link already said has to stop here — and one
        // that does carry news has to travel, or the far side of the tree
        // never hears of the key that turned up.
        let mut node = middle_of_a_line();

        assert!(
            node.handle(0, key(3), Message::Summary(summary_of(&[3, 7])))
                .is_empty(),
            "3 has said this once already"
        );

        let out = node.handle(0, key(3), Message::Summary(summary_of(&[3, 7, 9])));

        assert_eq!(
            out.len(),
            1,
            "upwards, and not back to the peer it came from"
        );
        assert_eq!(out[0].to, key(1));
        assert!(
            node.summary_for(key(1))
                .expect("the parent is a tree link")
                .contains(key(9))
        );
    }

    #[test]
    fn a_search_goes_only_where_a_summary_admits_it_might_be() {
        let mut node = middle_of_a_line();

        let out = node.lookup(0, key(7), nonce(0));
        assert_eq!(out.len(), 1, "one branch could hold it");
        assert_eq!(out[0].to, key(3));
        assert_eq!(
            out[0].message,
            Message::Lookup(Lookup {
                target: key(7),
                nonce: nonce(0),
                trail: vec![key(2)],
            })
        );

        assert!(
            node.lookup(0, key(9), nonce(1)).is_empty(),
            "no summary admits 9, so nothing is asked"
        );
        assert!(
            node.lookup(0, key(2), nonce(2)).is_empty(),
            "and nobody looks for itself"
        );
    }

    #[test]
    fn a_search_is_passed_on_with_this_node_added_to_its_trail() {
        let mut node = middle_of_a_line();
        let out = node.handle(
            0,
            key(1),
            Message::Lookup(Lookup {
                target: key(7),
                nonce: nonce(0),
                trail: vec![key(1)],
            }),
        );

        assert_eq!(out.len(), 1);
        assert_eq!(out[0].to, key(3));
        assert_eq!(
            out[0].message,
            Message::Lookup(Lookup {
                target: key(7),
                nonce: nonce(0),
                trail: vec![key(1), key(2)],
            })
        );
    }

    #[test]
    fn a_link_that_has_left_the_tree_stops_carrying_searches() {
        // What a peer last claimed lies beyond it stays on file — there is
        // nothing to replace it with until the peer says otherwise. But 3 has
        // moved out from under this node, and a summary is a claim about a
        // tree link and worthless off one: folded around the cycle that link
        // now closes, it would hand every key back to where it came from.
        let mut node = middle_of_a_line();
        assert_eq!(
            node.lookup(0, key(7), nonce(0)).len(),
            1,
            "while 3 was still below"
        );

        node.handle(
            0,
            key(3),
            Message::Announce(
                announcement(1, &[(6, 1), (3, 1)])
                    .with_seq(&signer(3), 1)
                    .expect("the author"),
            ),
        );

        assert_eq!(
            node.summary_for(key(3)),
            None,
            "nothing goes down it either"
        );
        assert!(
            node.lookup(0, key(7), nonce(1)).is_empty(),
            "3 still claims 7, and is no longer anybody this node may ask"
        );
    }

    #[test]
    fn a_search_is_never_handed_back_to_a_node_it_has_already_been_to() {
        // 1's summary admits 7 as readily as 3's does — of course it does,
        // since 7 is not on this node's side of that link either. Handing the
        // search straight back the way it came would still terminate, because
        // 1 would find itself on the trail and refuse it, but the message
        // exists only to be thrown away.
        let mut node = middle_of_a_line();
        node.handle(0, key(1), Message::Summary(summary_of(&[7])));

        let out = node.handle(
            0,
            key(1),
            Message::Lookup(Lookup {
                target: key(7),
                nonce: nonce(0),
                trail: vec![key(1)],
            }),
        );

        assert_eq!(out.len(), 1, "onwards only");
        assert_eq!(out[0].to, key(3));
    }

    #[test]
    fn a_search_that_has_been_here_before_is_refused() {
        let mut node = middle_of_a_line();
        let out = node.handle(
            0,
            key(1),
            Message::Lookup(Lookup {
                target: key(7),
                nonce: nonce(0),
                trail: vec![key(2), key(1)],
            }),
        );
        assert!(out.is_empty(), "a search must not go round in a circle");
    }

    #[test]
    fn the_node_being_looked_for_answers_with_where_it_sits() {
        let mut node = middle_of_a_line();
        let out = node.handle(
            0,
            key(1),
            Message::Lookup(Lookup {
                target: key(2),
                nonce: nonce(3),
                trail: vec![key(1)],
            }),
        );

        assert_eq!(out.len(), 1);
        assert_eq!(out[0].to, key(1), "back the way the search came");
        assert_eq!(
            out[0].message,
            Message::Found(Found::answer(
                &signer(2),
                node.announcement.clone(),
                nonce(3),
                vec![key(1)],
            )),
            "and vouching for the search it is answering"
        );
        let Message::Found(found) = &out[0].message else {
            panic!("an answer");
        };
        assert!(found.verify::<StandIn>());
    }

    #[test]
    fn an_answer_retraces_the_search_and_stops_where_it_started() {
        let mut node = middle_of_a_line();

        // Passing through: the trail still has the asker on it.
        let out = node.handle(0, key(3), answer(0, &[1, 2], 1, &[(2, 1), (3, 1), (7, 1)]));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].to, key(1));
        assert_eq!(
            out[0].message,
            answer(0, &[1], 1, &[(2, 1), (3, 1), (7, 1)])
        );
        assert!(
            !node.known().any(|known| known == key(7)),
            "carrying an answer is not the same as having asked for it"
        );

        // Arriving home: nothing before this node on the trail, and a
        // question of its own that this answers.
        node.lookup(0, key(7), nonce(0));
        let out = node.handle(0, key(3), answer(0, &[2], 1, &[(2, 1), (3, 1), (7, 1)]));
        assert!(out.is_empty(), "the answer goes no further");
        assert!(node.known().any(|known| known == key(7)));
        assert!(node.send(key(7), b"found you".to_vec()).is_ok());
    }

    #[test]
    fn an_answer_that_never_came_through_here_is_dropped() {
        let mut node = middle_of_a_line();
        let out = node.handle(0, key(3), answer(0, &[1, 8], 1, &[(2, 1), (3, 1), (7, 1)]));
        assert!(out.is_empty());
        assert!(!node.known().any(|known| known == key(7)));
    }
}
