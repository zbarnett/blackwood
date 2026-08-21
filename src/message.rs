//! What nodes hand to one another across a link.

use crate::key::PublicKey;
use crate::summary::Summary;
use crate::tree::{Announcement, Hop};

/// A unit of user traffic.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Packet {
    /// The node that originated the packet.
    pub src: PublicKey,
    /// The node it is addressed to.
    pub dst: PublicKey,
    /// The bytes being carried, opaque to routing.
    pub payload: Vec<u8>,
}

/// A packet on its way, with the coordinates it is being forwarded by.
///
/// The destination's path travels with the packet rather than being looked up
/// at each hop, because no node along the way holds it: a node knows where its
/// own peers sit and nothing more. It also makes the loop-freedom argument
/// exact, since every node on the route measures its progress against the same
/// target rather than against its own copy of it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Traffic {
    /// Where the destination sat when the sender last heard.
    pub dst_path: Vec<Hop>,
    /// The packet itself.
    pub packet: Packet,
}

/// A search for a node whose position is not known.
///
/// Tree routing needs the destination's coordinates, and a node holds those
/// only for its peers and for whoever it has already been talking to. This is
/// how it gets the rest: a walk along tree links, steered at every step by
/// what the [`Summary`] on each link claims lies beyond it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Lookup {
    /// The node being looked for.
    pub target: PublicKey,
    /// Every node this has passed through: the one that asked first, and the
    /// one that just sent it last.
    ///
    /// It does two jobs. A node that finds itself already on it refuses to
    /// take the search again, which is what stops one circling while the tree
    /// is unsettled. And it is the way home for the answer.
    pub trail: Vec<PublicKey>,
}

/// The answer to a [`Lookup`], on its way back.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Found {
    /// Where the node that was looked for says it sits.
    pub announcement: Announcement,
    /// What is left of the search's trail. Each node hands the answer to
    /// whoever comes before it and drops itself off the end, so the answer
    /// retraces the search exactly rather than needing a route of its own.
    pub trail: Vec<PublicKey>,
}

/// Anything one node sends to a directly linked peer.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Message {
    /// Where the sender sits in the tree.
    ///
    /// Only ever about the sender, and never passed on: a node needs the
    /// coordinates of its own peers and of nobody else.
    Announce(Announcement),
    /// What the sender says can be reached through it.
    ///
    /// Only ever about the sender's side of this one link, and never passed on
    /// as it stands — a node folds the ones it receives together into the
    /// different summary it sends over each of its own links.
    Summary(Summary),
    /// A search for a node, steered by summaries.
    Lookup(Lookup),
    /// The answer to one, retracing the search's steps.
    Found(Found),
    /// Traffic being forwarded towards its destination.
    Traffic(Traffic),
}

/// A message together with the linked peer it must be handed to.
///
/// Delivering it is the caller's job. Nothing in this crate performs I/O, so a
/// node's entire effect on the world is the envelopes it returns.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Envelope {
    /// The peer that should receive the message.
    pub to: PublicKey,
    /// The message itself.
    pub message: Message,
}
