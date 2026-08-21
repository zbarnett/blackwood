//! What nodes hand to one another across a link.

use crate::key::PublicKey;
use crate::tree::Announcement;

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

/// Anything one node sends to a directly linked peer.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Message {
    /// Gossip: some node's position in the tree.
    Announce(Announcement),
    /// Traffic being forwarded towards its destination.
    Packet(Packet),
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
