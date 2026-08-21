//! A minimal reimplementation of the [ironwood] routing protocol's core.
//!
//! [ironwood]: https://github.com/Arceliar/ironwood
//!
//! Nodes address one another by public key rather than by location, and reach
//! each other over a network where no node is guaranteed a direct link to any
//! other. Routing works by embedding the network in a spanning tree and then
//! greedily forwarding towards the destination in the metric that embedding
//! induces.
//!
//! # How it works
//!
//! The node with the smallest key in a connected component becomes the root.
//! Every node announces the path of keys running from that root down to itself,
//! and gossips the announcements it hears onward to its peers. Announcements
//! are only ever authored by the node they describe, so the set of them is a
//! conflict-free replicated map of key to announcement whose join per author is
//! simply the greater of the two: no coordination, no ordering requirements on
//! the network, and no divergence between nodes.
//!
//! Given two announcements, the distance between their authors is the walk up
//! to their lowest common ancestor and back down. A node forwards a packet to
//! whichever peer stands strictly closer to the destination than it does. Two
//! properties fall out of that rule, both of them local:
//!
//! - **Loop freedom.** Distance strictly decreases at every hop and is bounded
//!   below by zero, so a packet cannot revisit a node.
//! - **Delivery on a settled tree.** A node's tree neighbour towards the
//!   destination is always closer by exactly what the link between them costs,
//!   so a node with a consistent view always has a next hop to offer.
//!
//! Every link costs something to cross — latency, in ironwood's case, and
//! whatever the caller measures here — and both decisions weigh it. A node sits
//! below the peer offering the cheapest walk to the root rather than the
//! shortest one, and among the peers that make strict progress it hands a
//! packet to whichever leaves the least left to pay. A [`Cost`] is never zero,
//! which is what keeps both of the properties above standing; a network whose
//! links all cost [`Cost::UNIT`] measures distance in hops.
//!
//! The tree itself is loop-free for a separate reason: an announcement carries
//! its whole path, and a node refuses to sit below any path that already runs
//! through it. Staleness can cost a node its route, never its acyclicity.
//!
//! Announcements are soft state. A node reissues its own on a schedule and
//! forgets any it has not heard reissued, so a view repairs itself rather than
//! only accumulating: a node that vanishes is eventually forgotten instead of
//! lingering as a route to nowhere, and one that comes back having started its
//! sequence numbers over is not mistaken for a stale copy of itself. This is
//! the only part of the protocol that involves time, and even here the core
//! reads no clock — [`Node::tick`] is handed the current instant by its caller,
//! counted in whatever unit that caller likes.
//!
//! # What this is not
//!
//! Nothing here performs I/O, reads a clock, allocates a thread, or calls into
//! the operating system; the crate has no dependencies beyond `std` and no
//! `unsafe`. A [`Node`] is a state machine whose every effect on the world is
//! the [`Envelope`]s it hands back, and whose every input — a message, a link
//! coming or going, the passage of time — is an argument to one of its methods.
//! That is what makes a network of them deterministically simulatable and what
//! should make the argument above tractable to check in a proof assistant.
//!
//! Two things ironwood does are deliberately left out, each of them a
//! hardening or an optimisation of the model above rather than part of it:
//!
//! - **Cryptography.** Ironwood signs announcements so a node cannot lie about
//!   its parent. Here a key is an opaque identifier and announcements are
//!   trusted, so this core is correct only among honest participants.
//! - **Bloom filters.** Ironwood keeps constant state per peer and finds
//!   unknown destinations by lookup. Here every node learns every announcement,
//!   which is linear in the size of the network but needs no lookup protocol.
//!
//! # Example
//!
//! ```
//! use blackwood::{Cost, Message, Node, PublicKey, Timing};
//!
//! let (a, b) = (PublicKey::new([1; 32]), PublicKey::new([2; 32]));
//! let (mut a_node, mut b_node) = (Node::new(0, a), Node::new(0, b));
//!
//! // Bring up the link, then hand each side what the other offered. Nothing
//! // has been measured about it, so it is priced at a single hop.
//! let to_b = a_node.add_peer(0, b, Cost::UNIT);
//! for envelope in b_node.add_peer(0, a, Cost::UNIT) {
//!     a_node.handle(0, b, envelope.message);
//! }
//! // Hearing from a moves b below it, and saying so is what tells a where b
//! // now sits. Until that reply lands, a still believes b is off on its own.
//! for envelope in to_b {
//!     for reply in b_node.handle(0, a, envelope.message) {
//!         a_node.handle(0, b, reply.message);
//!     }
//! }
//!
//! // The smaller key is the root, and the other sits one link below it.
//! assert_eq!(b_node.root(), a);
//! assert_eq!(b_node.parent(), Some(a));
//! assert_eq!(b_node.cost_to_root(), 1);
//!
//! // A packet crosses the single hop.
//! for envelope in a_node.send(b, b"hello".to_vec()).expect("route is known") {
//!     b_node.handle(0, a, envelope.message);
//! }
//! assert_eq!(b_node.take_delivered()[0].payload, b"hello");
//!
//! // Let time pass with nothing arriving from a, and b forgets where it sat.
//! b_node.tick(Timing::DEFAULT.expiry);
//! assert_eq!(b_node.root(), b);
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod key;
pub mod message;
pub mod node;
pub mod tree;

pub use key::{KEY_LEN, PublicKey};
pub use message::{Envelope, Message, Packet};
pub use node::{Node, SendError, Timing};
pub use tree::{Announcement, Cost, Hop, MalformedAnnouncement, distance};
