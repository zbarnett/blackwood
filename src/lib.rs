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
//!   destination is always exactly one hop closer, so a node with a consistent
//!   view always has a next hop to offer.
//!
//! The tree itself is loop-free for a separate reason: an announcement carries
//! its whole path, and a node refuses to sit below any path that already runs
//! through it. Staleness can cost a node its route, never its acyclicity.
//!
//! # What this is not
//!
//! Nothing here performs I/O, reads a clock, allocates a thread, or calls into
//! the operating system; the crate has no dependencies beyond `std` and no
//! `unsafe`. A [`Node`] is a state machine whose every effect on the world is
//! the [`Envelope`]s it hands back, which is what makes a network of them
//! deterministically simulatable and what should make the argument above
//! tractable to check in a proof assistant.
//!
//! Four things ironwood does are deliberately left out, each of them an
//! optimisation or a hardening of the model above rather than part of it:
//!
//! - **Cryptography.** Ironwood signs announcements so a node cannot lie about
//!   its parent. Here a key is an opaque identifier and announcements are
//!   trusted, so this core is correct only among honest participants.
//! - **Soft state.** Ironwood expires announcements on a timer and refreshes
//!   them once a second. This core is driven purely by events, so state changes
//!   only when a message arrives or a link goes up or down.
//! - **Bloom filters.** Ironwood keeps constant state per peer and finds
//!   unknown destinations by lookup. Here every node learns every announcement,
//!   which is linear in the size of the network but needs no lookup protocol.
//! - **Link cost.** Ironwood weighs latency when picking a parent and a next
//!   hop. Here every link counts the same, so the choice is a pure function of
//!   the keys involved.
//!
//! # Example
//!
//! ```
//! use blackwood::{Message, Node, PublicKey};
//!
//! let (a, b) = (PublicKey::new([1; 32]), PublicKey::new([2; 32]));
//! let (mut a_node, mut b_node) = (Node::new(a), Node::new(b));
//!
//! // Bring up the link, then hand each side what the other offered.
//! let to_b = a_node.add_peer(b);
//! for envelope in b_node.add_peer(a) {
//!     a_node.handle(b, envelope.message);
//! }
//! for envelope in to_b {
//!     b_node.handle(a, envelope.message);
//! }
//!
//! // The smaller key is the root, and the other sits below it.
//! assert_eq!(b_node.root(), a);
//! assert_eq!(b_node.parent(), Some(a));
//!
//! // A packet crosses the single hop.
//! for envelope in a_node.send(b, b"hello".to_vec()).expect("route is known") {
//!     b_node.handle(a, envelope.message);
//! }
//! assert_eq!(b_node.take_delivered()[0].payload, b"hello");
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod key;
pub mod message;
pub mod node;
pub mod tree;

pub use key::{KEY_LEN, PublicKey};
pub use message::{Envelope, Message, Packet};
pub use node::{Node, SendError};
pub use tree::{Announcement, MalformedAnnouncement, distance};
