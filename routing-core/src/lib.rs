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
//! Every node announces the path of keys running from that root down to itself.
//! An announcement crosses one link and stops: a node needs to know where its
//! own peers sit and nothing else, so nothing is ever relayed and nothing
//! accumulates. Announcements are only ever authored by the node they describe,
//! so what a node holds about each of its peers is a max register, its join
//! simply the greater of the two — a repeat, or one that arrives out of order,
//! can be dropped on sight rather than reasoned about.
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
//! The destination's path travels in the packet, since no node along the way
//! holds it. That is also what makes the first property exact rather than
//! nearly so: every node on the route measures its progress against the same
//! target, instead of against its own copy of one.
//!
//! # Finding a node
//!
//! Addressing a node that is not a peer means finding out where it sits first.
//! Each node keeps, for each of its tree links, a [`Summary`] of the keys
//! reachable through it — a Bloom filter, a fixed few bytes however much lies
//! beyond — got by folding together what its *other* tree links told it.
//! Leaving out the link the summary is bound for is the whole trick: it makes
//! each one mean "what is on my side of this", and it is why summaries cross
//! tree links only. Folded around a cycle they would carry every key back to
//! where it came from until each one claimed the entire network.
//!
//! A search then walks the tree, handed on at each step only to the neighbours
//! whose summary admits the target might lie beyond them, and the node being
//! looked for answers by retracing the search's own trail. A summary never
//! misses a key it holds, so a search cannot overlook the branch its target is
//! really on; one that claims a key it does not hold costs a detour and nothing
//! more. As a summary fills, it prunes less, and in the limit a search is a
//! flood — which is what this would be without any of it.
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
//! What a node holds is a fixed amount per link, its own position, and the
//! positions of the nodes it is currently talking to — the last of these being
//! the only part that grows with use, and expiry is what bounds it. Nothing
//! here scales with the size of the network.
//!
//! Two things ironwood does are left out, both of them hardening rather than
//! part of the model above:
//!
//! - **Consent from a parent.** Every hop here is signed by the node it names,
//!   so nobody can be placed by anybody else — but a node can still claim to
//!   sit below a peer that never agreed to it. The claim is largely
//!   self-defeating, since packets routed to it through that peer are dropped
//!   by a peer that has no link to it. Ironwood closes it properly: the parent
//!   signs the hop naming the child, so a position is a bargain rather than an
//!   assertion. Doing the same here would mean a separate announcement per
//!   recipient, and the parent rather than the child pricing the link between
//!   them, which is the whole of why it is not done.
//! - **Signed summaries and searches.** A [`Summary`] is a claim about one
//!   link, made by the node on the far end of it, and there is nobody else who
//!   could sign it. Lying costs a search a wasted detour or an unanswered
//!   question; it cannot deliver a packet to the wrong node.
//!
//! One thing is simply not here yet. An [`Announcement`] can be taken apart
//! into [`Hop`]s and put back together through [`Announcement::new`], which is
//! the seam a wire format decodes through; a [`Summary`] has no such seam, so a
//! [`Message::Summary`] cannot be encoded by anything outside this crate. The
//! bits are a plain array and exposing them is a few lines, but nothing in this
//! repository sends a message over a wire, and an accessor nothing calls is an
//! accessor nothing has checked.
//!
//! # Signing
//!
//! Every hop of an announcement carries the signature of the node it names,
//! over that hop and over every hop above it exactly as they stand. A walk down
//! the tree is therefore a chain of statements, each made by the node it is
//! about: nobody can put a node somewhere it has not put itself, and no part of
//! one announcement can be lifted into another. That is what makes the answer
//! to a search worth having, since answering one is the only time a node speaks
//! about anybody but itself.
//!
//! The core performs none of this. It says what has to be signed and what has
//! to be checked, and takes the algorithm as a type parameter — which is how it
//! carries no dependencies and still refuses to take a stranger's word for
//! anything. There is nothing to opt out of and no stand-in shipped here to
//! reach for by accident: a [`Node`] cannot be built without a [`Signer`], so
//! whatever a network is running, somebody chose it. The `blackwood-ed25519`
//! crate is that choice made with real keys behind it, and the example below
//! is the smallest thing the trait will accept, written out so that what a
//! caller has to supply is on the page.
//!
//! A signature settles who said something, never whether it is still so. It is
//! as good on a long-dead announcement as on a fresh one, which is what
//! sequence numbers and expiry are there for.
//!
//! # Example
//!
//! ```
//! use routing_core::{
//!     Cost, KEY_LEN, Node, PublicKey, SIGNATURE_LEN, Signature, Signer, Timing,
//! };
//!
//! // The algorithm arrives from outside, so an example has to bring one. This
//! // one is worth nothing on purpose: a signature here is the signer's own key
//! // written out, and anybody can write out anybody's key. It is the whole of
//! // what the trait asks for, which is the point of showing it —
//! // `blackwood-ed25519` is the same four methods over real keys.
//! struct NoSecret(PublicKey);
//!
//! impl Signer for NoSecret {
//!     fn public_key(&self) -> PublicKey {
//!         self.0
//!     }
//!
//!     fn sign(&self, _message: &[u8]) -> Signature {
//!         let mut bytes = [0; SIGNATURE_LEN];
//!         bytes[..KEY_LEN].copy_from_slice(self.0.as_bytes());
//!         Signature::new(bytes)
//!     }
//!
//!     fn verify(key: PublicKey, _message: &[u8], signature: &Signature) -> bool {
//!         signature.as_bytes()[..KEY_LEN] == key.as_bytes()[..]
//!     }
//! }
//!
//! let (a, b) = (PublicKey::new([1; 32]), PublicKey::new([2; 32]));
//!
//! // A node's address is whatever key it can sign as, so an identity and the
//! // means of proving it arrive together and cannot come apart. The schedule
//! // is handed over for the same reason the signer is: the instants below are
//! // milliseconds because this caller says so, not because the core assumed a
//! // unit it has no way of knowing.
//! let (mut a_node, mut b_node) = (
//!     Node::new(0, NoSecret(a), Timing::MILLISECONDS),
//!     Node::new(0, NoSecret(b), Timing::MILLISECONDS),
//! );
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
//! // A packet crosses the single hop. b is a's peer, so a already holds its
//! // position; anywhere further would have to be found with `lookup` first.
//! for envelope in a_node.send(b, b"hello".to_vec()).expect("route is known") {
//!     b_node.handle(0, a, envelope.message);
//! }
//! assert_eq!(b_node.take_delivered()[0].payload, b"hello");
//!
//! // Let time pass with nothing arriving from a, and b forgets where it sat.
//! b_node.tick(Timing::MILLISECONDS.expiry);
//! assert_eq!(b_node.root(), b);
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod key;
pub mod message;
pub mod node;
pub mod signature;
pub mod summary;
pub mod tree;

/// A signer with the cryptography left out, so that the tests in this crate
/// can drive the core without one. Compiled only for those tests, and so
/// unreachable from anywhere a real network could run.
#[cfg(test)]
mod stand_in;

pub use key::{KEY_LEN, PublicKey};
pub use message::{Envelope, Found, Lookup, Message, Packet, Traffic};
pub use node::{Node, SendError, Timing};
pub use signature::{SIGNATURE_LEN, Signature, Signer};
pub use summary::Summary;
pub use tree::{Announcement, Cost, Hop, MalformedAnnouncement};
