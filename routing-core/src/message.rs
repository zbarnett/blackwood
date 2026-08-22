//! What nodes hand to one another across a link.

use std::fmt;

use crate::key::PublicKey;
use crate::signature::{Signature, Signer};
use crate::summary::Summary;
use crate::tree::{Announcement, Consent, Hop};

/// The length of a search nonce in bytes.
pub const NONCE_LEN: usize = 16;

/// The one-off number a search carries, so that its answer can be tied to it.
///
/// The core generates none of its own, for the same reason it reads no clock:
/// randomness comes from the operating system, and this crate does not touch
/// one. A caller hands a fresh one to [`lookup`], and it must be one nobody
/// else can guess — an answer is only evidence that its subject is alive now
/// because that subject signed a number it cannot have seen coming.
///
/// [`lookup`]: crate::node::Node::lookup
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Nonce([u8; NONCE_LEN]);

impl Nonce {
    /// Wraps raw nonce bytes.
    pub const fn new(bytes: [u8; NONCE_LEN]) -> Self {
        Self(bytes)
    }

    /// The raw nonce bytes.
    pub const fn as_bytes(&self) -> &[u8; NONCE_LEN] {
        &self.0
    }
}

impl fmt::Debug for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "nonce:")?;
        for byte in &self.0[..4] {
            write!(f, "{byte:02x}")?;
        }
        f.write_str("…")
    }
}

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
    /// The number this particular search is carrying.
    ///
    /// The node that answers signs it, so an answer belongs to the search that
    /// asked for it and cannot be a recording of an older one. It is also what
    /// the asker recognises its own answer by, so nothing arriving unbidden is
    /// mistaken for one.
    pub nonce: Nonce,
    /// Every node this has passed through: the one that asked first, and the
    /// one that just sent it last.
    ///
    /// It does two jobs. A node that finds itself already on it refuses to
    /// take the search again, which is what stops one circling while the tree
    /// is unsettled. And it is the way home for the answer.
    pub trail: Vec<PublicKey>,
}

/// The answer to a [`Lookup`], on its way back.
///
/// An announcement on its own settles only who said something, never when: a
/// signature is as good on a long-dead walk as on a fresh one, and a node that
/// has never heard of the subject has nothing to compare a stale copy against.
/// So the answer also carries the subject's signature over the searching
/// node's own nonce, which is the one thing a recording cannot supply. What
/// comes back is therefore evidence that the subject was alive to hear the
/// question, and that this is where it sat when it did.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Found {
    /// Where the node that was looked for says it sits.
    pub announcement: Announcement,
    /// The nonce of the search being answered.
    pub nonce: Nonce,
    /// The subject's signature over that nonce and over the announcement
    /// above, binding the two together so neither can be paired with another.
    pub proof: Signature,
    /// What is left of the search's trail. Each node hands the answer to
    /// whoever comes before it and drops itself off the end, so the answer
    /// retraces the search exactly rather than needing a route of its own.
    pub trail: Vec<PublicKey>,
}

impl Found {
    /// The answer `signer`'s node gives to a search that has reached it.
    pub(crate) fn answer<S: Signer>(
        signer: &S,
        announcement: Announcement,
        nonce: Nonce,
        trail: Vec<PublicKey>,
    ) -> Self {
        let proof = signer.sign(&answer_bytes(nonce, &announcement));
        Self {
            announcement,
            nonce,
            proof,
            trail,
        }
    }

    /// Whether this answer holds together: a well-signed walk, and the node it
    /// describes vouching for both that walk and the search it answers.
    ///
    /// Every node the answer passes through asks this before passing it on, so
    /// an answer that does not hold together never travels: a node handed one
    /// that does not is being handed it by whoever made it up.
    pub fn verify<S: Signer>(&self) -> bool {
        self.announcement.verify::<S>()
            && S::verify(
                self.announcement.author(),
                &answer_bytes(self.nonce, &self.announcement),
                &self.proof,
            )
    }
}

/// What a node is putting its name to when it answers a search.
const ANSWER_DOMAIN: &[u8] = b"blackwood/answer/1";

/// The bytes an answer is signed over: the search's nonce, the node
/// answering, and the walk it is claiming.
///
/// The walk enters by its author's own signature, which already covers every
/// hop above it, so signing these few bytes commits to the whole announcement.
/// Without that the proof would say only "I am alive", and anybody holding it
/// could staple it to an older walk.
fn answer_bytes(nonce: Nonce, announcement: &Announcement) -> Vec<u8> {
    let mut bytes = Vec::from(ANSWER_DOMAIN);
    bytes.extend_from_slice(nonce.as_bytes());
    bytes.extend_from_slice(announcement.author().as_bytes());
    bytes.extend_from_slice(announcement.author_signature().as_bytes());
    bytes
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
    /// The sender's agreement that the receiver may sit below it.
    ///
    /// Offered when a link comes up and again whenever the sender re-prices
    /// it, because the price is part of what is being agreed to. A node cannot
    /// take up a position below a peer it holds no consent from.
    Consent(Consent),
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
