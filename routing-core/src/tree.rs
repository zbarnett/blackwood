//! The spanning tree: what nodes announce, and the metric derived from it.

use std::cmp::Ordering;
use std::fmt;

use crate::key::PublicKey;
use crate::signature::{SIGNATURE_LEN, Signature, Signer};

/// What crossing one link costs.
///
/// Ironwood measures a peering's latency; here the number is whatever the
/// caller says it is, counted in whatever unit it likes. Only the ordering
/// matters, and only among the links of one network.
///
/// A cost is at least one, which is what keeps both of the protocol's
/// guarantees standing: a packet makes strict progress at every hop, and a
/// node's parent is strictly nearer the root than the node itself. A network
/// whose links all cost [`Cost::UNIT`] measures distance in hops, which is
/// what this core did before costs existed.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Cost(u64);

impl Cost {
    /// The cost of a link counted as a single hop.
    pub const UNIT: Self = Self(1);

    /// Wraps a measurement, rejecting the zero a free link would claim to be.
    pub const fn new(value: u64) -> Option<Self> {
        match value {
            0 => None,
            value => Some(Self(value)),
        }
    }

    /// The measurement itself.
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for Cost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// One step down the tree: a node, what reaching it cost, and its own hand on
/// the whole walk down to it.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Hop {
    /// The node this step arrives at.
    pub key: PublicKey,
    /// What the link from the previous hop to this one costs to cross, as
    /// priced by the previous hop.
    ///
    /// The node above sets it because it is the one that has to carry the
    /// traffic, and it is part of what that node signed in [`Hop::consent`] —
    /// so a node cannot announce a cheaper link than the one it was offered.
    ///
    /// Zero at the root, which nothing precedes, and at least one at every
    /// other hop. [`Announcement`] guarantees both, so summing the costs of a
    /// path's tail is always the cost of a real walk.
    pub cost: u64,
    /// The sequence number this hop's node stamped it with.
    ///
    /// Every hop carries its own, because every hop was signed separately by
    /// the node that added it, and the number is part of what it signed.
    pub seq: u64,
    /// The hop above's agreement that this node may sit below it at this price.
    ///
    /// `None` at the root, which nothing precedes, and `Some` at every other
    /// hop: the signature of the node named in the hop above, over this node's
    /// key and the cost of the link between them. It is what makes a position
    /// a bargain struck by both ends rather than a claim made by one, and so
    /// what stops a node signing itself onto a walk it has no link to.
    ///
    /// [`Announcement`] guarantees the shape, so a hop below the root always
    /// carries one and the root never does.
    pub consent: Option<Signature>,
    /// That node's signature over this hop and every hop above it.
    ///
    /// The signature covers the hops above exactly as they stand, their own
    /// signatures included, so a hop is bound to the particular walk it was
    /// made for and cannot be lifted out of one announcement into another.
    pub signature: Signature,
}

/// A node's agreement that another may sit below it in the tree.
///
/// A position in the tree is the only thing a node says that is really about
/// two nodes rather than one, and this is the other end's half of it. The
/// parent signs the child's key together with the price it puts on the link
/// between them; the child carries that signature in its own hop, where
/// anybody reading its walk down the tree can check it.
///
/// The cost travels here rather than in the child's announcement because the
/// parent is the end that has to agree to carry the traffic. A child that
/// understated what its link cost would otherwise be advertising a bargain
/// nobody had offered it.
///
/// A value of this type has always been checked. It is either one this node
/// signed itself, through [`issue`](Self::issue), or one that verified when it
/// was decoded, through [`new`](Self::new) — there is no third way to build
/// one, which is what lets [`Announcement::extend`] take it on trust.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Consent {
    parent: PublicKey,
    child: PublicKey,
    cost: Cost,
    signature: Signature,
}

impl Consent {
    /// The consent `signer`'s node gives `child` to sit below it, over a link
    /// the signer prices at `cost`.
    pub fn issue<S: Signer>(signer: &S, child: PublicKey, cost: Cost) -> Self {
        let parent = signer.public_key();
        Self {
            parent,
            child,
            cost,
            signature: signer.sign(&consent_bytes(parent, child, cost.get())),
        }
    }

    /// Rebuilds a consent from its parts, rejecting one `parent` did not sign.
    ///
    /// The entry point an eventual wire format would decode through, and the
    /// only way into this type from outside that does not involve signing.
    pub fn new<S: Signer>(
        parent: PublicKey,
        child: PublicKey,
        cost: Cost,
        signature: Signature,
    ) -> Option<Self> {
        S::verify(parent, &consent_bytes(parent, child, cost.get()), &signature).then_some(Self {
            parent,
            child,
            cost,
            signature,
        })
    }

    /// The node that gave this consent.
    pub fn parent(&self) -> PublicKey {
        self.parent
    }

    /// The node it was given to.
    pub fn child(&self) -> PublicKey {
        self.child
    }

    /// What the parent says the link between them costs.
    pub fn cost(&self) -> Cost {
        self.cost
    }

    /// The parent's signature, as it travels in the child's hop.
    pub fn signature(&self) -> Signature {
        self.signature
    }
}

/// A node's claimed position in the spanning tree.
///
/// The path runs from the root down to the announcing node, inclusive, so
/// `path[0]` is the root and the last element is the author. Each hop carries
/// the cost of the link that reaches it, as priced by the node above — the one
/// that agreed to carry it — along with that node's consent and its own
/// signature. Carrying the whole path rather than just a parent pointer is
/// what makes routing decisions local: a node can compute its distance to any
/// other node it has heard of without consulting anyone.
///
/// Every constructor guarantees the path is non-empty, free of repeated keys,
/// priced as [`Hop::cost`] describes, signed at every hop by the node that hop
/// names, and consented to at every hop by the node above it. A value of this type is therefore always well formed, but it is
/// only as *current* as whoever handed it over: see [`verify`](Self::verify)
/// for what a signature does and does not settle.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Announcement {
    path: Vec<Hop>,
}

/// Why a path could not be made into an [`Announcement`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MalformedAnnouncement {
    /// The path had no hops, so it named no author.
    EmptyPath,
    /// A key appeared twice, which would describe a loop rather than a path.
    RepeatedKey,
    /// The root hop carried a cost, though no link reaches the root.
    CostAtRoot,
    /// A link below the root cost nothing, so crossing it would be no progress.
    FreeLink,
    /// Some hop was not signed by the node it names.
    BadSignature,
    /// The root hop carried a consent, though no node sits above the root to
    /// have given it one.
    ConsentAtRoot,
    /// A hop below the root carried no consent, so it claimed a place nobody
    /// agreed to.
    MissingConsent,
    /// Some hop's consent was not signed by the node in the hop above it, or
    /// was given to another node or at another price.
    BadConsent,
}

impl fmt::Display for MalformedAnnouncement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPath => f.write_str("announcement path is empty"),
            Self::RepeatedKey => f.write_str("announcement path repeats a key"),
            Self::CostAtRoot => f.write_str("announcement prices the link into its root"),
            Self::FreeLink => f.write_str("announcement path contains a link costing nothing"),
            Self::BadSignature => {
                f.write_str("announcement hop is not signed by the node it names")
            }
            Self::ConsentAtRoot => f.write_str("announcement root carries a consent"),
            Self::MissingConsent => {
                f.write_str("announcement hop sits below a node that did not consent")
            }
            Self::BadConsent => {
                f.write_str("announcement hop's consent was not given by the node above it")
            }
        }
    }
}

impl std::error::Error for MalformedAnnouncement {}

impl Announcement {
    /// The announcement of a node that considers itself the root of its own tree.
    pub fn root_of<S: Signer>(signer: &S, seq: u64) -> Self {
        Self::signed_onto(signer, Vec::new(), 0, None, seq)
    }

    /// Builds an announcement from its parts, rejecting anything malformed or
    /// unsigned.
    ///
    /// Every other constructor preserves the invariants by construction; this
    /// is the entry point an eventual wire format would decode through.
    pub fn new<S: Signer>(path: Vec<Hop>) -> Result<Self, MalformedAnnouncement> {
        let Some((root, below)) = path.split_first() else {
            return Err(MalformedAnnouncement::EmptyPath);
        };
        if root.cost != 0 {
            return Err(MalformedAnnouncement::CostAtRoot);
        }
        if root.consent.is_some() {
            return Err(MalformedAnnouncement::ConsentAtRoot);
        }
        if below.iter().any(|hop| hop.cost == 0) {
            return Err(MalformedAnnouncement::FreeLink);
        }
        if below.iter().any(|hop| hop.consent.is_none()) {
            return Err(MalformedAnnouncement::MissingConsent);
        }
        for (index, hop) in path.iter().enumerate() {
            if path[..index].iter().any(|earlier| earlier.key == hop.key) {
                return Err(MalformedAnnouncement::RepeatedKey);
            }
        }
        let announcement = Self { path };
        if !announcement.hops_signed::<S>() {
            return Err(MalformedAnnouncement::BadSignature);
        }
        if !announcement.consents_given::<S>() {
            return Err(MalformedAnnouncement::BadConsent);
        }
        Ok(announcement)
    }

    /// The announcement `signer`'s node would make by attaching itself below
    /// this one, on the strength of `consent`.
    ///
    /// The price of the link is the one the parent named when it consented,
    /// not one the child picks, so a node cannot advertise a bargain nobody
    /// offered it.
    ///
    /// Returns `None` when the consent is not this announcement's author
    /// agreeing to this signer, or when the signer's key already appears in
    /// the path. The second check is what keeps the tree loop-free: a node
    /// never adopts a path that runs through itself, so no cycle can form
    /// however stale its view is.
    ///
    /// The consent's signature is taken on trust, because a [`Consent`] cannot
    /// be built without one that checks out.
    pub fn extend<S: Signer>(&self, signer: &S, consent: &Consent, seq: u64) -> Option<Self> {
        let child = signer.public_key();
        if consent.parent != self.author() || consent.child != child {
            return None;
        }
        if self.path.iter().any(|hop| hop.key == child) {
            return None;
        }
        Some(Self::signed_onto(
            signer,
            self.path.clone(),
            consent.cost.get(),
            Some(consent.signature),
            seq,
        ))
    }

    /// The same walk, stamped with a new sequence number and signed afresh.
    ///
    /// Only the author's own hop is restamped, because only the author can
    /// sign it; the walk down to it stands exactly as the nodes above it
    /// signed. Returns `None` for a signer that is not the author, which is
    /// the only thing it could mean.
    pub(crate) fn with_seq<S: Signer>(&self, signer: &S, seq: u64) -> Option<Self> {
        if signer.public_key() != self.author() {
            return None;
        }
        let mut above = self.path.clone();
        // The author's own hop is the one being restamped, and there is always
        // one to take: `author` above just read it.
        let own = above.pop()?;
        Some(Self::signed_onto(signer, above, own.cost, own.consent, seq))
    }

    /// The walk `above`, with `signer`'s node signed onto the end of it at a
    /// link costing `cost`.
    ///
    /// The only place a hop is ever made, so that the three ways of arriving
    /// at an announcement — rooting, extending, restamping — cannot drift
    /// apart in what they put their name to.
    fn signed_onto<S: Signer>(
        signer: &S,
        mut above: Vec<Hop>,
        cost: u64,
        consent: Option<Signature>,
        seq: u64,
    ) -> Self {
        let key = signer.public_key();
        let signature = signer.sign(&signed_bytes(&above, key, cost, consent, seq));
        above.push(Hop {
            key,
            cost,
            seq,
            consent,
            signature,
        });
        Self { path: above }
    }

    /// Whether every hop was signed by the node it names *and* agreed to by
    /// the node above it.
    ///
    /// What this settles is that every link in the walk is real. Authorship is
    /// the first half: nobody can put a node somewhere it has not put itself,
    /// so an answer to a search cannot invent a position for its subject and a
    /// node cannot invent the walk above it. Consent is the second: every step
    /// down the path is signed by both of the nodes it joins, so a node cannot
    /// sign itself onto a walk it has no link to, however much of that walk it
    /// has seen.
    ///
    /// What it does not settle is whether any of it is still true — a signature
    /// is as valid on a long-dead announcement as on a fresh one, which is what
    /// sequence numbers and expiry are for.
    pub fn verify<S: Signer>(&self) -> bool {
        self.hops_signed::<S>() && self.consents_given::<S>()
    }

    /// Whether every hop was signed by the node it names.
    fn hops_signed<S: Signer>(&self) -> bool {
        self.path.iter().enumerate().all(|(index, hop)| {
            let bytes = signed_bytes(&self.path[..index], hop.key, hop.cost, hop.consent, hop.seq);
            S::verify(hop.key, &bytes, &hop.signature)
        })
    }

    /// Whether every hop below the root carries the consent of the hop above
    /// it, at the price the path claims, and the root carries none.
    fn consents_given<S: Signer>(&self) -> bool {
        self.path
            .iter()
            .enumerate()
            .all(|(index, hop)| match (index.checked_sub(1), hop.consent) {
                // Nothing sits above the root, so nothing could have agreed to
                // it and nothing may claim to have.
                (None, None) => true,
                (Some(above), Some(consent)) => {
                    let parent = self.path[above].key;
                    let bytes = consent_bytes(parent, hop.key, hop.cost);
                    S::verify(parent, &bytes, &consent)
                }
                _ => false,
            })
    }

    /// The author's own signature, which covers the whole walk down to it and
    /// so stands for the announcement as a whole.
    pub(crate) fn author_signature(&self) -> Signature {
        // The path is never empty, so this cannot panic.
        self.path[self.path.len() - 1].signature
    }

    /// The sequence number its author last stamped it with.
    pub fn seq(&self) -> u64 {
        // The path is never empty, so this cannot panic.
        self.path[self.path.len() - 1].seq
    }

    /// The path from the root down to the author.
    pub fn path(&self) -> &[Hop] {
        &self.path
    }

    /// The root of the tree this announcement belongs to.
    pub fn root(&self) -> PublicKey {
        // The path is never empty, so this cannot panic.
        self.path[0].key
    }

    /// The node that made this announcement.
    pub fn author(&self) -> PublicKey {
        // The path is never empty, so this cannot panic.
        self.path[self.path.len() - 1].key
    }

    /// The author's parent, or `None` if the author is the root.
    pub fn parent(&self) -> Option<PublicKey> {
        self.path
            .len()
            .checked_sub(2)
            .map(|index| self.path[index].key)
    }

    /// What the walk from the author up to the root costs.
    ///
    /// This is the number parent selection minimises, and it is zero exactly
    /// for a node that believes it is the root.
    pub fn cost_to_root(&self) -> u64 {
        total_cost(self.path.iter())
    }

    /// Whether this describes the same walk as `other`: the same nodes at the
    /// same prices, however either of them was stamped and signed.
    ///
    /// This is the question "have I moved?", which the stamps must not answer.
    /// Comparing whole announcements would say yes every time anybody above
    /// reissued, and a node would spend its life announcing that nothing had
    /// changed.
    pub(crate) fn same_position(&self, other: &Self) -> bool {
        self.path.len() == other.path.len()
            && std::iter::zip(&self.path, &other.path)
                .all(|(here, there)| here.key == there.key && here.cost == there.cost)
    }

    /// Whether this announcement replaces `other` in the set of known announcements.
    ///
    /// Announcements are only ever authored by the node they describe, so per
    /// author this set is a max register: the join is whichever announcement is
    /// greater. Sequence number decides, with the path as a tie-break purely so
    /// that the rule is total and every node reaches the same answer.
    pub(crate) fn supersedes(&self, other: &Self) -> bool {
        (self.seq(), &self.path) > (other.seq(), &other.path)
    }

    /// Builds an announcement with nothing checked at all.
    ///
    /// Only tests have this, and only so they can present a node with
    /// something a well-behaved network could not have produced.
    #[cfg(test)]
    pub(crate) fn unchecked(path: Vec<Hop>) -> Self {
        Self { path }
    }

    /// Orders candidate parents, most preferred first.
    ///
    /// Smallest root key wins, so the network agrees on one root; then the
    /// cheapest walk to that root, which is the whole point of link cost; then
    /// the fewest hops, since two equally priced walks are not equally cheap to
    /// forward over; then the smallest path, so that ties are broken
    /// identically everywhere and the tree has a single fixed point. Two
    /// candidates always differ by the key of some hop before anything a stamp
    /// could reach, so the ordering does not move when a sequence number does.
    pub(crate) fn preference_cmp(&self, other: &Self) -> Ordering {
        self.root()
            .cmp(&other.root())
            .then_with(|| self.cost_to_root().cmp(&other.cost_to_root()))
            .then_with(|| self.path.len().cmp(&other.path.len()))
            .then_with(|| self.path.cmp(&other.path))
    }
}

/// What the walk between two nodes costs along the tree.
///
/// Both paths descend from the root, so they share a prefix ending at the two
/// nodes' lowest common ancestor; the distance is the climb up to it plus the
/// descent back down, each link counted at what it costs. Within one tree that
/// is zero only between a node and itself, since no link is free.
///
/// Two paths that disagree about the root share no prefix at all, and the
/// result — what each of them pays to reach its own root — is well defined but
/// says nothing about how far apart they are. That is the transient state
/// routing tolerates by refusing to forward without strict progress: rather
/// than trust the number, a node drops the packet.
///
/// Only keys are compared to find the shared prefix, so two nodes holding
/// differently stamped copies of the same walk still agree on where it forks.
pub(crate) fn distance(a: &[Hop], b: &[Hop]) -> u64 {
    let shared = a.iter().zip(b).take_while(|(x, y)| x.key == y.key).count();
    // Dropping the shared prefix leaves exactly the hops below the two nodes'
    // common ancestor: the climb from each of them up to it.
    total_cost(a.iter().skip(shared)).saturating_add(total_cost(b.iter().skip(shared)))
}

/// What crossing every link in `hops` costs, saturating rather than wrapping.
///
/// The ceiling needs costs summing past `u64::MAX`, which no caller counting
/// anything real can reach; a route that looks infinitely expensive still
/// beats one that looks free.
fn total_cost<'a>(hops: impl Iterator<Item = &'a Hop>) -> u64 {
    hops.fold(0, |total, hop| total.saturating_add(hop.cost))
}

/// What a node is putting its name to when it signs its own hop.
///
/// Every kind of statement a node makes starts with one of these, so that
/// bytes signed as one thing can never be read back as another however the
/// rest of them line up.
pub(crate) const HOP_DOMAIN: &[u8] = b"blackwood/hop/1";

/// What a node is putting its name to when it agrees to carry a child.
const CONSENT_DOMAIN: &[u8] = b"blackwood/consent/1";

/// The bytes a hop is signed over: every hop above it exactly as it stands,
/// signatures and all, followed by its own key, cost, sequence number and the
/// consent it sits on.
///
/// Including the hops above by their signatures is what chains them. A hop
/// commits to the particular walk it was added to, so no part of one
/// announcement can be spliced into another. Its own consent is in there for
/// the same reason: the agreement it sits on cannot be swapped for another.
///
/// A missing consent is written as a signature of zeroes rather than left out,
/// so every hop occupies the same width and no two different paths can lay
/// themselves out as the same bytes.
fn signed_bytes(
    above: &[Hop],
    key: PublicKey,
    cost: u64,
    consent: Option<Signature>,
    seq: u64,
) -> Vec<u8> {
    const NO_CONSENT: Signature = Signature::new([0; SIGNATURE_LEN]);

    let mut bytes = Vec::from(HOP_DOMAIN);
    for hop in above {
        bytes.extend_from_slice(hop.key.as_bytes());
        bytes.extend_from_slice(&hop.cost.to_be_bytes());
        bytes.extend_from_slice(&hop.seq.to_be_bytes());
        bytes.extend_from_slice(hop.consent.unwrap_or(NO_CONSENT).as_bytes());
        bytes.extend_from_slice(hop.signature.as_bytes());
    }
    bytes.extend_from_slice(key.as_bytes());
    bytes.extend_from_slice(&cost.to_be_bytes());
    bytes.extend_from_slice(&seq.to_be_bytes());
    bytes.extend_from_slice(consent.unwrap_or(NO_CONSENT).as_bytes());
    bytes
}

/// The bytes a parent signs to agree that `child` may sit below it at `cost`.
///
/// Both keys are named, so a consent cannot be handed to a different child or
/// presented as coming from a different parent, and the price is in there
/// because agreeing to carry a node is agreeing to carry it at some price.
fn consent_bytes(parent: PublicKey, child: PublicKey, cost: u64) -> Vec<u8> {
    let mut bytes = Vec::from(CONSENT_DOMAIN);
    bytes.extend_from_slice(parent.as_bytes());
    bytes.extend_from_slice(child.as_bytes());
    bytes.extend_from_slice(&cost.to_be_bytes());
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stand_in::StandIn;

    fn key(n: u8) -> PublicKey {
        PublicKey::new([n; crate::key::KEY_LEN])
    }

    fn signer(n: u8) -> StandIn {
        StandIn::for_key(key(n))
    }

    fn cost(n: u64) -> Cost {
        Cost::new(n).expect("a test cost is never zero")
    }

    /// `parent` agreeing to carry `child` over a link it prices at `price`.
    fn consent(parent: u8, child: u8, price: u64) -> Consent {
        Consent::issue(&signer(parent), key(child), cost(price))
    }

    /// An announcement for the node at the end of `root` + `steps`, built the
    /// way a real one is: each node attaching below the last over a link of the
    /// cost written beside it, on that node's consent, and signing its own hop
    /// as it goes.
    fn announcement(root: u8, steps: &[(u8, u64)]) -> Announcement {
        let mut announcement = Announcement::root_of(&signer(root), 0);
        let mut above = root;
        for &(node, price) in steps {
            announcement = announcement
                .extend(&signer(node), &consent(above, node, price), 0)
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

    #[test]
    fn a_cost_is_never_zero() {
        assert_eq!(Cost::new(0), None);
        assert_eq!(Cost::new(1), Some(Cost::UNIT));
        assert_eq!(cost(7).get(), 7);
    }

    #[test]
    fn rejects_malformed_paths() {
        assert_eq!(
            Announcement::new::<StandIn>(vec![]),
            Err(MalformedAnnouncement::EmptyPath)
        );

        let mut repeated = path(1, &[(2, 1)]);
        repeated.push(Hop {
            key: key(1),
            ..repeated[1]
        });
        assert_eq!(
            Announcement::new::<StandIn>(repeated),
            Err(MalformedAnnouncement::RepeatedKey)
        );

        let mut priced_root = path(1, &[]);
        priced_root[0].cost = 1;
        assert_eq!(
            Announcement::new::<StandIn>(priced_root),
            Err(MalformedAnnouncement::CostAtRoot)
        );

        let mut free = path(1, &[(2, 1)]);
        free[1].cost = 0;
        assert_eq!(
            Announcement::new::<StandIn>(free),
            Err(MalformedAnnouncement::FreeLink)
        );

        assert!(Announcement::new::<StandIn>(path(1, &[(2, 3)])).is_ok());
    }

    #[test]
    fn rejects_a_walk_that_was_altered_after_it_was_signed() {
        // Structurally perfect, and a lie: the price of the link into 2 rubbed
        // out and a cheaper one written in, which would put 2 nearer the root
        // than it has any right to be.
        let mut cheaper = path(1, &[(2, 5)]);
        cheaper[1].cost = 1;
        assert_eq!(
            Announcement::new::<StandIn>(cheaper),
            Err(MalformedAnnouncement::BadSignature)
        );

        let mut renamed = path(1, &[(2, 1)]);
        renamed[1].key = key(9);
        assert_eq!(
            Announcement::new::<StandIn>(renamed),
            Err(MalformedAnnouncement::BadSignature)
        );

        let mut restamped = path(1, &[(2, 1)]);
        restamped[1].seq = 500;
        assert_eq!(
            Announcement::new::<StandIn>(restamped),
            Err(MalformedAnnouncement::BadSignature)
        );
    }

    #[test]
    fn rejects_a_walk_altered_above_the_node_that_would_gain_by_it() {
        // The lie worth telling is not about one's own hop. 3 rubs out the
        // price of the link into 2, above it, so that the whole walk down to
        // it looks cheap and traffic for anything below comes its way — and
        // then signs its own hop over the altered walk, perfectly properly,
        // because that hop is the one thing here it is entitled to sign.
        //
        // Every hop below an alteration can be re-made like this by whoever
        // holds the key it names. What cannot be re-made is the signature on
        // the altered hop itself, which is why the check is per hop and not
        // merely a matter of following the chain down from the bottom.
        let mut above = path(1, &[(2, 9)]);
        above[1].cost = 1;
        let forged = Announcement::unchecked(above)
            .extend(&signer(3), &consent(2, 3, 1), 0)
            .expect("distinct key attaches");

        assert!(
            StandIn::verify(
                forged.path()[2].key,
                &signed_bytes(&forged.path()[..2], key(3), 1, forged.path()[2].consent, 0),
                &forged.path()[2].signature,
            ),
            "3's own hop is beyond reproach"
        );
        assert!(
            !forged.verify::<StandIn>(),
            "and 2's, which it rewrote, is not"
        );
        assert_eq!(
            Announcement::new::<StandIn>(forged.path().to_vec()),
            Err(MalformedAnnouncement::BadSignature)
        );
    }

    #[test]
    fn every_hop_is_signed_by_the_node_it_names() {
        let announcement = announcement(1, &[(2, 1), (3, 1)]);
        assert!(announcement.verify::<StandIn>());

        // Not one signature over the whole thing by the author: three, one per
        // node, so no single node's word covers anybody else's position.
        let signatures: Vec<_> = announcement
            .path()
            .iter()
            .map(|hop| hop.signature)
            .collect();
        assert_eq!(signatures.len(), 3);
        assert!(
            signatures[0] != signatures[1] && signatures[1] != signatures[2],
            "hops signed alike would mean they were not signed separately"
        );
    }

    #[test]
    fn a_hop_cannot_be_lifted_out_of_one_walk_into_another() {
        // 3 sits below 2 in one tree and below 4 in another, at the same price
        // and stamped the same. The two hops for 3 describe an identical step,
        // but each signature commits to the whole walk above it, so neither
        // hop is any use in the other's announcement.
        let below_two = announcement(1, &[(2, 1), (3, 1)]);
        let below_four = announcement(1, &[(4, 1), (3, 1)]);

        let mut spliced = below_four.path().to_vec();
        spliced[2] = below_two.path()[2];
        assert_eq!(spliced[2].key, below_four.path()[2].key);
        assert_eq!(spliced[2].cost, below_four.path()[2].cost);
        assert_eq!(spliced[2].seq, below_four.path()[2].seq);

        assert!(!Announcement::unchecked(spliced).verify::<StandIn>());
    }

    #[test]
    fn extending_records_what_the_link_cost() {
        let root = Announcement::root_of(&signer(1), 0);
        assert_eq!(root.cost_to_root(), 0, "the root is already there");

        let child = root
            .extend(&signer(2), &consent(1, 2, 4), 0)
            .expect("distinct key attaches");
        assert_eq!(walk(child.path()), [(key(1), 0), (key(2), 4)]);
        assert_eq!(child.parent(), Some(key(1)));
        assert_eq!(child.author(), key(2));
        assert_eq!(child.root(), key(1));
        assert_eq!(child.cost_to_root(), 4);
        assert!(child.verify::<StandIn>());

        let grandchild = child
            .extend(&signer(3), &consent(2, 3, 5), 0)
            .expect("distinct key attaches");
        assert_eq!(grandchild.cost_to_root(), 9, "costs add up the path");
        assert!(grandchild.verify::<StandIn>());
    }

    #[test]
    fn extending_refuses_to_form_a_loop() {
        let child = announcement(1, &[(2, 1)]);
        assert_eq!(child.extend(&signer(1), &consent(2, 1, 1), 0), None);
        assert_eq!(child.extend(&signer(2), &consent(2, 2, 1), 0), None);
    }

    #[test]
    fn extending_refuses_a_consent_meant_for_somebody_else() {
        let child = announcement(1, &[(2, 1)]);
        assert_eq!(
            child.extend(&signer(3), &consent(2, 4, 1), 0),
            None,
            "2 agreed to carry 4, not 3"
        );
        assert_eq!(
            child.extend(&signer(3), &consent(1, 3, 1), 0),
            None,
            "1 is not the node 3 would be sitting below"
        );
        assert!(
            child.extend(&signer(3), &consent(2, 3, 1), 0).is_some(),
            "the bargain 3 actually holds"
        );
    }

    #[test]
    fn a_walk_stands_on_consent_at_every_hop() {
        // A node that has seen somebody else's announcement — from a lookup
        // answer, say — holds every signature in it, and can sign its own hop
        // onto the end perfectly properly. What it cannot supply is the other
        // half of the bargain, and that is what stops it.
        let stranger = announcement(1, &[(2, 1)]);
        let mut spliced = stranger.path().to_vec();
        spliced.push(Hop {
            key: key(9),
            cost: 1,
            seq: 0,
            consent: Some(consent(2, 9, 1).signature()),
            signature: Signature::new([0; SIGNATURE_LEN]),
        });
        // With a consent 2 really gave, only the intruder's own hop is wrong.
        assert_eq!(
            Announcement::new::<StandIn>(spliced.clone()),
            Err(MalformedAnnouncement::BadSignature)
        );

        // Signed properly by the intruder, but sitting on nobody's agreement.
        let unwelcome = Announcement::unchecked(stranger.path().to_vec())
            .extend(&signer(9), &consent(2, 9, 1), 0)
            .expect("the intruder can sign its own hop");
        assert!(unwelcome.verify::<StandIn>(), "2 did agree to this one");

        let mut without = unwelcome.path().to_vec();
        without[2].consent = None;
        assert_eq!(
            Announcement::new::<StandIn>(without),
            Err(MalformedAnnouncement::MissingConsent)
        );

        // A consent from somebody other than the node above. The intruder
        // signs its own hop perfectly properly over it — that hop is the one
        // thing here it is entitled to sign — so nothing about the walk gives
        // it away except the agreement it is standing on.
        let above = announcement(1, &[(2, 1)]).path().to_vec();
        let elsewhere = consent(5, 9, 1).signature();
        let mut borrowed = above.clone();
        borrowed.push(Hop {
            key: key(9),
            cost: 1,
            seq: 0,
            consent: Some(elsewhere),
            signature: signer(9).sign(&signed_bytes(&above, key(9), 1, Some(elsewhere), 0)),
        });
        assert_eq!(
            Announcement::new::<StandIn>(borrowed),
            Err(MalformedAnnouncement::BadConsent),
            "5 is not the node 9 is sitting below"
        );

        let mut at_root = announcement(1, &[]).path().to_vec();
        at_root[0].consent = Some(consent(2, 1, 1).signature());
        assert_eq!(
            Announcement::new::<StandIn>(at_root),
            Err(MalformedAnnouncement::ConsentAtRoot)
        );
    }

    #[test]
    fn a_root_has_no_parent() {
        assert_eq!(Announcement::root_of(&signer(1), 0).parent(), None);
    }

    #[test]
    fn restamping_leaves_the_walk_where_it_was_and_still_checks_out() {
        let before = announcement(1, &[(2, 1), (3, 1)]);
        let after = before
            .with_seq(&signer(3), 7)
            .expect("the author may restamp");

        assert_eq!(after.seq(), 7);
        assert!(after.same_position(&before), "the walk did not move");
        assert_eq!(walk(after.path()), walk(before.path()));
        assert!(
            after.verify::<StandIn>(),
            "and it is signed for the new one"
        );
        assert!(after.supersedes(&before));

        // The hops above are untouched: only their author can restamp them,
        // and only the last hop had anything to restamp.
        assert_eq!(after.path()[..2], before.path()[..2]);
    }

    #[test]
    fn only_the_author_can_restamp() {
        let announcement = announcement(1, &[(2, 1), (3, 1)]);
        assert_eq!(announcement.with_seq(&signer(2), 7), None, "its parent");
        assert_eq!(announcement.with_seq(&signer(9), 7), None, "a stranger");
    }

    #[test]
    fn the_same_walk_is_the_same_position_however_it_was_stamped() {
        let announcement = announcement(1, &[(2, 1)]);
        let restamped = announcement
            .with_seq(&signer(2), 99)
            .expect("the author may restamp");

        assert!(announcement.same_position(&restamped));
        assert_ne!(announcement, restamped, "the values themselves differ");
        assert!(!announcement.same_position(&super::Announcement::root_of(&signer(1), 0)));
    }

    #[test]
    fn a_re_priced_walk_is_a_different_position() {
        // The same nodes in the same order, over a link measured again and
        // found worse. Nothing about the shape of the walk moved, but what it
        // costs to follow did, and a node that called this standing still
        // would keep the new price to itself and leave everyone below it
        // working from the old one.
        let before = announcement(1, &[(2, 1)]);
        let after = announcement(1, &[(2, 5)]);

        let keys = |a: &Announcement| a.path().iter().map(|hop| hop.key).collect::<Vec<_>>();
        assert_eq!(keys(&before), keys(&after), "nobody moved");
        assert!(!before.same_position(&after));
    }

    #[test]
    fn later_sequence_numbers_supersede() {
        let old = Announcement::root_of(&signer(1), 4);
        let new = Announcement::root_of(&signer(1), 5);
        assert!(new.supersedes(&old));
        assert!(!old.supersedes(&new));
        assert!(!new.supersedes(&new));
    }

    #[test]
    fn a_tie_on_sequence_numbers_is_broken_by_the_walk() {
        // One author, one sequence number, two different walks: a node that
        // moved without restamping, or two copies of one that crossed. The
        // rule has to answer anyway and answer the same way everywhere, or
        // two nodes holding both would keep different ones and disagree
        // about where their common neighbour sits.
        let through_two = announcement(1, &[(2, 1), (5, 1)]);
        let through_three = announcement(1, &[(3, 1), (5, 1)]);
        assert_eq!(through_two.seq(), through_three.seq());

        assert!(through_three.supersedes(&through_two));
        assert!(
            !through_two.supersedes(&through_three),
            "and not the reverse"
        );
    }

    #[test]
    fn preference_favours_the_smallest_root_then_the_cheapest_walk_to_it() {
        let low_root_dear = announcement(1, &[(9, 4), (5, 4)]);
        let high_root_cheap = announcement(2, &[(5, 1)]);
        assert_eq!(
            low_root_dear.preference_cmp(&high_root_cheap),
            Ordering::Less,
            "a smaller root outweighs any price"
        );

        let cheap = announcement(1, &[(5, 1)]);
        assert_eq!(cheap.preference_cmp(&low_root_dear), Ordering::Less);
    }

    #[test]
    fn preference_takes_the_long_way_round_when_it_is_cheaper() {
        let direct = announcement(1, &[(5, 10)]);
        let round_about = announcement(1, &[(3, 1), (4, 1), (5, 1)]);
        assert_eq!(
            round_about.preference_cmp(&direct),
            Ordering::Less,
            "three cheap links beat one expensive one"
        );
    }

    #[test]
    fn preference_breaks_a_priced_tie_on_hops() {
        let two_hops = announcement(1, &[(3, 1), (5, 1)]);
        let one_hop = announcement(1, &[(5, 2)]);
        assert_eq!(two_hops.cost_to_root(), one_hop.cost_to_root());
        assert_eq!(one_hop.preference_cmp(&two_hops), Ordering::Less);
    }

    #[test]
    fn preference_breaks_a_dead_heat_on_the_walk_itself() {
        // Same root, same price, same number of hops, and still one of them
        // has to win. What it settles on matters less than that every node
        // settles on it: this is the last tie-break, and without it the tree
        // would have no single fixed point to come to rest at.
        let through_three = announcement(1, &[(3, 1), (5, 1)]);
        let through_four = announcement(1, &[(4, 1), (5, 1)]);
        assert_eq!(through_three.cost_to_root(), through_four.cost_to_root());
        assert_eq!(through_three.path().len(), through_four.path().len());

        assert_eq!(through_three.preference_cmp(&through_four), Ordering::Less);
        assert_eq!(
            through_four.preference_cmp(&through_three),
            Ordering::Greater
        );
    }

    #[test]
    fn preference_does_not_move_when_a_sequence_number_does() {
        // Two candidates always part company at some hop's key, which is
        // compared before anything a restamp could reach. If they did not, a
        // node would change its mind every time somebody above it reissued.
        let left = announcement(1, &[(3, 1), (5, 1)]);
        let right = announcement(1, &[(4, 1), (5, 1)]);
        let before = left.preference_cmp(&right);

        let restamped = left.with_seq(&signer(5), 400).expect("the author");
        assert_eq!(restamped.preference_cmp(&right), before);
    }

    #[test]
    fn distance_counts_hops_when_every_link_costs_the_same() {
        let root = path(1, &[]);
        let child = path(1, &[(2, 1)]);
        let grandchild = path(1, &[(2, 1), (3, 1)]);
        let cousin = path(1, &[(4, 1)]);

        assert_eq!(distance(&root, &root), 0);
        assert_eq!(distance(&root, &child), 1);
        assert_eq!(distance(&root, &grandchild), 2);
        assert_eq!(distance(&grandchild, &cousin), 3);
        assert_eq!(distance(&cousin, &grandchild), 3, "distance is symmetric");
    }

    #[test]
    fn distance_adds_up_the_links_through_the_common_ancestor() {
        let grandchild = path(1, &[(2, 5), (3, 7)]);
        let cousin = path(1, &[(4, 2)]);

        assert_eq!(distance(&grandchild, &grandchild), 0);
        assert_eq!(distance(&path(1, &[(2, 5)]), &grandchild), 7);
        assert_eq!(
            distance(&grandchild, &cousin),
            7 + 5 + 2,
            "up to the root and back down"
        );
    }

    #[test]
    fn two_walks_that_disagree_about_the_root_share_no_prefix() {
        // Nothing is comparable across two trees, and what comes out is only
        // what each walk pays to reach its own root. The number is well
        // defined and means nothing, which is exactly the transient state
        // forwarding survives by demanding strict progress: offered a figure
        // like this one, a node drops the packet rather than trusting it.
        let mine = path(1, &[(2, 3)]);
        let theirs = path(4, &[(5, 7)]);

        assert_eq!(distance(&mine, &theirs), 3 + 7);
    }

    #[test]
    fn a_walk_priced_past_the_ceiling_saturates_rather_than_wrapping() {
        // Out of reach of any caller counting anything real, and it still has
        // to be the right kind of wrong: a route that looks infinitely
        // expensive is merely never chosen, where one that wrapped back round
        // to nothing would look like the best in the network. Nor may the
        // arithmetic be what decides it — a node does not panic.
        let mut mine = path(1, &[(2, 1), (4, 1)]);
        mine[1].cost = u64::MAX;
        mine[2].cost = u64::MAX;
        let mut theirs = path(1, &[(3, 1)]);
        theirs[1].cost = u64::MAX;

        assert_eq!(
            Announcement::unchecked(mine.clone()).cost_to_root(),
            u64::MAX,
            "two links of it are not cheaper than one"
        );
        assert_eq!(
            distance(&mine, &theirs),
            u64::MAX,
            "nor is the walk between two of them"
        );
    }

    #[test]
    fn distance_ignores_how_a_shared_prefix_was_stamped() {
        // Two nodes holding differently stamped copies of the same walk must
        // agree on where it forks, or a packet would appear to make progress
        // it had not made. The stamp that has to be overlooked is one *inside*
        // the shared part: 2 reissued, and only one of these two walks was
        // built after it did.
        let mine = announcement(1, &[(2, 1), (3, 1)]);
        let reissued = announcement(1, &[(2, 1)])
            .with_seq(&signer(2), 300)
            .expect("the author may restamp");
        let theirs = reissued
            .extend(&signer(4), &consent(2, 4, 1), 0)
            .expect("distinct key attaches");

        assert_ne!(
            mine.path()[1],
            theirs.path()[1],
            "the same hop, stamped twice"
        );
        assert_eq!(mine.path()[1].key, theirs.path()[1].key);
        assert_eq!(
            distance(mine.path(), theirs.path()),
            2,
            "they still fork below 2, not at it"
        );
    }
}
