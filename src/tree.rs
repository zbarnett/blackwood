//! The spanning tree: what nodes announce, and the metric derived from it.

use std::cmp::Ordering;
use std::fmt;

use crate::key::PublicKey;
use crate::signature::{Signature, Signer};

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

impl Default for Cost {
    fn default() -> Self {
        Self::UNIT
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
    /// What the link from the previous hop to this one costs to cross.
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
    /// That node's signature over this hop and every hop above it.
    ///
    /// The signature covers the hops above exactly as they stand, their own
    /// signatures included, so a hop is bound to the particular walk it was
    /// made for and cannot be lifted out of one announcement into another.
    pub signature: Signature,
}

/// A node's claimed position in the spanning tree.
///
/// The path runs from the root down to the announcing node, inclusive, so
/// `path[0]` is the root and the last element is the author. Each hop carries
/// the cost of the link that reaches it, as measured by the node it arrives at
/// — the one that chose to sit there — and that node's signature. Carrying the
/// whole path rather than just a parent pointer is what makes routing decisions
/// local: a node can compute its distance to any other node it has heard of
/// without consulting anyone.
///
/// Every constructor guarantees the path is non-empty, free of repeated keys,
/// priced as [`Hop::cost`] describes, and signed at every hop by the node that
/// hop names. A value of this type is therefore always well formed, but it is
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
        }
    }
}

impl std::error::Error for MalformedAnnouncement {}

impl Announcement {
    /// The announcement of a node that considers itself the root of its own tree.
    pub fn root_of<S: Signer>(signer: &S, seq: u64) -> Self {
        let key = signer.public_key();
        let signature = signer.sign(&signed_bytes(&[], key, 0, seq));
        Self {
            path: vec![Hop {
                key,
                cost: 0,
                seq,
                signature,
            }],
        }
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
        if below.iter().any(|hop| hop.cost == 0) {
            return Err(MalformedAnnouncement::FreeLink);
        }
        for (index, hop) in path.iter().enumerate() {
            if path[..index].iter().any(|earlier| earlier.key == hop.key) {
                return Err(MalformedAnnouncement::RepeatedKey);
            }
        }
        let announcement = Self { path };
        if !announcement.verify::<S>() {
            return Err(MalformedAnnouncement::BadSignature);
        }
        Ok(announcement)
    }

    /// The announcement `signer`'s node would make by attaching itself below
    /// this one across a link costing `cost`.
    ///
    /// Returns `None` when the signer's key already appears in the path. That
    /// single check is what keeps the tree loop-free: a node never adopts a
    /// path that runs through itself, so no cycle can form however stale its
    /// view is.
    pub fn extend<S: Signer>(&self, signer: &S, cost: Cost, seq: u64) -> Option<Self> {
        let child = signer.public_key();
        if self.path.iter().any(|hop| hop.key == child) {
            return None;
        }
        let signature = signer.sign(&signed_bytes(&self.path, child, cost.get(), seq));
        let mut path = self.path.clone();
        path.push(Hop {
            key: child,
            cost: cost.get(),
            seq,
            signature,
        });
        Some(Self { path })
    }

    /// The same walk, stamped with a new sequence number and signed afresh.
    ///
    /// Only the author's own hop is restamped, because only the author can
    /// sign it; the walk down to it stands exactly as the nodes above it
    /// signed. Returns `None` for a signer that is not the author, which is
    /// the only thing it could mean.
    pub fn with_seq<S: Signer>(&self, signer: &S, seq: u64) -> Option<Self> {
        let author = signer.public_key();
        if author != self.author() {
            return None;
        }
        let mut path = self.path.clone();
        // The path is never empty, so there is always a last hop.
        let last = path.len() - 1;
        let cost = path[last].cost;
        let signature = signer.sign(&signed_bytes(&path[..last], author, cost, seq));
        path[last] = Hop {
            key: author,
            cost,
            seq,
            signature,
        };
        Some(Self { path })
    }

    /// Whether every hop was signed by the node it names.
    ///
    /// What this settles is authorship: nobody can put a node somewhere it has
    /// not put itself, so an answer to a search cannot invent a position for
    /// its subject and a node cannot invent the walk above it. What it does not
    /// settle is whether any of it is still true — a signature is as valid on a
    /// long-dead announcement as on a fresh one, which is what sequence numbers
    /// and expiry are for.
    pub fn verify<S: Signer>(&self) -> bool {
        self.path.iter().enumerate().all(|(index, hop)| {
            let bytes = signed_bytes(&self.path[..index], hop.key, hop.cost, hop.seq);
            S::verify(hop.key, &bytes, &hop.signature)
        })
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
    pub fn same_position(&self, other: &Self) -> bool {
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
    pub fn supersedes(&self, other: &Self) -> bool {
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
    pub fn preference_cmp(&self, other: &Self) -> Ordering {
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
pub fn distance(a: &[Hop], b: &[Hop]) -> u64 {
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

/// The bytes a hop is signed over: every hop above it exactly as it stands,
/// signatures and all, followed by its own key, cost and sequence number.
///
/// Including the hops above by their signatures is what chains them. A hop
/// commits to the particular walk it was added to, so no part of one
/// announcement can be spliced into another.
fn signed_bytes(above: &[Hop], key: PublicKey, cost: u64, seq: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    for hop in above {
        bytes.extend_from_slice(hop.key.as_bytes());
        bytes.extend_from_slice(&hop.cost.to_be_bytes());
        bytes.extend_from_slice(&hop.seq.to_be_bytes());
        bytes.extend_from_slice(hop.signature.as_bytes());
    }
    bytes.extend_from_slice(key.as_bytes());
    bytes.extend_from_slice(&cost.to_be_bytes());
    bytes.extend_from_slice(&seq.to_be_bytes());
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::Insecure;

    fn key(n: u8) -> PublicKey {
        PublicKey::new([n; crate::key::KEY_LEN])
    }

    fn signer(n: u8) -> Insecure {
        Insecure::for_key(key(n))
    }

    fn cost(n: u64) -> Cost {
        Cost::new(n).expect("a test cost is never zero")
    }

    /// An announcement for the node at the end of `root` + `steps`, built the
    /// way a real one is: each node attaching below the last over a link of the
    /// cost written beside it, and signing its own hop as it goes.
    fn announcement(root: u8, steps: &[(u8, u64)]) -> Announcement {
        let mut announcement = Announcement::root_of(&signer(root), 0);
        for &(node, price) in steps {
            announcement = announcement
                .extend(&signer(node), cost(price), 0)
                .expect("the test path holds distinct keys");
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
            Announcement::new::<Insecure>(vec![]),
            Err(MalformedAnnouncement::EmptyPath)
        );

        let mut repeated = path(1, &[(2, 1)]);
        repeated.push(Hop {
            key: key(1),
            ..repeated[1]
        });
        assert_eq!(
            Announcement::new::<Insecure>(repeated),
            Err(MalformedAnnouncement::RepeatedKey)
        );

        let mut priced_root = path(1, &[]);
        priced_root[0].cost = 1;
        assert_eq!(
            Announcement::new::<Insecure>(priced_root),
            Err(MalformedAnnouncement::CostAtRoot)
        );

        let mut free = path(1, &[(2, 1)]);
        free[1].cost = 0;
        assert_eq!(
            Announcement::new::<Insecure>(free),
            Err(MalformedAnnouncement::FreeLink)
        );

        assert!(Announcement::new::<Insecure>(path(1, &[(2, 3)])).is_ok());
    }

    #[test]
    fn rejects_a_walk_that_was_altered_after_it_was_signed() {
        // Structurally perfect, and a lie: the price of the link into 2 rubbed
        // out and a cheaper one written in, which would put 2 nearer the root
        // than it has any right to be.
        let mut cheaper = path(1, &[(2, 5)]);
        cheaper[1].cost = 1;
        assert_eq!(
            Announcement::new::<Insecure>(cheaper),
            Err(MalformedAnnouncement::BadSignature)
        );

        let mut renamed = path(1, &[(2, 1)]);
        renamed[1].key = key(9);
        assert_eq!(
            Announcement::new::<Insecure>(renamed),
            Err(MalformedAnnouncement::BadSignature)
        );

        let mut restamped = path(1, &[(2, 1)]);
        restamped[1].seq = 500;
        assert_eq!(
            Announcement::new::<Insecure>(restamped),
            Err(MalformedAnnouncement::BadSignature)
        );
    }

    #[test]
    fn every_hop_is_signed_by_the_node_it_names() {
        let announcement = announcement(1, &[(2, 1), (3, 1)]);
        assert!(announcement.verify::<Insecure>());

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

        assert!(!Announcement::unchecked(spliced).verify::<Insecure>());
    }

    #[test]
    fn extending_records_what_the_link_cost() {
        let root = Announcement::root_of(&signer(1), 0);
        assert_eq!(root.cost_to_root(), 0, "the root is already there");

        let child = root
            .extend(&signer(2), cost(4), 0)
            .expect("distinct key attaches");
        assert_eq!(walk(child.path()), [(key(1), 0), (key(2), 4)]);
        assert_eq!(child.parent(), Some(key(1)));
        assert_eq!(child.author(), key(2));
        assert_eq!(child.root(), key(1));
        assert_eq!(child.cost_to_root(), 4);
        assert!(child.verify::<Insecure>());

        let grandchild = child
            .extend(&signer(3), cost(5), 0)
            .expect("distinct key attaches");
        assert_eq!(grandchild.cost_to_root(), 9, "costs add up the path");
        assert!(grandchild.verify::<Insecure>());
    }

    #[test]
    fn extending_refuses_to_form_a_loop() {
        let child = announcement(1, &[(2, 1)]);
        assert_eq!(child.extend(&signer(1), Cost::UNIT, 0), None);
        assert_eq!(child.extend(&signer(2), Cost::UNIT, 0), None);
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
            after.verify::<Insecure>(),
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
    fn later_sequence_numbers_supersede() {
        let old = Announcement::root_of(&signer(1), 4);
        let new = Announcement::root_of(&signer(1), 5);
        assert!(new.supersedes(&old));
        assert!(!old.supersedes(&new));
        assert!(!new.supersedes(&new));
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
    fn distance_ignores_how_a_shared_prefix_was_stamped() {
        // Two nodes holding differently stamped copies of the same walk must
        // agree on where it forks, or a packet would appear to make progress
        // it had not made.
        let mine = announcement(1, &[(2, 1), (3, 1)]);
        let theirs = announcement(1, &[(2, 1), (4, 1)]);
        let restamped = theirs.with_seq(&signer(4), 300).expect("the author");

        assert_eq!(
            distance(mine.path(), theirs.path()),
            distance(mine.path(), restamped.path())
        );
    }
}
