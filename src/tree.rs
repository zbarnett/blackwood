//! The spanning tree: what nodes announce, and the metric derived from it.

use std::cmp::Ordering;
use std::fmt;

use crate::key::PublicKey;

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

/// One step down the tree: a node, and what reaching it cost.
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
}

impl Hop {
    /// The first hop of a path: the root, arrived at from nowhere.
    pub const fn root(key: PublicKey) -> Self {
        Self { key, cost: 0 }
    }

    /// A step onto `key` across a link costing `cost`.
    pub const fn new(key: PublicKey, cost: Cost) -> Self {
        Self {
            key,
            cost: cost.get(),
        }
    }
}

/// A node's claimed position in the spanning tree.
///
/// The path runs from the root down to the announcing node, inclusive, so
/// `path[0]` is the root and the last element is the author. Each hop carries
/// the cost of the link that reaches it, as measured by the node it arrives at
/// — the one that chose to sit there. Carrying the whole path rather than just
/// a parent pointer is what makes routing decisions local: a node can compute
/// its distance to any other node it has heard of without consulting anyone.
///
/// Every constructor guarantees the path is non-empty, free of repeated keys,
/// and priced as [`Hop::cost`] describes, so a value of this type is always
/// well formed.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Announcement {
    seq: u64,
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
}

impl fmt::Display for MalformedAnnouncement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPath => f.write_str("announcement path is empty"),
            Self::RepeatedKey => f.write_str("announcement path repeats a key"),
            Self::CostAtRoot => f.write_str("announcement prices the link into its root"),
            Self::FreeLink => f.write_str("announcement path contains a link costing nothing"),
        }
    }
}

impl std::error::Error for MalformedAnnouncement {}

impl Announcement {
    /// The announcement of a node that considers itself the root of its own tree.
    pub fn root_of(key: PublicKey, seq: u64) -> Self {
        Self {
            seq,
            path: vec![Hop::root(key)],
        }
    }

    /// Builds an announcement from its parts, rejecting malformed paths.
    ///
    /// Every other constructor preserves the invariants by construction; this is
    /// the entry point an eventual wire format would decode through.
    pub fn new(seq: u64, path: Vec<Hop>) -> Result<Self, MalformedAnnouncement> {
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
        Ok(Self { seq, path })
    }

    /// The announcement `child` would make by attaching itself below this one
    /// across a link costing `cost`.
    ///
    /// Returns `None` when `child` already appears in the path. That single
    /// check is what keeps the tree loop-free: a node never adopts a path that
    /// runs through itself, so no cycle can form however stale its view is.
    pub fn extend(&self, child: PublicKey, cost: Cost, seq: u64) -> Option<Self> {
        if self.path.iter().any(|hop| hop.key == child) {
            return None;
        }
        let mut path = self.path.clone();
        path.push(Hop::new(child, cost));
        Some(Self { seq, path })
    }

    /// The same announcement carrying a new sequence number.
    pub fn with_seq(&self, seq: u64) -> Self {
        Self {
            seq,
            path: self.path.clone(),
        }
    }

    /// The sequence number its author last stamped it with.
    pub fn seq(&self) -> u64 {
        self.seq
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

    /// Whether this announcement replaces `other` in the set of known announcements.
    ///
    /// Announcements are only ever authored by the node they describe, so per
    /// author this set is a max register: the join is whichever announcement is
    /// greater. Sequence number decides, with the path as a tie-break purely so
    /// that the rule is total and every node reaches the same answer.
    pub fn supersedes(&self, other: &Self) -> bool {
        (self.seq, &self.path) > (other.seq, &other.path)
    }

    /// Orders candidate parents, most preferred first.
    ///
    /// Smallest root key wins, so the network agrees on one root; then the
    /// cheapest walk to that root, which is the whole point of link cost; then
    /// the fewest hops, since two equally priced walks are not equally cheap to
    /// forward over; then the smallest path, so that ties are broken
    /// identically everywhere and the tree has a single fixed point.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> PublicKey {
        PublicKey::new([n; crate::key::KEY_LEN])
    }

    fn cost(n: u64) -> Cost {
        Cost::new(n).expect("a test cost is never zero")
    }

    /// A path rooted at `root`, each later node reached over a link of the cost
    /// written beside it.
    fn path(root: u8, steps: &[(u8, u64)]) -> Vec<Hop> {
        let mut path = vec![Hop::root(key(root))];
        for &(node, price) in steps {
            path.push(Hop::new(key(node), cost(price)));
        }
        path
    }

    fn announce(root: u8, steps: &[(u8, u64)]) -> Announcement {
        Announcement::new(0, path(root, steps)).expect("the test path is well formed")
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
            Announcement::new(0, vec![]),
            Err(MalformedAnnouncement::EmptyPath)
        );
        assert_eq!(
            Announcement::new(0, path(1, &[(2, 1), (1, 1)])),
            Err(MalformedAnnouncement::RepeatedKey)
        );
        assert_eq!(
            Announcement::new(
                0,
                vec![Hop {
                    key: key(1),
                    cost: 1
                }]
            ),
            Err(MalformedAnnouncement::CostAtRoot)
        );
        assert_eq!(
            Announcement::new(
                0,
                vec![
                    Hop::root(key(1)),
                    Hop {
                        key: key(2),
                        cost: 0
                    }
                ]
            ),
            Err(MalformedAnnouncement::FreeLink)
        );
        assert!(Announcement::new(0, path(1, &[(2, 3)])).is_ok());
    }

    #[test]
    fn extending_records_what_the_link_cost() {
        let root = Announcement::root_of(key(1), 0);
        assert_eq!(root.cost_to_root(), 0, "the root is already there");

        let child = root
            .extend(key(2), cost(4), 0)
            .expect("distinct key attaches");
        assert_eq!(child.path(), path(1, &[(2, 4)]));
        assert_eq!(child.parent(), Some(key(1)));
        assert_eq!(child.author(), key(2));
        assert_eq!(child.root(), key(1));
        assert_eq!(child.cost_to_root(), 4);

        let grandchild = child
            .extend(key(3), cost(5), 0)
            .expect("distinct key attaches");
        assert_eq!(grandchild.cost_to_root(), 9, "costs add up the path");
    }

    #[test]
    fn extending_refuses_to_form_a_loop() {
        let child = announce(1, &[(2, 1)]);
        assert_eq!(child.extend(key(1), Cost::UNIT, 0), None);
        assert_eq!(child.extend(key(2), Cost::UNIT, 0), None);
    }

    #[test]
    fn a_root_has_no_parent() {
        assert_eq!(Announcement::root_of(key(1), 0).parent(), None);
    }

    #[test]
    fn later_sequence_numbers_supersede() {
        let old = Announcement::root_of(key(1), 4);
        let new = Announcement::root_of(key(1), 5);
        assert!(new.supersedes(&old));
        assert!(!old.supersedes(&new));
        assert!(!new.supersedes(&new));
    }

    #[test]
    fn preference_favours_the_smallest_root_then_the_cheapest_walk_to_it() {
        let low_root_dear = announce(1, &[(9, 4), (5, 4)]);
        let high_root_cheap = announce(2, &[(5, 1)]);
        assert_eq!(
            low_root_dear.preference_cmp(&high_root_cheap),
            Ordering::Less,
            "a smaller root outweighs any price"
        );

        let cheap = announce(1, &[(5, 1)]);
        assert_eq!(cheap.preference_cmp(&low_root_dear), Ordering::Less);
    }

    #[test]
    fn preference_takes_the_long_way_round_when_it_is_cheaper() {
        let direct = announce(1, &[(5, 10)]);
        let round_about = announce(1, &[(3, 1), (4, 1), (5, 1)]);
        assert_eq!(
            round_about.preference_cmp(&direct),
            Ordering::Less,
            "three cheap links beat one expensive one"
        );
    }

    #[test]
    fn preference_breaks_a_priced_tie_on_hops() {
        let two_hops = announce(1, &[(3, 1), (5, 1)]);
        let one_hop = announce(1, &[(5, 2)]);
        assert_eq!(two_hops.cost_to_root(), one_hop.cost_to_root());
        assert_eq!(one_hop.preference_cmp(&two_hops), Ordering::Less);
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
}
