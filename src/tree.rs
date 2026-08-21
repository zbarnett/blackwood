//! The spanning tree: what nodes announce, and the metric derived from it.

use std::cmp::Ordering;
use std::fmt;

use crate::key::PublicKey;

/// A node's claimed position in the spanning tree.
///
/// The path runs from the root down to the announcing node, inclusive, so
/// `path[0]` is the root and the last element is the author. Carrying the whole
/// path rather than just a parent pointer is what makes routing decisions local:
/// a node can compute its distance to any other node it has heard of without
/// consulting anyone.
///
/// Every constructor guarantees the path is non-empty and free of repeated
/// keys, so a value of this type is always well formed.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Announcement {
    seq: u64,
    path: Vec<PublicKey>,
}

/// Why a path could not be made into an [`Announcement`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MalformedAnnouncement {
    /// The path had no keys, so it named no author.
    EmptyPath,
    /// A key appeared twice, which would describe a loop rather than a path.
    RepeatedKey,
}

impl fmt::Display for MalformedAnnouncement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPath => f.write_str("announcement path is empty"),
            Self::RepeatedKey => f.write_str("announcement path repeats a key"),
        }
    }
}

impl std::error::Error for MalformedAnnouncement {}

impl Announcement {
    /// The announcement of a node that considers itself the root of its own tree.
    pub fn root_of(key: PublicKey, seq: u64) -> Self {
        Self {
            seq,
            path: vec![key],
        }
    }

    /// Builds an announcement from its parts, rejecting malformed paths.
    ///
    /// Every other constructor preserves the invariants by construction; this is
    /// the entry point an eventual wire format would decode through.
    pub fn new(seq: u64, path: Vec<PublicKey>) -> Result<Self, MalformedAnnouncement> {
        if path.is_empty() {
            return Err(MalformedAnnouncement::EmptyPath);
        }
        for (index, key) in path.iter().enumerate() {
            if path[..index].contains(key) {
                return Err(MalformedAnnouncement::RepeatedKey);
            }
        }
        Ok(Self { seq, path })
    }

    /// The announcement `child` would make by attaching itself below this one.
    ///
    /// Returns `None` when `child` already appears in the path. That single
    /// check is what keeps the tree loop-free: a node never adopts a path that
    /// runs through itself, so no cycle can form however stale its view is.
    pub fn extend(&self, child: PublicKey, seq: u64) -> Option<Self> {
        if self.path.contains(&child) {
            return None;
        }
        let mut path = self.path.clone();
        path.push(child);
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
    pub fn path(&self) -> &[PublicKey] {
        &self.path
    }

    /// The root of the tree this announcement belongs to.
    pub fn root(&self) -> PublicKey {
        // The path is never empty, so this cannot panic.
        self.path[0]
    }

    /// The node that made this announcement.
    pub fn author(&self) -> PublicKey {
        // The path is never empty, so this cannot panic.
        self.path[self.path.len() - 1]
    }

    /// The author's parent, or `None` if the author is the root.
    pub fn parent(&self) -> Option<PublicKey> {
        self.path.len().checked_sub(2).map(|index| self.path[index])
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
    /// shortest path to that root; then the smallest path, so that ties are
    /// broken identically everywhere and the tree has a single fixed point.
    pub fn preference_cmp(&self, other: &Self) -> Ordering {
        self.root()
            .cmp(&other.root())
            .then_with(|| self.path.len().cmp(&other.path.len()))
            .then_with(|| self.path.cmp(&other.path))
    }
}

/// The number of hops between two nodes along the tree.
///
/// Both paths descend from the root, so they share a prefix ending at the two
/// nodes' lowest common ancestor; the distance is the climb up to it plus the
/// descent back down. When the paths disagree about the root the result is
/// still well defined, just not useful, which is the transient state routing
/// tolerates by refusing to forward without strict progress.
pub fn distance(a: &[PublicKey], b: &[PublicKey]) -> usize {
    let shared = a.iter().zip(b).take_while(|(x, y)| x == y).count();
    // `shared` is at most the length of either path, so this cannot underflow.
    a.len() + b.len() - 2 * shared
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> PublicKey {
        PublicKey::new([n; crate::key::KEY_LEN])
    }

    #[test]
    fn rejects_malformed_paths() {
        assert_eq!(
            Announcement::new(0, vec![]),
            Err(MalformedAnnouncement::EmptyPath)
        );
        assert_eq!(
            Announcement::new(0, vec![key(1), key(2), key(1)]),
            Err(MalformedAnnouncement::RepeatedKey)
        );
        assert!(Announcement::new(0, vec![key(1), key(2)]).is_ok());
    }

    #[test]
    fn extending_refuses_to_form_a_loop() {
        let root = Announcement::root_of(key(1), 0);
        let child = root.extend(key(2), 0).expect("distinct key attaches");
        assert_eq!(child.path(), [key(1), key(2)]);
        assert_eq!(child.parent(), Some(key(1)));
        assert_eq!(child.author(), key(2));
        assert_eq!(child.root(), key(1));

        assert_eq!(child.extend(key(1), 0), None);
        assert_eq!(child.extend(key(2), 0), None);
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
    fn preference_favours_the_smallest_root_then_the_shortest_path() {
        let low_root_far = Announcement::new(0, vec![key(1), key(9), key(5)]).expect("valid");
        let high_root_near = Announcement::new(0, vec![key(2), key(5)]).expect("valid");
        assert_eq!(
            low_root_far.preference_cmp(&high_root_near),
            Ordering::Less,
            "a smaller root outweighs a shorter path"
        );

        let short = Announcement::new(0, vec![key(1), key(5)]).expect("valid");
        assert_eq!(short.preference_cmp(&low_root_far), Ordering::Less);
    }

    #[test]
    fn distance_counts_hops_through_the_common_ancestor() {
        let root = [key(1)];
        let child = [key(1), key(2)];
        let grandchild = [key(1), key(2), key(3)];
        let cousin = [key(1), key(4)];

        assert_eq!(distance(&root, &root), 0);
        assert_eq!(distance(&root, &child), 1);
        assert_eq!(distance(&root, &grandchild), 2);
        assert_eq!(distance(&grandchild, &cousin), 3);
        assert_eq!(distance(&cousin, &grandchild), 3, "distance is symmetric");
    }
}
