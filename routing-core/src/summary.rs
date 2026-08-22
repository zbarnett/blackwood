//! What lies beyond a link, summarised.

use std::fmt;

use crate::key::PublicKey;

/// The set of keys reachable through one link, as a Bloom filter.
///
/// A node keeps one of these per tree neighbour and sends one back, so what it
/// holds is a fixed number of bytes per link rather than an entry per node in
/// the network. That is the whole trade: a summary cannot be read back, only
/// asked about, and it answers "no" exactly and "yes" approximately.
///
/// A key that was inserted always tests present, so a search guided by
/// summaries never overlooks the branch its target is really on. A key that was
/// not may test present anyway, which costs a search a wasted detour and
/// nothing else. With [`Summary::BITS`] bits and [`Summary::HASHES`] of them
/// set per key, that happens for roughly one key in four hundred at sixteen
/// nodes to a summary, one in forty at thirty-two, and one in two at a hundred
/// and twenty-eight. Ironwood uses a filter thirty-two times this size;
/// [`BITS`](Summary::BITS) is the only thing standing between this and a
/// network of that size.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Summary {
    words: [u64; Summary::BITS / 64],
}

impl Summary {
    /// How many bits a summary holds.
    pub const BITS: usize = 256;

    /// How many of them each key sets.
    pub const HASHES: usize = 4;

    /// The summary of nothing at all, which claims no key.
    pub const fn new() -> Self {
        Self {
            words: [0; Self::BITS / 64],
        }
    }

    /// Records that `key` is reachable.
    pub fn insert(&mut self, key: PublicKey) {
        for round in 0..Self::HASHES {
            let bit = position(key, round);
            self.words[bit / 64] |= 1 << (bit % 64);
        }
    }

    /// Whether `key` may be reachable.
    ///
    /// False for a key that was never inserted unless every one of its bits was
    /// set by other keys; never false for one that was.
    pub fn contains(&self, key: PublicKey) -> bool {
        (0..Self::HASHES).all(|round| {
            let bit = position(key, round);
            self.words[bit / 64] & (1 << (bit % 64)) != 0
        })
    }

    /// Folds `other` in, so this claims everything either of them did.
    ///
    /// This is how a summary is built from the ones a node's other links gave
    /// it: the union is exact, which is what lets a node describe a whole
    /// subtree without ever holding it.
    pub fn union(&mut self, other: &Self) {
        for (word, more) in self.words.iter_mut().zip(&other.words) {
            *word |= more;
        }
    }

    /// How many bits are set, out of [`BITS`](Self::BITS).
    ///
    /// A summary that is filling up is one whose answers are getting vaguer,
    /// which is the only warning a Bloom filter ever gives.
    pub fn filled(&self) -> u32 {
        self.words.iter().map(|word| word.count_ones()).sum()
    }
}

impl Default for Summary {
    /// The same empty summary [`new`](Summary::new) builds, so that the two
    /// cannot drift apart. It is here because a type with a `new` taking no
    /// arguments is expected to have it, not because anything needs it.
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Summary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Summary({}/{} bits)", self.filled(), Self::BITS)
    }
}

/// Which bit `key` sets on the given round.
///
/// The mix after the hash is not decoration: the bit index is taken from the
/// bottom of the word, and those are the bits FNV moves least, so without it
/// keys that share a suffix would pile onto the same handful of positions.
fn position(key: PublicKey, round: usize) -> usize {
    let hash = mix(fnv1a(round as u8, key.as_bytes()));
    // `BITS` is a power of two, so this is a remainder and cannot exceed it.
    (hash as usize) & (Summary::BITS - 1)
}

/// FNV-1a over `bytes`, salted with `round` so one key can yield several
/// independent positions.
///
/// Not a substitute for the cryptography a [`Signer`] supplies, and not offered
/// to a caller as one: a Bloom filter needs bits that scatter, which is the
/// whole of what this has to do.
///
/// [`Signer`]: crate::signature::Signer
fn fnv1a(round: u8, bytes: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;

    let mut hash = OFFSET;
    for byte in std::iter::once(round).chain(bytes.iter().copied()) {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

/// The mix that finishes a murmur hash, for when only some of the bits of a
/// hash are going to be read.
///
/// FNV moves its low bits least, so taking a small index from the bottom of the
/// word wants this first.
fn mix(mut hash: u64) -> u64 {
    hash ^= hash >> 33;
    hash = hash.wrapping_mul(0xff51_afd7_ed55_8ccd);
    hash ^ (hash >> 33)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::KEY_LEN;

    fn key(n: u8) -> PublicKey {
        PublicKey::new([n; KEY_LEN])
    }

    #[test]
    fn an_empty_summary_claims_nothing() {
        let summary = Summary::new();
        assert_eq!(summary.filled(), 0);
        assert!(!summary.contains(key(1)));
    }

    #[test]
    fn what_was_inserted_is_never_missed() {
        let mut summary = Summary::new();
        for n in 0..32 {
            summary.insert(key(n));
        }
        for n in 0..32 {
            assert!(summary.contains(key(n)), "{n} went missing");
        }
    }

    #[test]
    fn keys_land_on_different_bits() {
        let mut summary = Summary::new();
        for n in 0..32 {
            summary.insert(key(n));
        }
        // Thirty-two keys setting four bits each land on 128 positions out of
        // 256. Some collide; a hash that spread them badly would show up here
        // as a summary far emptier than this bound allows.
        assert!(
            summary.filled() > 80,
            "only {} bits set, so keys are colliding",
            summary.filled()
        );
        assert!(summary.filled() <= 128);
    }

    #[test]
    fn a_union_claims_what_either_side_did() {
        let mut left = Summary::new();
        left.insert(key(1));
        let mut right = Summary::new();
        right.insert(key(2));

        left.union(&right);
        assert!(left.contains(key(1)));
        assert!(left.contains(key(2)));
        assert!(right.contains(key(2)));
        assert!(!right.contains(key(1)), "the union went one way only");
    }

    #[test]
    fn a_summary_holding_few_keys_says_no_to_the_rest() {
        let mut summary = Summary::new();
        for n in 0..8 {
            summary.insert(key(n));
        }
        // Eight keys leave the filter sparse enough that a false positive here
        // would mean the hash, not the mathematics, had gone wrong.
        let wrong = (8..=255).filter(|&n| summary.contains(key(n))).count();
        assert_eq!(wrong, 0, "{wrong} keys tested present by mistake");
    }

    #[test]
    fn a_full_summary_says_yes_to_everything() {
        // Nothing here breaks when a summary saturates; it just stops pruning,
        // which is the graceful end of the trade rather than a failure.
        let mut summary = Summary::new();
        for n in 0..=255 {
            summary.insert(key(n));
        }
        // 256 keys setting four bits apiece leave about e^-4 of the filter
        // clear, so it saturates without ever quite filling.
        assert!(summary.filled() > 240, "only {} bits set", summary.filled());
        assert!(summary.contains(key(7)));
        let wrong = (0..=255).filter(|&n| !summary.contains(key(n))).count();
        assert_eq!(wrong, 0, "a saturated summary still misses nothing");
    }
}
