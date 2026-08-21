//! A small non-cryptographic hash, used where only spread matters.
//!
//! Nothing here is a substitute for the cryptography a [`Signer`] supplies, and
//! nothing here is offered to a caller as one. Bloom filters need bits that
//! scatter, and the stand-in signer the tests run on needs bytes that change
//! when its input does; neither needs to be hard to reverse.
//!
//! [`Signer`]: crate::signature::Signer

/// FNV-1a over `bytes`, salted with `round` so one input can yield several
/// independent values.
pub fn fnv1a(round: u8, bytes: impl Iterator<Item = u8>) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;

    let mut hash = OFFSET;
    for byte in std::iter::once(round).chain(bytes) {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

/// The mix that finishes a murmur hash, for when only some of the bits of a
/// hash are going to be read.
///
/// FNV moves its low bits least, so anything taking a small index from the
/// bottom of the word wants this first.
pub fn mix(mut hash: u64) -> u64 {
    hash ^= hash >> 33;
    hash = hash.wrapping_mul(0xff51_afd7_ed55_8ccd);
    hash ^ (hash >> 33)
}
