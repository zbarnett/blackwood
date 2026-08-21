//! Node addresses.

use std::fmt;

/// The length of a key in bytes, matching ed25519.
pub const KEY_LEN: usize = 32;

/// The address of a node.
///
/// Ironwood uses an ed25519 public key. This core performs no cryptography, so
/// a key is an opaque identifier whose only relevant property is its total
/// order: the node holding the smallest key in a connected component becomes
/// the root of the spanning tree.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicKey([u8; KEY_LEN]);

impl PublicKey {
    /// Wraps raw key bytes.
    pub const fn new(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// The raw key bytes.
    pub const fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}
