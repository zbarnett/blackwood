//! Signing, without saying with what.

use std::fmt;

use crate::key::PublicKey;

/// The length of a signature in bytes, matching ed25519.
pub const SIGNATURE_LEN: usize = 64;

/// A signature over some bytes by the holder of a [`PublicKey`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Signature([u8; SIGNATURE_LEN]);

impl Signature {
    /// Wraps raw signature bytes.
    pub const fn new(bytes: [u8; SIGNATURE_LEN]) -> Self {
        Self(bytes)
    }

    /// The raw signature bytes.
    pub const fn as_bytes(&self) -> &[u8; SIGNATURE_LEN] {
        &self.0
    }
}

impl fmt::Debug for Signature {
    /// Abbreviated, since a signature is never read and printing sixty-four
    /// bytes of it only buries whatever is next to it.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sig:")?;
        for byte in &self.0[..4] {
            write!(f, "{byte:02x}")?;
        }
        f.write_str("…")
    }
}

/// The cryptography a node speaks with.
///
/// The core performs none of its own. It says what has to be signed and what
/// has to be checked, and the algorithm arrives from outside: that is what lets
/// this crate keep no dependencies while still refusing to take a stranger's
/// word for anything. There is no default and no way to opt out — a [`Node`]
/// cannot be built without one, so every network is running some real scheme
/// or one its own author wrote knowing exactly what it was worth.
///
/// One type serves both halves. Signing needs a secret and so takes `&self`;
/// checking somebody else's signature needs nothing of one's own, only the
/// algorithm, so [`verify`](Signer::verify) takes no receiver. Every node in a
/// network has to be using the same one.
///
/// The `blackwood-ed25519` crate is an implementation over real keys. See the
/// crate documentation for what a stand-in costs to write, which is what the
/// tests here and in `tests/simulation.rs` do.
///
/// [`Node`]: crate::node::Node
pub trait Signer {
    /// The key this signer speaks for.
    fn public_key(&self) -> PublicKey;

    /// Signs `message` as that key.
    fn sign(&self, message: &[u8]) -> Signature;

    /// Whether `signature` is `key`'s signature over `message`.
    fn verify(key: PublicKey, message: &[u8], signature: &Signature) -> bool;
}
