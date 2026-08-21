//! Signing, without saying with what.

use std::fmt;

use crate::hash::fnv1a;
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
/// word for anything.
///
/// One type serves both halves. Signing needs a secret and so takes `&self`;
/// checking somebody else's signature needs nothing of one's own, only the
/// algorithm, so [`verify`](Signer::verify) takes no receiver. Every node in a
/// network has to be using the same one.
///
/// [`Insecure`] is the shape of an implementation with the cryptography left
/// out. The `blackwood-ed25519` crate is one with it put back in.
pub trait Signer {
    /// The key this signer speaks for.
    fn public_key(&self) -> PublicKey;

    /// Signs `message` as that key.
    fn sign(&self, message: &[u8]) -> Signature;

    /// Whether `signature` is `key`'s signature over `message`.
    fn verify(key: PublicKey, message: &[u8], signature: &Signature) -> bool;
}

/// A [`Signer`] with the cryptography taken out.
///
/// A signature here is a hash of the key and the message, so anyone can produce
/// one for anyone: it notices a path that was altered in passing and stops
/// nothing that was altered on purpose. What it buys is that this crate stands
/// up and can be tested with no dependency at all, and that the shape of what a
/// caller has to supply is written down somewhere runnable.
///
/// It is not a weak cipher. There is no secret anywhere in it. Carrying real
/// traffic with it means trusting every node not to lie.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Insecure(PublicKey);

impl Insecure {
    /// A signer speaking for `key`, with nothing to stop anybody else doing
    /// the same.
    pub const fn for_key(key: PublicKey) -> Self {
        Self(key)
    }
}

impl Signer for Insecure {
    fn public_key(&self) -> PublicKey {
        self.0
    }

    fn sign(&self, message: &[u8]) -> Signature {
        stamp(self.0, message)
    }

    fn verify(key: PublicKey, message: &[u8], signature: &Signature) -> bool {
        &stamp(key, message) == signature
    }
}

/// A hash of key and message, run enough times to fill a signature.
fn stamp(key: PublicKey, message: &[u8]) -> Signature {
    let mut bytes = [0; SIGNATURE_LEN];
    for (round, chunk) in bytes.chunks_mut(8).enumerate() {
        let hash = fnv1a(round as u8, key.as_bytes().iter().chain(message).copied());
        // Every chunk of a 64-byte array split eight ways is eight bytes long.
        chunk.copy_from_slice(&hash.to_be_bytes());
    }
    Signature(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::KEY_LEN;

    fn key(n: u8) -> PublicKey {
        PublicKey::new([n; KEY_LEN])
    }

    #[test]
    fn a_signature_checks_out_against_what_was_signed() {
        let signer = Insecure::for_key(key(1));
        let signature = signer.sign(b"where i sit");

        assert!(Insecure::verify(key(1), b"where i sit", &signature));
        assert!(!Insecure::verify(key(1), b"where i sat", &signature));
        assert!(!Insecure::verify(key(2), b"where i sit", &signature));
    }

    #[test]
    fn a_signature_changes_when_anything_about_it_does() {
        let signer = Insecure::for_key(key(1));
        let signature = signer.sign(b"a");

        assert_ne!(signature, signer.sign(b"b"), "a different message");
        assert_ne!(
            signature,
            Insecure::for_key(key(2)).sign(b"a"),
            "a different signer"
        );
        assert_eq!(signature, signer.sign(b"a"), "and the same one twice");
    }

    #[test]
    fn a_signature_fills_its_whole_length() {
        // Eight rounds of hashing, one per eight bytes. A bug that left the
        // tail zeroed would still verify, so nothing else would catch it.
        let signature = Insecure::for_key(key(1)).sign(b"anything");
        assert!(signature.as_bytes()[56..].iter().any(|&byte| byte != 0));
        assert_ne!(signature.as_bytes()[..8], signature.as_bytes()[8..16]);
    }

    #[test]
    fn anyone_can_forge_an_insecure_signature() {
        // Stated as a test because it is the whole point of the type: there is
        // no secret here, and a caller who wants one has to bring it.
        let mine = Insecure::for_key(key(1)).sign(b"i am the root");
        let forged = Insecure::for_key(key(1));
        assert_eq!(forged.sign(b"i am the root"), mine);
    }
}
