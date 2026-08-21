//! A [`Signer`] with the cryptography left out, for this crate's own tests.
//!
//! The core cannot tell one signer from another — it hands bytes to `sign` and
//! asks `verify` about them, and that is the whole of the interface — so the
//! tests here can drive it with keys that read as `01`, `02`, `03` and still be
//! exercising exactly the code a real network runs. What ed25519 does with the
//! same trait is exercised in the `blackwood-ed25519` crate, against a network
//! built the same way.
//!
//! This module is `#[cfg(test)]`, so it exists only while the crate is compiled
//! for its own tests. There is no build of this library in which a caller could
//! reach for it instead of bringing cryptography of their own.

use crate::hash::fnv1a;
use crate::key::PublicKey;
use crate::signature::{SIGNATURE_LEN, Signature, Signer};

/// A signer with no secret in it.
///
/// A signature here is a hash of the key and the message, so anyone can produce
/// one for anyone: it notices a walk that was altered after it was signed,
/// which is what the tests ask of it, and stops nothing that was altered on
/// purpose.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(crate) struct StandIn(PublicKey);

impl StandIn {
    /// A signer speaking for `key`, with nothing to stop anybody else doing
    /// the same.
    pub(crate) const fn for_key(key: PublicKey) -> Self {
        Self(key)
    }
}

impl Signer for StandIn {
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
    Signature::new(bytes)
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
        let signer = StandIn::for_key(key(1));
        let signature = signer.sign(b"where i sit");

        assert!(StandIn::verify(key(1), b"where i sit", &signature));
        assert!(!StandIn::verify(key(1), b"where i sat", &signature));
        assert!(!StandIn::verify(key(2), b"where i sit", &signature));
    }

    #[test]
    fn a_signature_changes_when_anything_about_it_does() {
        let signer = StandIn::for_key(key(1));
        let signature = signer.sign(b"a");

        assert_ne!(signature, signer.sign(b"b"), "a different message");
        assert_ne!(
            signature,
            StandIn::for_key(key(2)).sign(b"a"),
            "a different signer"
        );
        assert_eq!(signature, signer.sign(b"a"), "and the same one twice");
    }

    #[test]
    fn a_signature_fills_its_whole_length() {
        // Eight rounds of hashing, one per eight bytes. A bug that left the
        // tail zeroed would still verify, so nothing else would catch it.
        let signature = StandIn::for_key(key(1)).sign(b"anything");
        assert!(signature.as_bytes()[56..].iter().any(|&byte| byte != 0));
        assert_ne!(signature.as_bytes()[..8], signature.as_bytes()[8..16]);
    }

    #[test]
    fn anyone_can_forge_a_stand_in_signature() {
        // Stated as a test because it is the whole point of the type, and the
        // reason it does not leave this crate: there is no secret here, and a
        // caller who wants one has to bring it.
        let mine = StandIn::for_key(key(1)).sign(b"i am the root");
        let forged = StandIn::for_key(key(1));
        assert_eq!(forged.sign(b"i am the root"), mine);
    }
}
