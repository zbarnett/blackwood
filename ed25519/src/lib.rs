//! ed25519 for [`routing_core`], kept outside it.
//!
//! The core says what has to be signed and what has to be checked, and takes
//! the algorithm as a type parameter. This crate is one such algorithm. The
//! arrangement is what lets the core carry no dependencies while still
//! refusing to take a stranger's word about where anybody sits: the third-party
//! code lives here, on this side of the boundary, and the core never sees it.
//!
//! ```
//! use routing_core::{Cost, Node, Signer};
//! use blackwood_ed25519::Ed25519;
//!
//! let alice = Ed25519::from_seed([1; 32]);
//! let bob = Ed25519::from_seed([2; 32]);
//! let (alice_key, bob_key) = (alice.public_key(), bob.public_key());
//!
//! let mut node = Node::new(0, alice);
//! node.add_peer(0, bob_key, Cost::UNIT);
//! assert_eq!(node.key(), alice_key);
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::fmt;

use ed25519_dalek::{
    Signature as Ed25519Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey,
};
use routing_core::{PublicKey, Signature, Signer};

/// The number of bytes in the seed an identity is built from.
pub const SEED_LEN: usize = 32;

/// An ed25519 identity: a key to sign as, and the algorithm to check others.
///
/// The public half is derived from the secret, so a node cannot choose the
/// address it answers to — which is what makes a public key worth using as one.
#[derive(Clone)]
pub struct Ed25519 {
    signing: SigningKey,
    /// The public half, worked out once. Routing asks for it constantly.
    public: PublicKey,
}

impl Ed25519 {
    /// The identity belonging to a secret seed.
    ///
    /// No randomness is drawn here. Where the seed comes from is the caller's
    /// problem, which is the only place that decision can sensibly be made:
    /// a real node wants 32 bytes from the operating system, and a test or a
    /// simulation wants 32 bytes it can write down and repeat.
    pub fn from_seed(seed: [u8; SEED_LEN]) -> Self {
        Self::from_signing_key(SigningKey::from_bytes(&seed))
    }

    /// The identity belonging to a key that was made elsewhere.
    pub fn from_signing_key(signing: SigningKey) -> Self {
        let public = PublicKey::new(signing.verifying_key().to_bytes());
        Self { signing, public }
    }

    /// The key it signs as, without needing [`Signer`] in scope.
    pub fn key(&self) -> PublicKey {
        self.public
    }
}

impl fmt::Debug for Ed25519 {
    /// Prints the public half only. The secret is the one thing in this
    /// repository that must never turn up in a log line by accident.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ed25519({:?})", self.public)
    }
}

impl Signer for Ed25519 {
    fn public_key(&self) -> PublicKey {
        self.public
    }

    fn sign(&self, message: &[u8]) -> Signature {
        Signature::new(self.signing.sign(message).to_bytes())
    }

    fn verify(key: PublicKey, message: &[u8], signature: &Signature) -> bool {
        // A `PublicKey` is any 32 bytes at all, so most of them are not points
        // on the curve and name nobody. Saying so is a plain "no", not an
        // error: the core has no route for one and needs none.
        let Ok(verifying) = VerifyingKey::from_bytes(key.as_bytes()) else {
            return false;
        };
        verifying
            .verify(message, &Ed25519Signature::from_bytes(signature.as_bytes()))
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_signature_checks_out_against_what_was_signed() {
        let signer = Ed25519::from_seed([1; SEED_LEN]);
        let signature = signer.sign(b"where i sit");

        assert!(Ed25519::verify(signer.key(), b"where i sit", &signature));
        assert!(!Ed25519::verify(signer.key(), b"where i sat", &signature));
    }

    #[test]
    fn one_key_cannot_sign_for_another() {
        let mallory = Ed25519::from_seed([9; SEED_LEN]);
        let alice = Ed25519::from_seed([1; SEED_LEN]);

        let forged = mallory.sign(b"alice sits at the root");
        assert!(
            !Ed25519::verify(alice.key(), b"alice sits at the root", &forged),
            "this is the whole difference from the core's stand-in"
        );
    }

    #[test]
    fn a_seed_gives_the_same_identity_every_time() {
        assert_eq!(
            Ed25519::from_seed([7; SEED_LEN]).key(),
            Ed25519::from_seed([7; SEED_LEN]).key()
        );
        assert_ne!(
            Ed25519::from_seed([7; SEED_LEN]).key(),
            Ed25519::from_seed([8; SEED_LEN]).key()
        );
    }

    #[test]
    fn a_key_is_not_chosen_but_derived() {
        // The seed is all a caller supplies, and the address that comes out
        // looks nothing like it. Picking a key to impersonate would mean
        // finding a seed that produced it.
        let seed = [3; SEED_LEN];
        assert_ne!(Ed25519::from_seed(seed).key().as_bytes(), &seed);
    }

    #[test]
    fn nothing_verifies_against_a_key_that_is_not_a_point() {
        // Most 32-byte strings are not ed25519 public keys. Handing one over
        // must be answered rather than blown up on.
        let nonsense = PublicKey::new([0xff; 32]);
        let signature = Ed25519::from_seed([1; SEED_LEN]).sign(b"anything");
        assert!(!Ed25519::verify(nonsense, b"anything", &signature));
    }

    #[test]
    fn the_secret_stays_out_of_the_debug_output() {
        let signer = Ed25519::from_seed([5; SEED_LEN]);
        let printed = format!("{signer:?}");
        let secret = format!("{:02x?}", [5u8; SEED_LEN]);
        assert!(!printed.contains(&secret));
        assert!(printed.contains(&format!("{:?}", signer.key())));
    }
}
