//! Elliptic curve cryptography on secp256k1.
//!
//! Provides private keys, public keys, ECDSA signatures,
//! key derivation (BRC-42), and symmetric encryption.

pub mod private_key;
pub mod public_key;
pub mod signature;
pub mod symmetric;

pub use private_key::PrivateKey;
pub use public_key::PublicKey;
pub use signature::Signature;
pub use symmetric::SymmetricKey;
