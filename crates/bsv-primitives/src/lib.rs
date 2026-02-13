/// BSV Blockchain SDK - Cryptographic primitives, hashing, and utilities.
///
/// This crate provides the foundational building blocks for the BSV SDK:
/// - Hash functions (SHA-256, SHA-256d, RIPEMD-160, SHA-512, HMAC)
/// - Chain hash type for transaction and block identification
/// - Elliptic curve cryptography (secp256k1 keys, signatures, derivation)
/// - AES encryption (GCM and CBC modes)
/// - Variable-length integer encoding
/// - Base58 encoding/decoding
/// - Key share splitting (Shamir secret sharing)

pub mod hash;
pub mod chainhash;
pub mod util;
pub mod base58;
pub mod ec;
pub mod aes;
pub mod keyshares;
pub mod ecdsa;
pub mod schnorr;
pub mod bip39;

mod error;
pub use error::PrimitivesError;
