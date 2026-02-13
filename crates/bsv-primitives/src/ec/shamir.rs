//! Shamir secret sharing for private key splitting and recovery.
//!
//! Splits a private key into N shares with a threshold of K required
//! for reconstruction, using polynomial interpolation over the secp256k1 field.
