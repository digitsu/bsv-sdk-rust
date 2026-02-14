

//! BSV Blockchain SDK - SPV verification.
//!
//! Provides Simplified Payment Verification (SPV) types including
//! Merkle paths (BUMP format), BEEF transaction containers, chain
//! tracking traits, and broadcaster interfaces.
//!
//! Ported from the Go BSV SDK's transaction/merklepath.go, transaction/beef.go,
//! transaction/chaintracker/, and transaction/broadcaster.go.

pub mod error;
pub mod merkle_tree_parent;
pub mod merkle_path;
pub mod chain_tracker;
pub mod broadcaster;
pub mod beef;

pub use error::SpvError;
pub use merkle_path::{MerklePath, PathElement};
pub use merkle_tree_parent::{merkle_tree_parent, merkle_tree_parent_bytes, merkle_tree_parent_str};
pub use chain_tracker::ChainTracker;
pub use broadcaster::{Broadcaster, BroadcastSuccess, BroadcastFailure};
pub use beef::{Beef, BeefTx, DataFormat, BEEF_V1, BEEF_V2, ATOMIC_BEEF};
