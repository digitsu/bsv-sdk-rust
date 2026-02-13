//! Chain tracker trait for SPV verification.
//!
//! Ported from the Go SDK's `chaintracker/chaintracker.go`.

use bsv_primitives::chainhash::Hash;

use crate::error::SpvError;

/// Trait for verifying Merkle roots against block headers.
///
/// Implementors provide access to block header data, allowing
/// SPV verification of transactions by checking that a computed
/// Merkle root matches the expected root for a given block height.
pub trait ChainTracker {
    /// Verify that a Merkle root is valid for a given block height.
    ///
    /// # Arguments
    /// * `root` - The computed Merkle root hash.
    /// * `height` - The block height to verify against.
    ///
    /// # Returns
    /// `Ok(true)` if the root matches the block at the given height.
    fn is_valid_root_for_height(&self, root: &Hash, height: u32) -> Result<bool, SpvError>;

    /// Get the current chain tip height.
    fn current_height(&self) -> Result<u32, SpvError>;
}
