//! Common types for token operations.

use serde::{Deserialize, Serialize};

use bsv_primitives::chainhash::Hash;
use bsv_primitives::ec::PrivateKey;
use bsv_script::{Address, Script};

/// A UTXO payment input for token transactions.
pub struct Payment {
    /// Transaction hash of the UTXO.
    pub txid: Hash,
    /// Output index within the transaction.
    pub vout: u32,
    /// Satoshi value of the UTXO.
    pub satoshis: u64,
    /// The locking script of the UTXO.
    pub locking_script: Script,
    /// Private key to sign this input.
    pub private_key: PrivateKey,
}

/// A destination for token transfer.
#[derive(Debug, Clone)]
pub struct Destination {
    /// The recipient address.
    pub address: Address,
    /// Satoshi amount to send.
    pub satoshis: u64,
}

/// dSTAS spending operation type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum DstasSpendType {
    /// Standard token transfer.
    Transfer = 1,
    /// Freeze or unfreeze operation.
    FreezeUnfreeze = 2,
    /// Confiscation by authority.
    Confiscation = 3,
    /// Cancel a pending swap.
    SwapCancellation = 4,
}

/// Additional data attached to a dSTAS action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionData {
    /// Atomic swap with a requested script hash.
    Swap {
        /// The SHA-256 hash of the requested output script.
        requested_script_hash: [u8; 32],
    },
    /// Custom application data.
    Custom(Vec<u8>),
}

/// Parameters for constructing a dSTAS locking script.
#[derive(Debug, Clone)]
pub struct DstasLockingParams {
    /// The recipient address.
    pub address: Address,
    /// The spend type for this locking script.
    pub spend_type: DstasSpendType,
    /// Optional action data.
    pub action_data: Option<ActionData>,
}

/// A destination specific to dSTAS token operations.
#[derive(Debug, Clone)]
pub struct DstasDestination {
    /// The recipient address.
    pub address: Address,
    /// Satoshi amount.
    pub satoshis: u64,
    /// The dSTAS spend type.
    pub spend_type: DstasSpendType,
    /// Optional action data.
    pub action_data: Option<ActionData>,
}
