//! JungleBus data types: configuration, transaction, block header, and address models.

use serde::{Deserialize, Serialize};

/// Configuration for a [`JungleBusClient`](crate::JungleBusClient).
#[derive(Debug, Clone)]
pub struct JungleBusConfig {
    /// Base URL for the JungleBus API (e.g. `https://junglebus.gorillapool.io`).
    pub server_url: String,
    /// Optional authentication token sent via `token` header.
    pub token: Option<String>,
    /// API version prefix (e.g. `v1`).
    pub api_version: String,
}

impl Default for JungleBusConfig {
    fn default() -> Self {
        Self {
            server_url: "https://junglebus.gorillapool.io".to_string(),
            token: None,
            api_version: "v1".to_string(),
        }
    }
}

/// A transaction returned by the JungleBus API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    /// Transaction ID.
    #[serde(default)]
    pub id: String,
    /// Raw transaction data (hex-encoded).
    #[serde(default)]
    pub transaction: Option<String>,
    /// Block hash containing this transaction.
    #[serde(default)]
    pub block_hash: Option<String>,
    /// Block height containing this transaction.
    #[serde(default)]
    pub block_height: Option<u32>,
    /// Block timestamp.
    #[serde(default)]
    pub block_time: Option<u32>,
    /// Index of the transaction within the block.
    #[serde(default)]
    pub block_index: Option<u64>,
    /// Addresses involved in this transaction.
    #[serde(default)]
    pub addresses: Vec<String>,
    /// Input scripts/addresses.
    #[serde(default)]
    pub inputs: Vec<String>,
    /// Output scripts/addresses.
    #[serde(default)]
    pub outputs: Vec<String>,
    /// Input script types.
    #[serde(default)]
    pub input_types: Vec<String>,
    /// Output script types.
    #[serde(default)]
    pub output_types: Vec<String>,
    /// Context labels.
    #[serde(default)]
    pub contexts: Vec<String>,
    /// Sub-context labels.
    #[serde(default)]
    pub sub_contexts: Vec<String>,
    /// Additional data fields.
    #[serde(default)]
    pub data: Vec<String>,
    /// Merkle proof data (hex-encoded).
    #[serde(default)]
    pub merkle_proof: Option<String>,
}

/// A block header returned by the JungleBus API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    /// Block hash.
    #[serde(default)]
    pub hash: String,
    /// Coin type identifier.
    #[serde(default)]
    pub coin: Option<u32>,
    /// Block height.
    #[serde(default)]
    pub height: u32,
    /// Block timestamp.
    #[serde(default)]
    pub time: u32,
    /// Block nonce.
    #[serde(default)]
    pub nonce: Option<u32>,
    /// Block version.
    #[serde(default)]
    pub version: Option<u32>,
    /// Merkle root hash.
    #[serde(default, alias = "merkleroot")]
    pub merkle_root: Option<String>,
    /// Difficulty target bits.
    #[serde(default)]
    pub bits: Option<String>,
    /// Sync status timestamp.
    #[serde(default)]
    pub synced: Option<u64>,
}

/// Address information returned by the JungleBus API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressInfo {
    /// The address.
    #[serde(default)]
    pub address: String,
    /// Number of transactions associated with this address.
    #[serde(default)]
    pub transaction_count: Option<u64>,
    /// Total value received (in satoshis).
    #[serde(default)]
    pub total_received: Option<u64>,
    /// Total value sent (in satoshis).
    #[serde(default)]
    pub total_sent: Option<u64>,
}
