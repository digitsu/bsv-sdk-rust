//! ARC data types: configuration, status codes, and API response structures.

use serde::{Deserialize, Serialize};

/// ARC transaction status codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ArcStatus {
    /// Transaction was rejected.
    Rejected,
    /// Transaction is queued for processing.
    Queued,
    /// Transaction was received by ARC.
    Received,
    /// Transaction has been stored.
    Stored,
    /// Transaction announced to the network.
    AnnouncedToNetwork,
    /// Transaction requested by the network.
    RequestedByNetwork,
    /// Transaction sent to the network.
    SentToNetwork,
    /// Transaction accepted by the network.
    AcceptedByNetwork,
    /// Transaction seen on the network.
    SeenOnNetwork,
    /// Transaction has been mined.
    Mined,
    /// Transaction has been confirmed.
    Confirmed,
    /// A double-spend was attempted.
    DoubleSpendAttempted,
    /// Transaction seen in orphan mempool.
    SeenInOrphanMempool,
}

impl ArcStatus {
    /// Returns the integer status code used by the ARC API.
    pub fn as_code(&self) -> i32 {
        match self {
            Self::Rejected => 0,
            Self::Queued => 1,
            Self::Received => 2,
            Self::Stored => 3,
            Self::AnnouncedToNetwork => 4,
            Self::RequestedByNetwork => 5,
            Self::SentToNetwork => 6,
            Self::AcceptedByNetwork => 7,
            Self::SeenOnNetwork => 8,
            Self::Mined => 9,
            Self::Confirmed => 10,
            Self::DoubleSpendAttempted => 11,
            Self::SeenInOrphanMempool => 12,
        }
    }
}

impl std::fmt::Display for ArcStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = serde_json::to_value(self)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_default();
        write!(f, "{s}")
    }
}

/// Configuration for an [`ArcClient`](crate::ArcClient).
#[derive(Debug, Clone)]
pub struct ArcConfig {
    /// Base URL for the ARC API (e.g. `https://arc.taal.com/v1`).
    pub base_url: String,
    /// Optional Bearer token for authentication.
    pub api_key: Option<String>,
    /// Callback URL for status notifications.
    pub callback_url: Option<String>,
    /// Token sent with callbacks for verification.
    pub callback_token: Option<String>,
    /// Wait for transaction to reach this status before returning.
    pub wait_for_status: Option<ArcStatus>,
    /// Skip fee validation.
    pub skip_fee_validation: bool,
    /// Skip script validation.
    pub skip_script_validation: bool,
    /// Skip transaction validation.
    pub skip_tx_validation: bool,
    /// Use cumulative fee validation.
    pub cumulative_fee_validation: bool,
    /// Request full status updates via callback.
    pub full_status_updates: bool,
    /// Maximum timeout in seconds.
    pub max_timeout: Option<u32>,
}

impl Default for ArcConfig {
    fn default() -> Self {
        Self {
            base_url: "https://arc.taal.com/v1".to_string(),
            api_key: None,
            callback_url: None,
            callback_token: None,
            wait_for_status: None,
            skip_fee_validation: false,
            skip_script_validation: false,
            skip_tx_validation: false,
            cumulative_fee_validation: false,
            full_status_updates: false,
            max_timeout: None,
        }
    }
}

/// Response from the ARC API.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArcResponse {
    /// Transaction ID.
    pub txid: String,
    /// Transaction status string (e.g. `MINED`).
    #[serde(default)]
    pub tx_status: Option<String>,
    /// Numeric status code.
    #[serde(default)]
    pub status: Option<i32>,
    /// Response title.
    #[serde(default)]
    pub title: Option<String>,
    /// Block hash if mined.
    #[serde(default)]
    pub block_hash: Option<String>,
    /// Block height if mined.
    #[serde(default)]
    pub block_height: Option<u64>,
    /// Extra information from the node.
    #[serde(default)]
    pub extra_info: Option<String>,
    /// Timestamp of the response.
    #[serde(default)]
    pub timestamp: Option<String>,
    /// ARC instance identifier.
    #[serde(default)]
    pub instance: Option<String>,
    /// Detail/error message.
    #[serde(default)]
    pub detail: Option<String>,
    /// Merkle path for SPV proof.
    #[serde(default)]
    pub merkle_path: Option<String>,
}
