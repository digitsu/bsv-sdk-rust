#![deny(missing_docs)]

//! # bsv-junglebus
//!
//! JungleBus client for querying BSV blockchain transactions, addresses,
//! and block headers via GorillaPool's JungleBus service.
//!
//! This crate provides an async HTTP client for the JungleBus REST API.
//!
//! # Example
//!
//! ```no_run
//! use bsv_junglebus::{JungleBusClient, JungleBusConfig};
//!
//! # async fn example() -> Result<(), bsv_junglebus::JungleBusError> {
//! let client = JungleBusClient::new(JungleBusConfig {
//!     token: Some("my-token".to_string()),
//!     ..Default::default()
//! });
//!
//! let tx = client.get_transaction("abcdef1234567890").await?;
//! println!("Transaction: {:?}", tx);
//!
//! let header = client.get_block_header("800000").await?;
//! println!("Block: {:?}", header);
//! # Ok(())
//! # }
//! ```
//!
//! # Subscriptions (planned)
//!
//! Real-time subscriptions via WebSocket are planned for a future release.
//! The JungleBus subscription system uses the Centrifuge protocol with protobuf
//! encoding over WebSocket connections. Key features:
//! - Subscribe to mined transactions matching a filter
//! - Subscribe to mempool transactions
//! - Control channel for block sync status
//! - Lite mode for hash-only notifications
//! - Automatic reconnection with resume from last block
//!
//! ## Subscription channels
//!
//! - `query:{subId}:{fromBlock}:{fromPage}` — mined transactions
//! - `query:{subId}:mempool` — mempool transactions
//! - `query:{subId}:control` — control events (block sync status)
//!
//! ## Event handler pattern
//!
//! The subscription layer will provide callbacks: `OnTransaction`, `OnMempool`,
//! `OnStatus`, and `OnError`, following the Go SDK's `EventHandler` pattern.

pub mod client;
pub mod error;
pub mod types;

#[cfg(test)]
mod tests;

pub use client::JungleBusClient;
pub use error::JungleBusError;
pub use types::{AddressInfo, BlockHeader, JungleBusConfig, Transaction};
