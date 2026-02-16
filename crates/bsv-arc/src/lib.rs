#![deny(missing_docs)]

//! # bsv-arc
//!
//! ARC (Authoritative Response Component) HTTP client for broadcasting
//! BSV transactions and querying their status.
//!
//! This crate provides an async-first client that also implements the
//! synchronous [`Broadcaster`](bsv_spv::broadcaster::Broadcaster) trait
//! from `bsv-spv`.
//!
//! # Example
//!
//! ```no_run
//! use bsv_arc::{ArcClient, ArcConfig};
//!
//! let client = ArcClient::new(ArcConfig {
//!     base_url: "https://arc.taal.com/v1".to_string(),
//!     api_key: Some("my-key".to_string()),
//!     ..Default::default()
//! });
//! ```

pub mod client;
pub mod error;
pub mod types;

#[cfg(test)]
mod tests;

pub use client::{ArcClient, AsyncBroadcaster};
pub use error::ArcError;
pub use types::{ArcConfig, ArcResponse, ArcStatus};
