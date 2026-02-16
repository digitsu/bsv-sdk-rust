#![deny(missing_docs)]
//! BSV Token protocol support (STAS, dSTAS).
//!
//! Provides types and utilities for creating, transferring, and managing
//! tokens on the BSV blockchain using the STAS and dSTAS protocols.

pub mod error;
pub mod scheme;
pub mod token_id;
pub mod script_type;
pub mod types;

pub use error::TokenError;
pub use scheme::{Authority, TokenScheme};
pub use token_id::TokenId;
pub use script_type::ScriptType;
pub use types::{Payment, Destination, DstasSpendType, ActionData, DstasLockingParams, DstasDestination};
