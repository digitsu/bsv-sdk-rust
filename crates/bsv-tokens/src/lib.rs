#![deny(missing_docs)]
//! BSV Token protocol support (STAS, dSTAS).
//!
//! Provides types and utilities for creating, transferring, and managing
//! tokens on the BSV blockchain using the STAS and dSTAS protocols.

pub mod error;
pub mod factory;
pub mod scheme;
pub mod script;
pub mod script_type;
pub mod template;
pub mod token_id;
pub mod types;

pub use error::TokenError;
pub use scheme::{Authority, TokenScheme};
pub use token_id::TokenId;
pub use script_type::ScriptType;
pub use types::{Payment, Destination, DstasSpendType, ActionData, DstasLockingParams, DstasDestination};
pub use script::stas_builder::build_stas_locking_script;
pub use script::dstas_builder::{build_dstas_locking_script, build_dstas_flags};
pub use template::stas::StasUnlockingTemplate;
pub use template::dstas::DstasUnlockingTemplate;
pub use factory::{
    build_contract_tx, ContractConfig,
    build_issue_tx, build_transfer_tx, build_split_tx, build_merge_tx, build_redeem_tx,
    IssueConfig, TransferConfig, SplitConfig, MergeConfig, RedeemConfig,
    build_dstas_issue_txs, build_dstas_base_tx, build_dstas_freeze_tx, build_dstas_unfreeze_tx,
    build_dstas_swap_flow_tx, DstasIssueConfig, DstasIssueOutput, DstasIssueTxs,
    DstasBaseConfig, DstasOutputParams, TokenInput,
};
