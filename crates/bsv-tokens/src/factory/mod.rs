//! Transaction factories for STAS token operations.
//!
//! Each factory is a pure function that builds a complete, signed `Transaction`.

pub mod contract;
pub mod stas;

pub use contract::{build_contract_tx, ContractConfig};
pub use stas::{
    build_issue_tx, build_merge_tx, build_redeem_tx, build_split_tx, build_transfer_tx,
    IssueConfig, MergeConfig, RedeemConfig, SplitConfig, TransferConfig,
};
