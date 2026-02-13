/// BSV Blockchain SDK - Transaction building, signing, and serialization.
///
/// Provides the Transaction type with inputs, outputs, fee calculation,
/// signature hash computation, and binary/hex serialization.
///
/// # Modules
///
/// - `transaction` - Core `Transaction` struct and serialization.
/// - `input` - `TransactionInput` type and wire-format parsing.
/// - `output` - `TransactionOutput` type and wire-format parsing.
/// - `sighash` - BIP-143 (FORKID) signature hash computation.
/// - `template` - Script templates (P2PKH, PushDrop) for signing (stub).
/// - `fee_model` - Fee calculation models (stub).
/// - `broadcaster` - Transaction broadcasting interfaces (stub).
/// - `chaintracker` - Chain tracking for SPV verification (stub).

pub mod transaction;
pub mod input;
pub mod output;
pub mod sighash;
pub mod template;
pub mod fee_model;
pub mod broadcaster;
pub mod chaintracker;

mod error;
pub use error::TransactionError;
pub use transaction::Transaction;
pub use input::TransactionInput;
pub use output::TransactionOutput;

#[cfg(test)]
mod tests;
