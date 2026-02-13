/// BSV Blockchain SDK - Transaction building, signing, and serialization.
///
/// Provides the Transaction type with inputs, outputs, fee calculation,
/// signature hash computation, and binary/hex serialization.

pub mod transaction;
pub mod input;
pub mod output;
pub mod sighash;
pub mod template;

mod error;
pub use error::TransactionError;
pub use transaction::Transaction;
pub use input::TransactionInput;
pub use output::TransactionOutput;

#[cfg(test)]
mod tests;
