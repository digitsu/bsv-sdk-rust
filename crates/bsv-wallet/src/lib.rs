/// BSV Blockchain SDK - Wallet interface and key derivation.
///
/// Defines the 29-method Wallet trait, key derivation (BRC-42),
/// proto-wallet implementation, and wire protocol serialization.

mod error;
pub use error::WalletError;

pub mod types;
pub mod key_deriver;
pub mod wallet_trait;
pub mod proto_wallet;

pub use key_deriver::KeyDeriver;
pub use proto_wallet::{ProtoWallet, ProtoWalletArgs, Wallet};
pub use wallet_trait::WalletInterface;

pub mod serializer;
