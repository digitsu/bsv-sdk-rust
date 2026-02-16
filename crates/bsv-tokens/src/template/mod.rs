//! Script templates for STAS token transactions.

pub mod dstas;
pub mod stas;

pub use dstas::DstasUnlockingTemplate;
pub use stas::{unlock, StasUnlockingTemplate};
