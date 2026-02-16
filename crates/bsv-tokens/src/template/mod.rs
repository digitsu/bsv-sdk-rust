//! Script templates for STAS token transactions.

pub mod dstas;
pub mod stas;
pub mod stas_btg;

pub use dstas::DstasUnlockingTemplate;
pub use stas::{unlock, StasUnlockingTemplate};
pub use stas_btg::{unlock_btg, StasBtgUnlockingTemplate};
