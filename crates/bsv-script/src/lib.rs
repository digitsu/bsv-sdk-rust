/// BSV Blockchain SDK - Script parsing, execution, and address handling.
///
/// Provides the Bitcoin Script type, opcode definitions, script chunk parsing,
/// address generation/validation, and a full script interpreter engine.

pub mod script;
pub mod opcodes;
pub mod chunk;
pub mod address;
pub mod interpreter;

mod error;
pub use error::ScriptError;
pub use script::Script;
pub use address::{Address, Network};
pub use chunk::ScriptChunk;
