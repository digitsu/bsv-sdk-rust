
#![allow(
    clippy::collapsible_if,
    clippy::empty_line_after_doc_comments,
    clippy::if_same_then_else,
    clippy::manual_range_contains,
    clippy::needless_borrows_for_generic_args,
    clippy::new_without_default,
    clippy::question_mark,
    clippy::single_match,
    unused_imports
)]

//! BSV Blockchain SDK - Script parsing, execution, and address handling.
//!
//! Provides the Bitcoin Script type, opcode definitions, script chunk parsing,
//! address generation/validation, and a full script interpreter engine.

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
