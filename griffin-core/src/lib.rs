//! This crate is the core of the Griffin runtime framework.
//!
//! All Griffin runtimes will use this machinery and plug in their specific
//! Griffin piece(s)

#![cfg_attr(not(feature = "std"), no_std)]

mod executive;

pub mod support_macros;
pub mod genesis;
pub mod types;
pub mod utxo_set;
pub use executive::Executive;

/// A Griffin-specific target for diagnostic node log messages
const LOG_TARGET: &str = "griffin-core";

/// A transient storage key that will hold the partial header while a block is being built.
/// This key is cleared before the end of the block.
const HEADER_KEY: &[u8] = b"header";

/// A storage key that will store the block height during and after execution.
/// This allows the block number to be available in the runtime even during off-chain api calls.
pub const HEIGHT_KEY: &[u8] = b"height";

/// A transient storage key that will hold the list of extrinsics that have been applied so far.
/// This key is cleared before the end of the block.
pub const EXTRINSIC_KEY: &[u8] = b"extrinsics";
