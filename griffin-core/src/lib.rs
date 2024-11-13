//! This crate contains all the fundamental building blocks for the Griffin
//! ledger, runtime, and wallet.

#![cfg_attr(not(feature = "std"), no_std)]

#[macro_use]
extern crate alloc;

mod executive;

pub mod pallas_codec;
pub mod pallas_crypto;
pub mod pallas_addresses;
pub mod pallas_primitives;
pub mod pallas_traverse;
pub mod pallas_applying;
pub mod support_macros;
pub mod types;
pub mod genesis;
pub mod pallas_interface;
pub mod checks_interface;
pub mod h224;
use h224::H224;
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
