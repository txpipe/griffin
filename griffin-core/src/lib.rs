//! This crate contains all the fundamental building blocks for the Griffin
//! ledger, runtime, and wallet.
//!
//! It was initially based on
//! [tuxedo_core](https://off-narrative-labs.github.io/Tuxedo/tuxedo_core/index.html),
//! and it now includes a clone of six crates from the
//! [Pallas](https://github.com/txpipe/pallas) suite, with modifications in
//! order to be used in a `no-std` setting.
//!
//! The Core main purpose is to bring the Griffin node to life. The node is
//! based on Substrate / Polkadot SDK, and the instructions to make it run can
//! be found
//! [here](https://github.com/txpipe/griffin/tree/main?tab=readme-ov-file#griffin).

#![cfg_attr(not(feature = "std"), no_std)]

#[macro_use]
extern crate alloc;

mod executive;

pub mod checks_interface;
pub mod genesis;
pub mod h224;
pub mod pallas_addresses;
pub mod pallas_applying;
pub mod pallas_codec;
pub mod pallas_crypto;
pub mod pallas_interface;
pub mod pallas_primitives;
pub mod pallas_traverse;
pub mod support_macros;
pub mod types;
pub mod uplc;
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
