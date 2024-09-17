//! Utilities for blockchainchain genesis.

#[cfg(feature = "std")]
mod block_builder;
mod config_builder;

#[cfg(feature = "std")]
pub use block_builder::GriffinGenesisBlockBuilder;
pub use config_builder::GriffinGenesisConfigBuilder;

