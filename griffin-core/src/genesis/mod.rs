//! Utilities for blockchainchain genesis.

#[cfg(feature = "std")]
mod block_builder;
pub mod config_builder;

#[cfg(feature = "std")]
pub use block_builder::GriffinGenesisBlockBuilder;
pub use config_builder::GriffinGenesisConfigBuilder;

/// A default seed phrase for signing inputs when none is provided
/// Corresponds to the default pubkey.
pub const SHAWN_PHRASE: &str =
    "news slush supreme milk chapter athlete soap sausage put clutch what kitten";

/// The public key corresponding to the default seed above.
pub const SHAWN_PUB_KEY: &str = "7b155093789404780735f4501c576e9f6e2b0a486cdec70e03e1ef8b9ef99274";

/// The public key hash corresponding to Shawn's public key.
pub const SHAWN_PUB_KEY_HASH: &str = "01e6301758a6badfab05035cffc8e3438b3aff2a4edc6544b47329c4";

/// The address corresponding to Shawn's public key. Such addresses always start with `0x61`.
pub const SHAWN_ADDRESS: &str = "6101e6301758a6badfab05035cffc8e3438b3aff2a4edc6544b47329c4";

pub const ALICE_PHRASE: &str =
    "mobile broken meat lonely empty cupboard mom come derive write sugar cushion";
pub const ALICE_PUB_KEY: &str = "c6f58a018f5f4fba0eec76bb2d92cacab00eb6b548197925572c61c17b3e4edf";
pub const ALICE_PUB_KEY_HASH: &str = "547932e40a24e2b7deb41f31af21ed57acd125f4ed8a72b626b3d7f6";
pub const ALICE_ADDRESS: &str = "61547932e40a24e2b7deb41f31af21ed57acd125f4ed8a72b626b3d7f6";
