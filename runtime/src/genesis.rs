//! Helper module to build a genesis configuration for the template runtime.

#[cfg(feature = "std")]
pub use super::WASM_BINARY;
use super::{
    Transaction,
    Output
};
use alloc::{ vec::Vec, vec };
use griffin_core::{
    types::{ FakeDatum, Datum, address_from_hex },
    pallas_codec::minicbor::encode,
};

/// A default seed phrase for signing inputs when none is provided
/// Corresponds to the default pubkey.
pub const SHAWN_PHRASE: &str =
    "news slush supreme milk chapter athlete soap sausage put clutch what kitten";

/// The public key corresponding to the default seed above.
pub const SHAWN_PUB_KEY: &str = "7b155093789404780735f4501c576e9f6e2b0a486cdec70e03e1ef8b9ef99274";

/// The address corresponding to Shawn's public key. Such addresses always start with `0x61`.
pub const SHAWN_ADDRESS: &str = "6101e6301758a6badfab05035cffc8e3438b3aff2a4edc6544b47329c4";

/// This function returns a list of valid transactions to be included in the genesis block.
/// It is called by the `ChainSpec::build` method, via the `development_genesis_config` function.
/// The resulting transactions must be ordered: inherent first, then extrinsics.
pub fn development_genesis_transactions() -> Vec<Transaction> {
    let mut datum: Vec<u8> = Vec::new();
    match encode(FakeDatum::CuteOutput, &mut datum) {
        Ok(_) => (),
        Err(err) => panic!("Unable to encode datum ({:?})", err),
    };

    let output = Output::from((
        address_from_hex(SHAWN_ADDRESS),
        314,
        Datum::from(datum.clone()),
    ));

    vec![Transaction::from((vec![], vec![output]))]
}

pub fn development_genesis_config() -> serde_json::Value {
    serde_json::json!(development_genesis_transactions())
}
