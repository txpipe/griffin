//! Helper module to build a genesis configuration for the template runtime.

#[cfg(feature = "std")]
pub use super::WASM_BINARY;
use super::{
    Transaction,
    Output
};
use alloc::{ vec::Vec, vec };
use hex::FromHex;
use core::convert::From;
use griffin_core::types::{ Address, FakeDatum, Datum };
use pallas_codec::minicbor::encode;

/// A default seed phrase for signing inputs when none is provided
/// Corresponds to the default pubkey.
pub const SHAWN_PHRASE: &str =
    "news slush supreme milk chapter athlete soap sausage put clutch what kitten";

/// The public key corresponding to the default seed above.
pub const SHAWN_PUB_KEY: &str = "d2bf4b844dfefd6772a8843e669f943408966a977e3ae2af1dd78e0f55f4df67";

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
        Address(Vec::from(<[u8; 32]>::from_hex(SHAWN_PUB_KEY).unwrap())),
        314,
        Datum::from(datum),
    ));

    log::info!("Datum: {:?}", output.clone());

    vec![
        Transaction {
            inputs: vec![],
            outputs: vec![output],
        }
    ]
}

pub fn development_genesis_config() -> serde_json::Value {
    serde_json::json!(development_genesis_transactions())
}
