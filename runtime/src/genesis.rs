//! Helper module to build a genesis configuration for the template runtime.

#[cfg(feature = "std")]
pub use super::WASM_BINARY;
use super::{
    Transaction,
    Output
};
use alloc::{ vec::Vec, vec };
use core::convert::From;
use griffin_core::types::{ Address, FakeDatum, Datum };
use pallas_codec::minicbor::encode;
use pallas_crypto::hash::{Hasher as PallasHasher};
use hex::FromHex;

/// A default seed phrase for signing inputs when none is provided
/// Corresponds to the default pubkey.
pub const SHAWN_PHRASE: &str =
    "news slush supreme milk chapter athlete soap sausage put clutch what kitten";

/// The public key corresponding to the default seed above.
pub const SHAWN_PUB_KEY: &str = "7b155093789404780735f4501c576e9f6e2b0a486cdec70e03e1ef8b9ef99274";

/// This function returns a list of valid transactions to be included in the genesis block.
/// It is called by the `ChainSpec::build` method, via the `development_genesis_config` function.
/// The resulting transactions must be ordered: inherent first, then extrinsics.
pub fn development_genesis_transactions() -> Vec<Transaction> {
    let mut datum: Vec<u8> = Vec::new();
    match encode(FakeDatum::CuteOutput, &mut datum) {
        Ok(_) => (),
        Err(err) => panic!("Unable to encode datum ({:?})", err),
    };
    // FIXME: Duplicate code in pallas_interface.rs
    // Adding header `0x61` to indicate a "mainnet" enterprise (no staking) address
    let mut hash_with_header: Vec<u8> = vec![0x61];
    let mut hash: Vec<u8>  = PallasHasher::<224>::hash(&<[u8; 32]>::from_hex(SHAWN_PUB_KEY).unwrap()).to_vec();
    hash_with_header.append(&mut hash);

    let output = Output::from((
        Address(hash_with_header),
        314,
        Datum::from(datum.clone()),
    ));

    vec![Transaction::from((vec![], vec![output]))]
}

pub fn development_genesis_config() -> serde_json::Value {
    serde_json::json!(development_genesis_transactions())
}
