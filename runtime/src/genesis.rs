//! Helper module to build a genesis configuration for the template runtime.

#[cfg(feature = "std")]
pub use super::WASM_BINARY;
use super::{
    Transaction,
    Output
};
use alloc::{ vec::Vec, vec, string::String, collections::BTreeMap };
use griffin_core::{
    types::{
        address_from_hex, Coin, AssetName, EncapBTree, Multiasset,
    },
    h224::H224,
};
use serde::{Deserialize, Serialize};
use serde_json;
use hex::FromHex;
use pallas_crypto::hash::Hash;
use core::str::FromStr;

/// A default seed phrase for signing inputs when none is provided
/// Corresponds to the default pubkey.
pub const SHAWN_PHRASE: &str =
    "news slush supreme milk chapter athlete soap sausage put clutch what kitten";

/// The public key corresponding to the default seed above.
pub const SHAWN_PUB_KEY: &str = "7b155093789404780735f4501c576e9f6e2b0a486cdec70e03e1ef8b9ef99274";

/// The address corresponding to Shawn's public key. Such addresses always start with `0x61`.
pub const SHAWN_ADDRESS: &str = "6101e6301758a6badfab05035cffc8e3438b3aff2a4edc6544b47329c4";

#[derive(Serialize, Deserialize, Debug, Clone)]
struct TransparentMultiasset {
    pub policy: String,
    pub assets: Vec<(String, Coin)>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct TransparentOutput {
    pub address: String,
    pub coin: Coin,
    pub value: Vec<TransparentMultiasset>,
    pub datum: Option<String>,
}

/// This function returns a list of valid transactions to be included in the genesis block.
/// It is called by the `ChainSpec::build` method, via the `development_genesis_config` function.
/// The resulting transactions must be ordered: inherent first, then extrinsics.
pub fn development_genesis_transactions() -> Vec<Transaction> {
    let json_data = r#"
[
  {
    "address": "6101e6301758a6badfab05035cffc8e3438b3aff2a4edc6544b47329c4",
    "coin": 314000000,
    "value": [
               {
                 "policy": "0298aa99f95e2fe0a0132a6bb794261fb7e7b0d988215da2f2de2005",
                 "assets": [ ["tokenA", 271000000], ["tokenB", 1123581321] ]
               },
               {
                 "policy": "1111111111111111111111111114261fb7e7b0d988215da2f2de2005",
                 "assets": [ ["tokenA", 271000000], ["tokenB", 1123581321] ]
               }
             ],
    "datum": null
  },
  {
    "address": "6101e6301758a6badfab05035cffc8e3438b3aff2a4edc6544b47329c4",
    "coin": 314000000,
    "value": [],
    "datum": "820080"
  }
]
"#;
    let transp_outputs: Vec<TransparentOutput> = parse_json(json_data).unwrap();

    vec![Transaction::from((
        vec![],
        transp_outputs.into_iter().map(transp_to_output).collect()
    ))
    ]
}

pub fn development_genesis_config() -> serde_json::Value {
    serde_json::json!(development_genesis_transactions())
}

fn parse_json(input: &str) -> Result<Vec<TransparentOutput>, serde_json::Error> {
    serde_json::from_str(input)
}

fn transp_to_assets(transp: Vec<(String, Coin)>) -> EncapBTree<AssetName, Coin> {
    let mut asset_btree = BTreeMap::new();

    for (name, amount) in transp {
        asset_btree.insert(<_>::from(name), amount);
    }
    
    EncapBTree(asset_btree)
}

fn transp_to_value(transp: Vec<TransparentMultiasset>) -> Multiasset<Coin> {
    let mut ma_btree = BTreeMap::new();

    for TransparentMultiasset{ policy, assets } in transp {
        ma_btree.insert(
            H224::from(Hash::from_str(&policy).unwrap()),
            transp_to_assets(assets)
        );
    }
    
    EncapBTree(ma_btree)
}

fn transp_to_output(transp: TransparentOutput) -> Output {
    Output::from((
        address_from_hex(&transp.address),
        transp.coin,
        transp_to_value(transp.value),
        transp.datum.map(|v| <_>::from(<Vec<u8>>::from_hex(v).unwrap())),
    ))
}
