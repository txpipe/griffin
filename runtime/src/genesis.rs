//! Helper module to build a genesis configuration for the runtime.

#[cfg(feature = "std")]
pub use super::WASM_BINARY;
use super::{Output, Transaction};
use alloc::{collections::BTreeMap, string::String, vec, vec::Vec};
use core::str::FromStr;
use griffin_core::{
    h224::H224,
    pallas_crypto::hash::Hash,
    types::{address_from_hex, AssetName, Coin, EncapBTree, Multiasset},
};
use hex::FromHex;
use serde::{Deserialize, Serialize};
use serde_json;

/// The default genesis. It can be replaced by a custom one by providing the
/// node with an analogous JSON file through the `--chain` flag
pub const GENESIS_DEFAULT_JSON: &str = r#"
[
  {
    "address": "6101e6301758a6badfab05035cffc8e3438b3aff2a4edc6544b47329c4",
    "coin": 314000000,
    "value": [
               {
                 "policy": "0298aa99f95e2fe0a0132a6bb794261fb7e7b0d988215da2f2de2005",
                 "assets": [ ["tokenA", 271000000], ["tokenB", 1123581321] ]
               }
             ],
    "datum": "820080"
  }
]
"#;

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
///
/// If a custom genesis is not provided, [GENESIS_DEFAULT_JSON] is used.
pub fn development_genesis_transactions(genesis_json: String) -> Vec<Transaction> {
    let mut json_data: &str = GENESIS_DEFAULT_JSON;
    if !genesis_json.is_empty() {
        json_data = &genesis_json;
    };
    let transp_outputs: Vec<TransparentOutput> = match parse_json(json_data) {
        Err(e) => panic!("Error: {e}\nJSON data: {json_data}"),
        Ok(v) => v,
    };

    vec![Transaction::from((
        vec![],
        transp_outputs.into_iter().map(transp_to_output).collect(),
    ))]
}

pub fn development_genesis_config(genesis_json: String) -> serde_json::Value {
    serde_json::json!(development_genesis_transactions(genesis_json))
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

    for TransparentMultiasset { policy, assets } in transp {
        ma_btree.insert(
            H224::from(Hash::from_str(&policy).unwrap()),
            transp_to_assets(assets),
        );
    }

    EncapBTree(ma_btree)
}

fn transp_to_output(transp: TransparentOutput) -> Output {
    Output::from((
        address_from_hex(&transp.address),
        transp.coin,
        transp_to_value(transp.value),
        transp
            .datum
            .map(|v| <_>::from(<Vec<u8>>::from_hex(v).unwrap())),
    ))
}
