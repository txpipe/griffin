//! Custom GenesisConfigBuilder, to allow extrinsics to be added to the genesis block.

use crate::{
    ensure,
    h224::H224,
    pallas_crypto::hash::Hash,
    types::{
        address_from_hex, AssetName, Coin, EncapBTree, Input, Multiasset, Output, Transaction,
    },
    EXTRINSIC_KEY, ZERO_SLOT, ZERO_TIME,
};
use alloc::{collections::BTreeMap, string::String, vec, vec::Vec};
use core::str::FromStr;
use hex::FromHex;
use parity_scale_codec::Encode;
use serde::{Deserialize, Serialize};
use sp_runtime::traits::Hash as HashT;

pub struct GriffinGenesisConfigBuilder;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransparentMultiasset<A> {
    pub policy: String,
    pub assets: Vec<(String, A)>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransparentOutput {
    pub address: String,
    pub coin: Coin,
    pub value: Vec<TransparentMultiasset<Coin>>,
    pub datum: Option<String>,
}

/// Genesis configuration for the Griffin chain.
/// It contains a list of outputs used to build the transactions
/// to be included in the genesis block, the initial slot and the initial time.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GenesisConfig {
    pub zero_slot: u64,
    pub zero_time: u64,
    pub outputs: Vec<TransparentOutput>,
}

impl GriffinGenesisConfigBuilder
where
    Transaction: Encode,
{
    /// This function expects the chain's genesis configuration to be passed as a parameter.
    /// It will build the genesis block by creating transactions from the outputs provided
    /// in the genesis configuration. The transactions are created with empty inputs.
    /// It will also store the zero slot and zero time in the storage.
    pub fn build(genesis_config: GenesisConfig) -> sp_genesis_builder::Result {
        let transactions = vec![Transaction::from((
            vec![],
            genesis_config
                .outputs
                .into_iter()
                .map(transp_to_output)
                .collect(),
        ))];

        // The transactions, zero slot and zero time are stored under special keys.
        sp_io::storage::set(EXTRINSIC_KEY, &transactions.encode());
        sp_io::storage::set(ZERO_SLOT, &genesis_config.zero_slot.encode());
        sp_io::storage::set(ZERO_TIME, &genesis_config.zero_time.encode());

        for tx in transactions.into_iter() {
            // Enforce that transactions do not have any inputs.
            ensure!(
                tx.transaction_body.inputs.is_empty(),
                "Genesis transactions must not have any inputs."
            );
            // Insert the outputs into the storage.
            let tx_hash = sp_runtime::traits::BlakeTwo256::hash_of(&tx.encode());
            for (index, utxo) in tx.transaction_body.outputs.iter().enumerate() {
                let input = Input {
                    tx_hash,
                    index: index as u32,
                };
                sp_io::storage::set(&input.encode(), &utxo.encode());
            }
        }

        Ok(())
    }
}

pub fn transp_to_output(transp: TransparentOutput) -> Output {
    Output::from((
        address_from_hex(&transp.address),
        transp.coin,
        transp_to_multiasset(transp.value),
        transp
            .datum
            .map(|v| <_>::from(<Vec<u8>>::from_hex(v).unwrap())),
    ))
}

fn transp_to_assets<A>(transp: Vec<(String, A)>) -> EncapBTree<AssetName, A> {
    let mut asset_btree = BTreeMap::new();

    for (name, amount) in transp {
        asset_btree.insert(<_>::from(name), amount);
    }

    EncapBTree(asset_btree)
}

pub fn transp_to_multiasset<A>(transp: Vec<TransparentMultiasset<A>>) -> Multiasset<A> {
    let mut ma_btree = BTreeMap::new();

    for TransparentMultiasset { policy, assets } in transp {
        ma_btree.insert(
            H224::from(Hash::from_str(&policy).unwrap()),
            transp_to_assets(assets),
        );
    }

    EncapBTree(ma_btree)
}
