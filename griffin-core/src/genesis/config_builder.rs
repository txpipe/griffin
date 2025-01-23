//! Custom GenesisConfigBuilder, to allow extrinsics to be added to the genesis block.

use crate::{
    ensure,
    types::{Input, Transaction},
    EXTRINSIC_KEY,
};
use alloc::vec::Vec;
use parity_scale_codec::Encode;
use sp_runtime::traits::Hash as HashT;

pub struct GriffinGenesisConfigBuilder;

impl GriffinGenesisConfigBuilder
where
    Transaction: Encode,
{
    /// This function expects a list of transactions to be included in the genesis block,
    /// and stored along with their outputs. They must not contain any inputs.
    pub fn build(genesis_transactions: Vec<Transaction>) -> sp_genesis_builder::Result {
        // The transactions are stored under a special key.
        sp_io::storage::set(EXTRINSIC_KEY, &genesis_transactions.encode());

        for tx in genesis_transactions.into_iter() {
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
