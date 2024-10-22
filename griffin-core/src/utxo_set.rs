//! UTxO interface to storage.

use crate::{
    types::{Output, Input},
    LOG_TARGET,
};
use parity_scale_codec::{Decode, Encode};

pub struct TransparentUtxoSet;

impl TransparentUtxoSet {
    /// Fetch a utxo from the set.
    pub fn peek_utxo(input: &Input) -> Option<Output> {
        sp_io::storage::get(&input.encode()).and_then(|d| Output::decode(&mut &*d).ok())
    }

    /// Consume a Utxo from the set.
    pub fn consume_utxo(input: &Input) -> Option<Output> {
        let maybe_output = Self::peek_utxo(input);
        sp_io::storage::clear(&input.encode());
        maybe_output
    }

    /// Add a utxo into the set.
    pub fn store_utxo(input: Input, output: &Output) {
        let key = input.encode();
        log::debug!(
            target: LOG_TARGET,
            "Storing UTXO at key: {:?}",
            sp_core::hexdisplay::HexDisplay::from(&key)
        );
        sp_io::storage::set(&key, &output.encode());
    }
}
