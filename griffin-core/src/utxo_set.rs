//! UTxO interface to storage.

use crate::{
    types::{Output, OutputRef},
    LOG_TARGET,
};
use parity_scale_codec::{Decode, Encode};

pub struct TransparentUtxoSet;

impl TransparentUtxoSet {
    /// Fetch a utxo from the set.
    pub fn peek_utxo(output_ref: &OutputRef) -> Option<Output> {
        sp_io::storage::get(&output_ref.encode()).and_then(|d| Output::decode(&mut &*d).ok())
    }

    /// Consume a Utxo from the set.
    pub fn consume_utxo(output_ref: &OutputRef) -> Option<Output> {
        let maybe_output = Self::peek_utxo(output_ref);
        sp_io::storage::clear(&output_ref.encode());
        maybe_output
    }

    /// Add a utxo into the set.
    pub fn store_utxo(output_ref: OutputRef, output: &Output) {
        let key = output_ref.encode();
        log::debug!(
            target: LOG_TARGET,
            "Storing UTXO at key: {:?}",
            sp_core::hexdisplay::HexDisplay::from(&key)
        );
        sp_io::storage::set(&key, &output.encode());
    }
}
