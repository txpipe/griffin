//! Suplementary functions to perform ledger checks on Griffin transactions
//! by using tools available in Pallas.
//!
//! Some of these functions were brought directly from Pallas since they belong
//! to its test suit.
use crate::pallas_applying::{utils::ValidationError, UTxOs};
use crate::pallas_codec::minicbor::encode;
use crate::pallas_codec::utils::{Bytes, CborWrap};
use crate::pallas_primitives::{
    alonzo::Value,
    babbage::{
        MintedDatumOption, MintedPostAlonzoTransactionOutput, MintedScriptRef,
        MintedTransactionBody, MintedTransactionOutput, MintedTx as BabbageMintedTx,
        PseudoTransactionOutput, Tx as BabbageTx,
    },
};
use crate::pallas_traverse::{MultiEraInput, MultiEraOutput};
use crate::types::{
    value_leq, DispatchResult,
    UTxOError::{self, *},
};
use alloc::{borrow::Cow, boxed::Box, string::String, vec::Vec};
use core::iter::zip;

/// Every output must contain this many `Coin`s.
pub const MIN_COIN_PER_OUTPUT: crate::types::Coin = 10;

impl From<ValidationError> for UTxOError {
    /// Translation of Cardano's Babbage era errors to Griffin's.
    fn from(err: ValidationError) -> UTxOError {
        match err {
            ValidationError::Babbage(err) => UTxOError::Babbage(err),
            _ => Fail,
        }
    }
}

pub fn babbage_tx_to_cbor(tx: &BabbageTx) -> Vec<u8> {
    let mut tx_buf: Vec<u8> = Vec::new();
    let _ = encode(tx, &mut tx_buf);

    tx_buf
}

pub fn babbage_minted_tx_from_cbor(tx_cbor: &[u8]) -> BabbageMintedTx<'_> {
    crate::pallas_codec::minicbor::decode::<BabbageMintedTx>(&tx_cbor[..]).unwrap()
}

pub fn mk_utxo_for_babbage_tx<'a>(
    tx_body: &MintedTransactionBody,
    tx_outs_info: &'a [(
        String, // address in string format
        Value,
        Option<MintedDatumOption>,
        Option<CborWrap<MintedScriptRef>>,
    )],
) -> UTxOs<'a> {
    let mut utxos: UTxOs = UTxOs::new();
    for (tx_in, (addr, val, datum_opt, script_ref)) in zip(tx_body.inputs.clone(), tx_outs_info) {
        let multi_era_in: MultiEraInput =
            MultiEraInput::AlonzoCompatible(Box::new(Cow::Owned(tx_in)));
        let address_bytes: Bytes = match hex::decode(addr) {
            Ok(bytes_vec) => Bytes::from(bytes_vec),
            _ => panic!("Unable to decode input address"),
        };
        let tx_out: MintedTransactionOutput =
            PseudoTransactionOutput::PostAlonzo(MintedPostAlonzoTransactionOutput {
                address: address_bytes,
                value: val.clone(),
                datum_option: datum_opt.clone(),
                script_ref: script_ref.clone(),
            });
        let multi_era_out: MultiEraOutput = MultiEraOutput::Babbage(Box::new(Cow::Owned(tx_out)));
        utxos.insert(multi_era_in, multi_era_out);
    }

    utxos
}

pub fn check_min_coin(tx_body: &MintedTransactionBody) -> DispatchResult {
    use crate::pallas_applying::utils::BabbageError::MinLovelaceUnreached;

    let min_reached: bool = tx_body.outputs.iter().all(|out| {
        value_leq(
            &crate::types::Value::Coin(MIN_COIN_PER_OUTPUT),
            &<_>::from(match out {
                PseudoTransactionOutput::PostAlonzo(pos) => pos.value.clone(),
                _ => return false, // Legacy outputs should not be here!
            }),
        )
    });
    if min_reached {
        Ok(())
    } else {
        Err(UTxOError::Babbage(MinLovelaceUnreached))
    }
}
