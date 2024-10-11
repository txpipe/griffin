// Brought from pallas-applying/tests/
use pallas_applying::{
    UTxOs, utils::{ValidationError::{self, *}, BabbageError },
};
use crate::types::UtxoError::{self, *};
use pallas_codec::minicbor::encode;
use pallas_primitives::{
    alonzo::Value,
    babbage::{
        MintedDatumOption, MintedPostAlonzoTransactionOutput, MintedScriptRef,
        MintedTransactionBody, MintedTransactionOutput, MintedTx as BabbageMintedTx,
        PseudoTransactionOutput, Tx as BabbageTx,
    },
};
use pallas_traverse::{MultiEraInput, MultiEraOutput};
use alloc::{
    borrow::Cow, vec::Vec,
    string::String,
    boxed::Box,
};
use core::iter::zip;
use pallas_codec::utils::{Bytes, CborWrap};

impl From<ValidationError> for UtxoError {
    fn from(err: ValidationError) -> UtxoError {
        match err {
            Babbage(BabbageError::InputNotInUTxO) => MissingInput,
            Babbage(BabbageError::PreservationOfValue) => PreservationOfValue,
            Babbage(BabbageError::NegativeValue) => PreservationOfValue,
            _ => Unimplemented,
        }
    }
}

pub fn babbage_tx_to_cbor(tx: &BabbageTx) -> Vec<u8> {
    let mut tx_buf: Vec<u8> = Vec::new();
    let _ = encode(tx, &mut tx_buf);

    tx_buf
}

pub fn babbage_minted_tx_from_cbor(tx_cbor: &[u8]) -> BabbageMintedTx<'_> {
    pallas_codec::minicbor::decode::<BabbageMintedTx>(&tx_cbor[..]).unwrap()
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
