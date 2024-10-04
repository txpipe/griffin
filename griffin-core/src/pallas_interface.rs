use crate::types::*;
use sp_core::H256;
use pallas_codec::{
    minicbor::{
        encode, Decode, Decoder
    },
    utils::{
        Bytes, Nullable, // CborWrap, KeepRaw, KeyValuePairs, MaybeIndefArray,
    }
};
use pallas_crypto::hash::Hash as PallasHash;
use pallas_primitives::babbage::{
    DatumOption,
    // Mint as PallasMint,
    // Multiasset as PallasMultiasset,
    // PlutusData as PallasPlutusData,
    // PlutusV1Script as PallasPlutusV1Script,
    // PlutusV2Script as PallasPlutusV2Script,
    // PolicyId as PallasPolicyId,
    PostAlonzoTransactionOutput,
    // Redeemer as PallasRedeemer,
    Tx as PallasTransaction,
    TransactionBody as PallasTransactionBody,
    TransactionInput as PallasInput,
    TransactionOutput as PallasOutput,
    // VKeyWitness as PallasVKeyWitness,
    Value as PallasValue,
    WitnessSet as PallasWitnessSet,
};
use alloc::vec::Vec;
use core::{ops::Deref, default::Default};

impl From<Input> for PallasInput {
    fn from(val: Input) -> Self {
        Self {
            transaction_id: PallasHash::<32>::from(val.tx_hash.as_bytes()),
            index: val.index as u64,
        }
    }
}

impl From<PallasInput> for Input {
    fn from(val: PallasInput) -> Self {
        Self {
            tx_hash: H256::from(val.transaction_id.deref()),
            index: val.index as u32, // truncation
        }
    }
}

impl From<Output> for PostAlonzoTransactionOutput {
    fn from(val: Output) -> Self {
        // FIXME: Add error handling
        let datum_option: Option<DatumOption> = match val.datum_option {
            None => None,
            Some(d) => Decode::decode(&mut Decoder::new(d.0.as_slice()), &mut ()).unwrap(),
        };

        Self {
            address: Bytes::from(val.address.0),
            value: PallasValue::Coin(val.value),
            datum_option,
            script_ref: Default::default(),
        }
    }
}

impl From<PostAlonzoTransactionOutput> for Output {
    fn from(val: PostAlonzoTransactionOutput) -> Self {
        let value: Coin = match val.value {
            PallasValue::Coin(c) => c,
            _ => 0,
        };

        let mut datum_option: Option<Datum> = None;
        let mut datum: Vec<u8> = Vec::new();
        if let Some(data) = val.datum_option {
            match encode(&data, &mut datum) {
                Ok(_) =>  {
                    datum_option = Some(Datum(datum));
                },
                Err(err) => log::info!("Unable to encode datum ({:?})", err),
            };
        };
        
        Self {
            address: Address(Vec::from(val.address)),
            value,
            datum_option,
        }
    }
}

impl From<Output> for PallasOutput {
    fn from(val: Output) -> Self {
        PallasOutput::PostAlonzo(PostAlonzoTransactionOutput::from(val))
    }
}

impl From<PallasOutput> for Output {
    fn from(val: PallasOutput) -> Self {
        match val {
            PallasOutput::PostAlonzo(pat) => Output::from(pat),
            _ => todo!("Legacy (Alonzo) transactions not considered yet."),
        }
    }
}

impl From<WitnessSet> for PallasWitnessSet {
    fn from(val: WitnessSet) -> Self {
        // FIXME: Add error handling
        Decode::decode(&mut Decoder::new(val.0.as_slice()), &mut ()).unwrap()
    }
}

impl From<PallasWitnessSet> for WitnessSet {
    fn from(val: PallasWitnessSet) -> Self {
        let mut witnesses: Vec<u8> = Vec::new();
        
        match encode(&val, &mut witnesses) {
            Ok(_) =>  (),
            Err(err) => log::info!("Unable to encode witnesses ({:?})", err),
        }

        WitnessSet(witnesses)
    }
}

impl From<TransactionBody> for PallasTransactionBody {
    fn from(val: TransactionBody) -> Self {
        Self {
            inputs: val.inputs.into_iter().map(|i| PallasInput::from(i)).collect(),
            outputs: val.outputs.into_iter().map(|i| PallasOutput::from(i)).collect(),
            fee: 0,
            ttl: None,
            certificates: None,
            withdrawals: None,
            update: None,
            auxiliary_data_hash: None,
            validity_interval_start: None,
            mint: None,
            script_data_hash: None,
            collateral: None,
            required_signers: None,
            network_id: None,
            collateral_return: None,
            total_collateral: None,
            reference_inputs: None,
        }
    }
}

impl From<PallasTransactionBody> for TransactionBody {
    fn from(val: PallasTransactionBody) -> Self {
        Self {
            inputs: val.inputs.into_iter().map(|i| Input::from(i)).collect(),
            outputs: val.outputs.into_iter().map(|i| Output::from(i)).collect(),
        }
    }
}

impl From<Transaction> for PallasTransaction {
    fn from(val: Transaction) -> Self {
        Self {
            transaction_body: PallasTransactionBody::from(val.transaction_body),
            transaction_witness_set: PallasWitnessSet::from(val.transaction_witness_set),
            success: true,
            auxiliary_data: Nullable::Undefined,
        }
    }
}

impl From<PallasTransaction> for Transaction {
    fn from(val: PallasTransaction) -> Self {
        Self {
            transaction_body: TransactionBody::from(val.transaction_body),
            transaction_witness_set: WitnessSet::from(val.transaction_witness_set),
        }
    }
}

