//! Interface between Griffin and Pallas Transaction type.

use crate::{types::*, H224};
use sp_core::H256;
use pallas_codec::{
    minicbor::{
        encode, Decode, Decoder
    },
    utils::{
        Bytes, Nullable, KeyValuePairs, // CborWrap, KeepRaw, MaybeIndefArray,
    }
};
use pallas_crypto::hash::Hash as PallasHash;
use pallas_primitives::babbage::{
    AssetName as PallasAssetName,
    DatumOption,
    Multiasset as PallasMultiasset,
    // PlutusData as PallasPlutusData,
    // PlutusV1Script as PallasPlutusV1Script,
    // PlutusV2Script as PallasPlutusV2Script,
    PolicyId as PallasPolicyId,
    PostAlonzoTransactionOutput,
    LegacyTransactionOutput,
    // Redeemer as PallasRedeemer,
    Tx as PallasTransaction,
    TransactionBody as PallasTransactionBody,
    TransactionInput as PallasInput,
    TransactionOutput as PallasOutput,
    VKeyWitness as PallasVKeyWitness,
    Value as PallasValue,
    WitnessSet as PallasWitnessSet,
};
use alloc::{vec::Vec, collections::BTreeMap};
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

impl From<PolicyId> for PallasPolicyId {
    fn from(val: PolicyId) -> Self {
        PallasHash::<28>::from(val.as_bytes())
    }
}

impl From<PallasPolicyId> for PolicyId {
    fn from(val: PallasPolicyId) -> Self {
        H224::from(val.deref())
    }
}

impl From<AssetName> for PallasAssetName {
    fn from(val: AssetName) -> Self {
        Bytes::from(val.0)
    }
}

impl From<PallasAssetName> for AssetName {
    fn from(val: PallasAssetName) -> Self {
        Self(Vec::from(val))
    }
}

impl<K: Clone + Ord, V: Clone> From<EncapBTree<K, V>> for KeyValuePairs<K, V> {
    fn from(val: EncapBTree<K, V>) -> Self {
        let res: KeyValuePairs<K, V> = <_>::from(val.0
                                                 .into_iter()
                                                 .collect::<Vec<_>>());
        res
    }
}

impl<K: Clone + Ord, V: Clone> From<KeyValuePairs<K, V>> for EncapBTree<K, V> {
    fn from(val: KeyValuePairs<K, V>) -> Self {
        let tree: BTreeMap<K, V> = <_>::from_iter(Vec::from(val).into_iter());

        Self(tree)
    }
}

impl<A: Clone> From<Multiasset<A>> for PallasMultiasset<A> {
    fn from(val: Multiasset<A>) -> Self {
        let mut res: Vec<(PallasPolicyId, KeyValuePairs<PallasAssetName, A>)> =
                      Vec::new();
        
        for (k, v) in val.0.into_iter() {
            res.push((<_>::from(k),
                      <_>::from(v
                                .0
                                .into_iter()
                                .map(|(k, v)| (<_>::from(k), v))
                                .collect::<Vec<_>>())))
        }

        KeyValuePairs::from(res)
    }
}

impl<A: Clone> From<PallasMultiasset<A>> for Multiasset<A> {
    fn from(val: PallasMultiasset<A>) -> Self {
        let mut res: Vec<(PolicyId, EncapBTree<AssetName, A>)> =
                      Vec::new();
        
        for (k, v) in val.iter() {
            res.push((PolicyId::from(k.clone()),
                      EncapBTree(<_>::from_iter(v.clone()
                                          .iter()
                                          .map(|(k, v)| (<_>::from(k.clone()), v.clone()))))))
        }

        EncapBTree(<_>::from_iter(res.into_iter()))
    }
}

impl From<Value> for PallasValue {
    fn from(val: Value) -> Self {
        match val {
            Value::Coin(c) => Self::Coin(c),
            Value::Multiasset(c, m) => Self::Multiasset(c, <_>::from(m)),
        }
    }
}

impl From<PallasValue> for Value {
    fn from(val: PallasValue) -> Self {
        match val {
            PallasValue::Coin(c) => Self::Coin(c),
            PallasValue::Multiasset(c, m) => Self::Multiasset(c, <_>::from(m)),
        }
    }
}

impl From<Output> for PostAlonzoTransactionOutput {
    fn from(val: Output) -> Self {
        // FIXME: Add error handling
        let datum_option: Option<DatumOption> = val.datum_option.map(
            |d| Decode::decode(&mut Decoder::new(d.0.as_slice()), &mut ()).unwrap()
        );
        
        Self {
            address: <_>::from(val.address.0),
            value: <_>::from(val.value),
            datum_option,
            script_ref: Default::default(),
        }
    }
}

impl From<PostAlonzoTransactionOutput> for Output {
    fn from(val: PostAlonzoTransactionOutput) -> Self {
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
            value: Value::from(val.value),
            datum_option,
        }
    }
}

impl From<LegacyTransactionOutput> for Output {
    fn from(val: LegacyTransactionOutput) -> Self {
        let mut datum_option: Option<Datum> = None;
        let mut datum: Vec<u8> = Vec::new();
        if let Some(data) = val.datum_hash {
            match encode(&data, &mut datum) {
                Ok(_) =>  {
                    datum_option = Some(Datum(datum));
                },
                Err(err) => log::info!("Unable to encode datum ({:?})", err),
            };
        };
        
        Self {
            address: Address(Vec::from(val.address)),
            value: Value::from(val.amount),
            datum_option,
        }
    }
}

impl From<Output> for PallasOutput {
    fn from(val: Output) -> Self {
        PallasOutput::PostAlonzo(<_>::from(val))
    }
}

impl From<PallasOutput> for Output {
    fn from(val: PallasOutput) -> Self {
        match val {
            PallasOutput::PostAlonzo(pat) => Output::from(pat),
            PallasOutput::Legacy(leg) => Output::from(leg),
        }
    }
}

impl From<VKeyWitness> for PallasVKeyWitness {
    fn from(val: VKeyWitness) -> Self {
        Self{
            vkey: Bytes::from(val.vkey),
            signature: Bytes::from(val.signature),
        }
    }
}

impl From<PallasVKeyWitness> for VKeyWitness {
    fn from(val: PallasVKeyWitness) -> Self {
        Self{
            vkey: Vec::from(val.vkey),
            signature: Vec::from(val.signature),
        }
    }
}

impl From<WitnessSet> for PallasWitnessSet {
    fn from(val: WitnessSet) -> Self {
        let vkeywitness: Option<Vec<PallasVKeyWitness>> =
            val
            .vkeywitness
            .map(
                |vks| vks.into_iter().map(|vk| <_>::from(vk)).collect());
        Self {
            vkeywitness,
            native_script: None,
            bootstrap_witness: None,
            plutus_v1_script: None,
            plutus_data: None,
            redeemer: None,
            plutus_v2_script: None,
        }
    }
}

impl From<PallasWitnessSet> for WitnessSet {
    fn from(val: PallasWitnessSet) -> Self {
        Self {
            vkeywitness: val.vkeywitness
                .map(|v| v.into_iter().map(|y| <_>::from(y)).collect())
        }
    }
}

impl From<TransactionBody> for PallasTransactionBody {
    fn from(val: TransactionBody) -> Self {
        Self {
            inputs: val.inputs.into_iter().map(|i| <_>::from(i)).collect(),
            outputs: val.outputs.into_iter().map(|i| <_>::from(i)).collect(),
            fee: 0,
            ttl: None,
            certificates: None,
            withdrawals: None,
            update: None,
            auxiliary_data_hash: None,
            validity_interval_start: None,
            mint: val.mint.map(|m| PallasMultiasset::from(m)),
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
            mint: val.mint.map(|m| Multiasset::from(m)),
        }
    }
}

impl From<Transaction> for PallasTransaction {
    fn from(val: Transaction) -> Self {
        Self {
            transaction_body: <_>::from(val.transaction_body),
            transaction_witness_set: <_>::from(val.transaction_witness_set),
            success: true,
            auxiliary_data: Nullable::Undefined,
        }
    }
}

impl From<PallasTransaction> for Transaction {
    fn from(val: PallasTransaction) -> Self {
        Self {
            transaction_body: <_>::from(val.transaction_body),
            transaction_witness_set: <_>::from(val.transaction_witness_set),
        }
    }
}

