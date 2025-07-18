//! Interface between Griffin and Pallas Transaction types.
use crate::pallas_codec::{
    minicbor::{encode, Decode, Decoder},
    utils::{
        Bytes, CborWrap, KeyValuePairs, MaybeIndefArray, NonEmptyKeyValuePairs,
        NonEmptySet as PallasNonEmptySet, NonZeroInt as PallasNonZeroInt, Nullable,
    },
};
use crate::pallas_crypto::hash::Hash as PallasHash;
use crate::pallas_primitives::alonzo::{Multiasset as LegacyMultiasset, Value as LegacyValue};
use crate::pallas_primitives::conway::{
    AssetName as PallasAssetName, DatumOption, ExUnits as PallasExUnits, LegacyTransactionOutput,
    Multiasset as PallasMultiasset, PlutusData as PallasPlutusData,
    PlutusScript as PallasPlutusScript, PolicyId as PallasPolicyId, PostAlonzoTransactionOutput,
    PseudoDatumOption::Data, Redeemer as PallasRedeemer, RedeemerTag as PallasRedeemerTag,
    Redeemers as PallasRedeemers, TransactionBody as PallasTransactionBody,
    TransactionInput as PallasInput, TransactionOutput as PallasOutput, Tx as PallasTransaction,
    VKeyWitness as PallasVKeyWitness, Value as PallasValue, WitnessSet as PallasWitnessSet,
};
use crate::pallas_primitives::{AddrKeyhash, PositiveCoin};
use crate::{types::*, H224};
use alloc::{collections::BTreeMap, string::String, vec::Vec};
use core::{default::Default, ops::Deref};
use sp_core::H256;

type PallasRequiredSigner = AddrKeyhash;

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
        Bytes::from(Vec::<u8>::from(val.0.as_bytes()))
    }
}

impl From<PallasAssetName> for AssetName {
    fn from(val: PallasAssetName) -> Self {
        Self(String::from(val))
    }
}

impl<K: Clone + Ord, V: Clone> From<EncapBTree<K, V>> for KeyValuePairs<K, V> {
    fn from(val: EncapBTree<K, V>) -> Self {
        let res: KeyValuePairs<K, V> = <_>::from(val.0.into_iter().collect::<Vec<_>>());
        res
    }
}

impl<K: Clone + Ord, V: Clone> From<KeyValuePairs<K, V>> for EncapBTree<K, V> {
    fn from(val: KeyValuePairs<K, V>) -> Self {
        let tree: BTreeMap<K, V> = <_>::from_iter(Vec::from(val).into_iter());

        Self(tree)
    }
}

impl<A: Clone> From<Multiasset<A>> for LegacyMultiasset<A> {
    fn from(val: Multiasset<A>) -> Self {
        let mut res: Vec<(PallasPolicyId, KeyValuePairs<PallasAssetName, A>)> = Vec::new();

        for (k, v) in val.0.into_iter() {
            res.push((
                <_>::from(k),
                <_>::from(
                    v.0.into_iter()
                        .map(|(k, v)| (<_>::from(k), v))
                        .collect::<Vec<_>>(),
                ),
            ))
        }

        KeyValuePairs::from(res)
    }
}

impl<A: Clone> From<Multiasset<A>> for PallasMultiasset<A> {
    fn from(val: Multiasset<A>) -> Self {
        let mut res: Vec<(PallasPolicyId, NonEmptyKeyValuePairs<PallasAssetName, A>)> = Vec::new();

        for (k, v) in val.0.into_iter() {
            res.push((
                <_>::from(k),
                NonEmptyKeyValuePairs::try_from(
                    v.0.into_iter()
                        .map(|(k, v)| (<_>::from(k), v))
                        .collect::<Vec<_>>(),
                )
                .expect("Failed to convert to NonEmptyKeyValuePairs."),
            ))
        }

        NonEmptyKeyValuePairs::try_from(res).expect("Failed to convert to NonEmptyKeyValuePairs.")
    }
}

impl From<Multiasset<Coin>> for PallasMultiasset<PositiveCoin> {
    fn from(val: Multiasset<Coin>) -> Self {
        let mut res: Vec<(
            PallasPolicyId,
            NonEmptyKeyValuePairs<PallasAssetName, PositiveCoin>,
        )> = Vec::new();

        for (k, v) in val.0.into_iter() {
            res.push((
                <_>::from(k),
                NonEmptyKeyValuePairs::try_from(
                    v.0.into_iter()
                        .map(|(k, v)| (<_>::from(k), PositiveCoin::try_from(v).expect("Failed to convert Coin to PositiveCoin")))
                        .collect::<Vec<_>>(),
                )
                .expect("Failed to convert to NonEmptyKeyValuePairs."),
            ))
        }

        NonEmptyKeyValuePairs::try_from(res).expect("Failed to convert to NonEmptyKeyValuePairs.")
    }
}

impl From<Multiasset<NonZeroInt>> for PallasMultiasset<PallasNonZeroInt> {
    fn from(val: Multiasset<NonZeroInt>) -> Self {
        let mut res: Vec<(
            PallasPolicyId,
            NonEmptyKeyValuePairs<PallasAssetName, PallasNonZeroInt>,
        )> = Vec::new();

        for (k, v) in val.0.into_iter() {
            res.push((
                <_>::from(k),
                NonEmptyKeyValuePairs::try_from(
                    v.0.into_iter()
                        .map(|(k, v)| (<_>::from(k), PallasNonZeroInt::from(v)))
                        .collect::<Vec<_>>(),
                )
                .expect("Failed to convert to NonEmptyKeyValuePairs."),
            ))
        }

        NonEmptyKeyValuePairs::try_from(res).expect("Failed to convert to NonEmptyKeyValuePairs.")
    }
}

impl<A: Clone> From<LegacyMultiasset<A>> for Multiasset<A> {
    fn from(val: LegacyMultiasset<A>) -> Self {
        let mut res: Vec<(PolicyId, EncapBTree<AssetName, A>)> = Vec::new();

        for (k, v) in val.iter() {
            res.push((
                PolicyId::from(k.clone()),
                EncapBTree(<_>::from_iter(
                    v.clone()
                        .iter()
                        .map(|(k, v)| (<_>::from(k.clone()), v.clone())),
                )),
            ))
        }

        EncapBTree(<_>::from_iter(res.into_iter()))
    }
}

impl From<PallasMultiasset<PositiveCoin>> for Multiasset<Coin> {
    fn from(val: PallasMultiasset<PositiveCoin>) -> Self {
        let mut res: Vec<(PolicyId, EncapBTree<AssetName, Coin>)> = Vec::new();

        for (k, v) in val.iter() {
            res.push((
                PolicyId::from(k.clone()),
                EncapBTree(<_>::from_iter(
                    v.clone()
                        .iter()
                        .map(|(k, v)| (<_>::from(k.clone()), u64::from(v.clone()))),
                )),
            ))
        }

        EncapBTree(<_>::from_iter(res.into_iter()))
    }
}

impl From<PallasMultiasset<PallasNonZeroInt>> for Multiasset<NonZeroInt> {
    fn from(val: PallasMultiasset<PallasNonZeroInt>) -> Self {
        let mut res: Vec<(PolicyId, EncapBTree<AssetName, NonZeroInt>)> = Vec::new();

        for (k, v) in val.iter() {
            res.push((
                PolicyId::from(k.clone()),
                EncapBTree(<_>::from_iter(
                    v.clone()
                        .iter()
                        .map(|(k, v)| (<_>::from(k.clone()), NonZeroInt::from(v.clone()))),
                )),
            ))
        }

        EncapBTree(<_>::from_iter(res.into_iter()))
    }
}

impl<A: Clone> From<PallasMultiasset<A>> for Multiasset<A> {
    fn from(val: PallasMultiasset<A>) -> Self {
        let mut res: Vec<(PolicyId, EncapBTree<AssetName, A>)> = Vec::new();

        for (k, v) in val.iter() {
            res.push((
                PolicyId::from(k.clone()),
                EncapBTree(<_>::from_iter(
                    v.clone()
                        .iter()
                        .map(|(k, v)| (<_>::from(k.clone()), v.clone())),
                )),
            ))
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

impl From<LegacyValue> for Value {
    fn from(val: LegacyValue) -> Self {
        match val {
            LegacyValue::Coin(c) => Self::Coin(c),
            LegacyValue::Multiasset(c, m) => Self::Multiasset(c, <_>::from(m)),
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
        let datum_option: Option<DatumOption> = val.datum_option.map(|d| {
            Data(CborWrap(
                Decode::decode(&mut Decoder::new(d.0.as_slice()), &mut ()).unwrap(),
            ))
        });

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
                Ok(_) => {
                    datum_option = Some(Datum(datum));
                }
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
                Ok(_) => {
                    datum_option = Some(Datum(datum));
                }
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
        Self {
            vkey: Bytes::from(val.vkey),
            signature: Bytes::from(val.signature),
        }
    }
}

impl From<PallasVKeyWitness> for VKeyWitness {
    fn from(val: PallasVKeyWitness) -> Self {
        Self {
            vkey: Vec::from(val.vkey),
            signature: Vec::from(val.signature),
        }
    }
}

impl From<ExUnits> for PallasExUnits {
    fn from(ExUnits { mem, steps }: ExUnits) -> Self {
        Self { mem, steps }
    }
}

impl From<RedeemerTag> for PallasRedeemerTag {
    fn from(val: RedeemerTag) -> Self {
        match val {
            RedeemerTag::Spend => PallasRedeemerTag::Spend,
            RedeemerTag::Mint => PallasRedeemerTag::Mint,
        }
    }
}

impl From<PlutusData> for PallasPlutusData {
    fn from(data: PlutusData) -> Self {
        // FIXME: Add error handling
        Decode::decode(&mut Decoder::new(data.0.as_slice()), &mut ()).unwrap()
    }
}

impl From<PallasPlutusData> for PlutusData {
    fn from(data: PallasPlutusData) -> Self {
        let mut plutus_data: Vec<u8> = Vec::new();
        match encode(&data, &mut plutus_data) {
            Err(err) => log::error!("Unable to encode Plutus Data ({:?})", err),
            Ok(_) => (),
        };

        Self(plutus_data)
    }
}

impl From<Redeemer> for PallasRedeemer {
    fn from(Redeemer { tag, index, data }: Redeemer) -> Self {
        Self {
            tag: <_>::from(tag),
            index,
            ex_units: Default::default(),
            data: <_>::from(data),
        }
    }
}

impl From<WitnessSet> for PallasWitnessSet {
    fn from(val: WitnessSet) -> Self {
        let vkeywitness: Option<PallasNonEmptySet<PallasVKeyWitness>> =
            val.vkeywitness.map(|vks| {
                <_>::try_from(
                    vks.into_iter()
                        .map(|vk| <_>::from(vk.clone()))
                        .collect::<Vec<_>>(),
                )
                .unwrap()
            });
        let redeemer: Option<PallasRedeemers> = val.redeemer.map(|vks| {
            PallasRedeemers::List(MaybeIndefArray::Def(
                vks.into_iter().map(|vk| <_>::from(vk)).collect(),
            ))
        });
        let plutus_v2_script: Option<PallasNonEmptySet<PallasPlutusScript<2>>> =
            val.plutus_v2_script.map(|vks| {
                <_>::try_from(
                    vks.into_iter()
                        .map(|vk| PallasPlutusScript::<2>(<_>::from(vk.0.clone())))
                        .collect::<Vec<_>>(),
                )
                .unwrap()
            });
        let plutus_v3_script: Option<PallasNonEmptySet<PallasPlutusScript<3>>> =
            val.plutus_v3_script.map(|vks| {
                <_>::try_from(
                    vks.into_iter()
                        .map(|vk| PallasPlutusScript::<3>(<_>::from(vk.0.clone())))
                        .collect::<Vec<_>>(),
                )
                .unwrap()
            });
        Self {
            redeemer,
            vkeywitness,
            plutus_data: None,
            native_script: None,
            plutus_v1_script: None,
            plutus_v2_script,
            plutus_v3_script,
            bootstrap_witness: None,
        }
    }
}

impl From<PallasWitnessSet> for WitnessSet {
    fn from(val: PallasWitnessSet) -> Self {
        Self {
            vkeywitness: val.vkeywitness.map(|v| {
                <_>::try_from(
                    v.into_iter()
                        .map(|y| <_>::from(y.clone()))
                        .collect::<Vec<_>>(),
                )
                .unwrap()
            }),
            plutus_v2_script: None,
            plutus_v3_script: None,
            redeemer: None,
        }
    }
}

impl From<TransactionBody> for PallasTransactionBody {
    fn from(val: TransactionBody) -> Self {
        Self {
            inputs: <_>::from(
                val.inputs
                    .into_iter()
                    .map(|i| <_>::from(i))
                    .collect::<Vec<_>>(),
            ),
            outputs: val.outputs.into_iter().map(|i| <_>::from(i)).collect(),
            fee: 0,
            ttl: val.ttl,
            certificates: None,
            withdrawals: None,
            auxiliary_data_hash: None,
            validity_interval_start: val.validity_interval_start,
            mint: val.mint.map(|m| PallasMultiasset::from(m)),
            script_data_hash: None,
            collateral: None,
            required_signers: val.required_signers.map(|rss| {
                <_>::try_from(
                    rss.into_iter()
                        .map(|rs| PallasRequiredSigner::from(*rs))
                        .collect::<Vec<_>>(),
                )
                .unwrap()
            }),
            network_id: None,
            collateral_return: None,
            total_collateral: None,
            reference_inputs: None,
            donation: None,
            proposal_procedures: None,
            treasury_value: None,
            voting_procedures: None,
        }
    }
}

impl From<PallasTransactionBody> for TransactionBody {
    fn from(val: PallasTransactionBody) -> Self {
        Self {
            inputs: <_>::from(
                val.inputs
                    .into_iter()
                    .map(|i| Input::from(i.clone()))
                    .collect::<Vec<_>>(),
            ),
            outputs: val.outputs.into_iter().map(|i| Output::from(i)).collect(),
            ttl: val.ttl,
            validity_interval_start: val.validity_interval_start,
            mint: val.mint.map(|m| Multiasset::from(m)),
            required_signers: val.required_signers.map(|rss| {
                <_>::try_from(
                    rss.into_iter()
                        .map(|rs| RequiredSigner::from(*rs))
                        .collect::<Vec<_>>(),
                )
                .unwrap()
            }),
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
