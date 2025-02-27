//! Types used to construct Griffin transactions.
use crate::h224::H224;
use crate::pallas_applying::utils::BabbageError;
use crate::pallas_codec::minicbor::{
    self, decode::Error as MiniDecError, encode::Error as MiniEncError, encode::Write as MiniWrite,
    Decode as MiniDecode, Decoder, Encode as MiniEncode, Encoder,
};
use crate::pallas_crypto::hash::Hash as PallasHash;
use crate::pallas_primitives::babbage::{
    PlutusData as PallasPlutusData, PlutusScript as PallasPlutusScript,
};
use alloc::{collections::BTreeMap, string::String, vec::Vec};
use core::ops::{Add, AddAssign, Sub, SubAssign};
use core::{fmt, ops::Deref};
use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;
use serde::{Deserialize, Serialize};
use sp_core::{ed25519::Public, H256};
use sp_runtime::{
    traits::{BlakeTwo256, Extrinsic, Hash as HashT},
    transaction_validity::InvalidTransaction,
};

pub type Coin = u64;

pub type Hash = BlakeTwo256;
pub type OpaqueHash = <Hash as HashT>::Output;
pub type BlockNumber = u32;
/// Because all griffin chains use the same Blocknumber and Hash types,
/// they also use the same concrete header type.
pub type Header = sp_runtime::generic::Header<BlockNumber, Hash>;
pub type Block = sp_runtime::generic::Block<Header, Transaction>;
/// Opaque block type. It has a Griffin header, and opaque transactions.
pub type OpaqueBlock = sp_runtime::generic::Block<Header, sp_runtime::OpaqueExtrinsic>;

/// A reference to a utxo that will be consumed.
#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Eq, Clone, TypeInfo)]
pub struct Input {
    /// A hash of the transaction that created this output
    pub tx_hash: H256,
    /// The index of this output among all outputs created by the same transaction
    pub index: u32,
}

pub type RequiredSigner = H224;

#[derive(
    Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Eq, Clone, TypeInfo, Default,
)]
pub struct TransactionBody {
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
    pub validity_interval_start: Option<u64>,
    pub mint: Option<Mint>,
    pub required_signers: Option<Vec<RequiredSigner>>,
}

/// Hash of a 28-byte Cardano policy ID.
pub type PolicyId = H224;

// TODO: Minicbor implementation needed for temporary `FakeDatum` struct.
impl<'b, C> MiniDecode<'b, C> for PolicyId {
    fn decode(d: &mut Decoder<'b>, ctx: &mut C) -> Result<Self, MiniDecError> {
        let tx_hash28: PallasHash<28> = d.decode_with(ctx)?;

        Ok(H224::from(tx_hash28.deref()))
    }
}

impl<C> MiniEncode<C> for PolicyId {
    fn encode<W: MiniWrite>(
        &self,
        e: &mut Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), MiniEncError<W::Error>> {
        let tx_hash28 = PallasHash::<28>::from(self.as_bytes());
        e.encode_with(tx_hash28, ctx)?;

        Ok(())
    }
}

/// Name of a Cardano asset as byte sequence.
// TODO: Mini traits needed to encode temporary `FakeDatum`
#[derive(
    Serialize,
    Deserialize,
    Encode,
    Decode,
    Debug,
    PartialEq,
    Eq,
    Clone,
    TypeInfo,
    Default,
    PartialOrd,
    Ord,
    MiniEncode,
    MiniDecode,
)]
pub struct AssetName(#[n(0)] pub String);

/// `BTreeMap`, encapsulated in order to implement relevant traits.
#[derive(
    Serialize,
    Deserialize,
    Encode,
    Decode,
    Debug,
    PartialEq,
    Eq,
    Clone,
    TypeInfo,
    Default,
    PartialOrd,
    Ord,
)]
pub struct EncapBTree<K: Ord, V>(pub BTreeMap<K, V>);

impl<K: Ord, V> EncapBTree<K, V> {
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }
}

/// Port of Cardano `Multiasset`s by using encapsulated `BTreeMap`s instead of
/// `KeyValuePairs`.
pub type Multiasset<A> = EncapBTree<PolicyId, EncapBTree<AssetName, A>>;

impl<T: Clone + fmt::Display> fmt::Display for Multiasset<T> {
    /// Displays a `Multiasset` as formatted list of triples.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut res = String::new();
        for (p, n, a) in Vec::from(self).iter() {
            res += &format!("  ({p}) {}: {a}\n", n.0);
        }
        res.pop(); // Remove the last newline.
        write!(f, "{res}")
    }
}

pub type Mint = Multiasset<i64>;

/// Port of Cardano `Value` using `BTreeMap`-based Multiassets
#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Eq, Clone, TypeInfo)]
pub enum Value {
    /// An amount of coins. `Coin(c)` is equivalent to
    /// `Multiasset(c, EncapBTree::new())` in value.
    Coin(Coin),

    /// A value consisting of a `Coin` amount and a map of tokens.
    Multiasset(Coin, Multiasset<Coin>),
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Value::*;

        match self {
            Coin(c) => write!(f, "{} Coins", c),
            Multiasset(c, ma) => write!(f, "{} Coins, Multiassets:\n{}", c, ma),
        }
    }
}

/// Verification using public key and signature (both encoded as byte
/// sequences).
#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Eq, Clone, TypeInfo, Hash)]
pub struct VKeyWitness {
    pub vkey: Vec<u8>,
    pub signature: Vec<u8>,
}

/// CBOR encoded Plutus Script.
#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Eq, Clone, TypeInfo, Hash)]
pub struct PlutusScript(pub Vec<u8>);

pub fn compute_plutus_v2_script_hash(script: PlutusScript) -> PolicyId {
    PolicyId::from(
        crate::pallas_applying::utils::compute_plutus_v2_script_hash(&PallasPlutusScript::<2>(
            <_>::from(script.0),
        )),
    )
}

#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Eq, Clone, TypeInfo, Hash)]
pub struct ExUnits {
    pub mem: u64,
    pub steps: u64,
}

/// Cardano-like redeemer tag.
///
/// We are not using the `Cert` nor the `Rewards`
/// variants.
#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Eq, Clone, TypeInfo, Hash)]
pub enum RedeemerTag {
    Spend,
    Mint,
}

#[derive(
    Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Eq, Clone, TypeInfo, Hash, PartialOrd,
)]
pub struct PlutusData(pub Vec<u8>);

#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Eq, Clone, TypeInfo, Hash)]
pub struct Redeemer {
    pub tag: RedeemerTag,
    pub index: u32,
    pub data: PlutusData,
    pub ex_units: ExUnits,
}

/// Fragment of a Cardano witness set.
#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Eq, Clone, TypeInfo, Hash)]
pub struct WitnessSet {
    pub vkeywitness: Option<Vec<VKeyWitness>>,
    pub redeemer: Option<Vec<Redeemer>>,
    pub plutus_script: Option<Vec<PlutusScript>>,
}

impl Default for WitnessSet {
    fn default() -> Self {
        Self {
            vkeywitness: None,
            plutus_script: None,
            redeemer: None,
        }
    }
}

impl From<Vec<VKeyWitness>> for WitnessSet {
    fn from(wits: Vec<VKeyWitness>) -> Self {
        Self {
            vkeywitness: Some(wits),
            plutus_script: None,
            redeemer: None,
        }
    }
}

/// Griffin transaction type. It is divided in a body and a witness set.
#[derive(Serialize, Deserialize, Default, Debug, PartialEq, Eq, Clone, TypeInfo)]
pub struct Transaction {
    pub transaction_body: TransactionBody,
    pub transaction_witness_set: WitnessSet,
}

// Manually implement Encode and Decode for the Transaction type
// so that its encoding is the same as an opaque Vec<u8>.
impl Encode for Transaction {
    fn encode_to<T: parity_scale_codec::Output + ?Sized>(&self, dest: &mut T) {
        let transaction_body = self.transaction_body.encode();
        let transaction_witness_set = self.transaction_witness_set.encode();

        let total_len = (transaction_body.len() + transaction_witness_set.len()) as u32;
        let size = parity_scale_codec::Compact::<u32>(total_len).encode();

        dest.write(&size);
        dest.write(&transaction_body);
        dest.write(&transaction_witness_set);
    }
}

impl Decode for Transaction {
    fn decode<I: parity_scale_codec::Input>(
        input: &mut I,
    ) -> Result<Self, parity_scale_codec::Error> {
        // Throw away the length of the vec. We just want the bytes.
        <parity_scale_codec::Compact<u32>>::skip(input)?;

        let transaction_body = <TransactionBody as Decode>::decode(input)?;
        let transaction_witness_set = <WitnessSet as Decode>::decode(input)?;

        Ok(Transaction {
            transaction_body,
            transaction_witness_set,
        })
    }
}

// We must implement this Extrinsic trait to use our Transaction type as the Block's associated Extrinsic type.
// See https://paritytech.github.io/polkadot-sdk/master/sp_runtime/traits/trait.Block.html#associatedtype.Extrinsic
impl Extrinsic for Transaction {
    type Call = Self;
    type SignaturePayload = ();

    fn new(data: Self, _: Option<Self::SignaturePayload>) -> Option<Self> {
        Some(data)
    }

    // Most probably, transactions will never need be signed, since UTxOs
    // require proof for consumption.
    fn is_signed(&self) -> Option<bool> {
        None
    }
}

/// Reasons to reject a transaction.
#[derive(Debug)]
pub enum UTxOError {
    /// A Babbage era validation error returned by Pallas.
    Babbage(BabbageError),
    /// No other kind of error should be received.
    Fail,
}

/// `UTxOError`s are mapped to custom Substrate errors.
impl From<UTxOError> for InvalidTransaction {
    fn from(utxo_error: UTxOError) -> Self {
        use BabbageError::*;
        use InvalidTransaction::Custom;
        use UTxOError::*;

        match utxo_error {
            Fail => Custom(32),
            Babbage(err) => match err {
                TxWrongNetworkID => Custom(64),
                OutputWrongNetworkID => Custom(65),
                BlockPrecedesValInt => Custom(128),
                BlockExceedsValInt => Custom(129),
                AddressDecoding => Custom(192),
                InputDecoding => Custom(193),
                MaxTxSizeExceeded => Custom(194),
                UnknownTxSize => Custom(195),
                DuplicateInput => Custom(196),
                TxInsEmpty => Custom(197),
                OutputAlreadyInUTxO => Custom(198),
                InputNotInUTxO => Custom(208),
                CollateralNotInUTxO => Custom(209),
                ReferenceInputNotInUTxO => Custom(210),
                RefInputNotInUTxO => Custom(211),
                CollateralMissing => Custom(212),
                TooManyCollaterals => Custom(213),
                CollateralNotVKeyLocked => Custom(214),
                CollateralMinLovelace => Custom(215),
                NonLovelaceCollateral => Custom(216),
                CollateralWrongAssets => Custom(217),
                CollateralAnnotation => Custom(218),
                FeeBelowMin => Custom(219),
                NegativeValue => Custom(220),
                PreservationOfValue => Custom(221),
                MinLovelaceUnreached => Custom(222),
                MaxValSizeExceeded => Custom(223),
                UnneededDatum => Custom(224),
                UnneededNativeScript => Custom(225),
                UnneededPlutusV1Script => Custom(226),
                UnneededPlutusV2Script => Custom(227),
                TxExUnitsExceeded => Custom(228),
                MintingLacksPolicy => Custom(229),
                MetadataHash => Custom(230),
                DatumMissing => Custom(231),
                UnsupportedPlutusLanguage => Custom(232),
                ScriptIntegrityHash => Custom(233),
                RedeemerMissing => Custom(240),
                ReqSignerMissing => Custom(241),
                VKWitnessMissing => Custom(242),
                ScriptWitnessMissing => Custom(243),
                UnneededRedeemer => Custom(244),
                ReqSignerWrongSig => Custom(245),
                VKWrongSignature => Custom(246),
                PhaseTwoValidationError => Custom(247),
            },
        }
    }
}

/// The Result of dispatching a UTXO transaction.
pub type DispatchResult = Result<(), UTxOError>;

/// Bytes of the Plutus Data.
#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Eq, Clone, TypeInfo)]
pub struct Datum(pub Vec<u8>);

// TODO: Write a macro for this and similar `impl`s of opaque data.
impl<C> MiniDecode<'_, C> for Datum {
    fn decode(d: &mut Decoder<'_>, _: &mut C) -> Result<Self, MiniDecError> {
        d.bytes().map(|xs| Self(xs.to_vec()))
    }
}

impl<C> MiniEncode<C> for Datum {
    fn encode<W: MiniWrite>(
        &self,
        e: &mut Encoder<W>,
        _: &mut C,
    ) -> Result<(), MiniEncError<W::Error>> {
        e.bytes(&self.0)?.ok()
    }
}

/// Sample data type to used to demonstrate {en,de}coding from the Datum.
#[derive(Debug, PartialEq, Eq, Clone, MiniEncode, MiniDecode)]
pub enum FakeDatum {
    #[n(0)]
    CuteOutput,

    #[n(1)]
    UglyOutput,

    #[n(2)]
    ReceiverValue(#[n(0)] PolicyId, #[n(1)] AssetName, #[n(2)] Coin),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AssetClass {
    pub policy_id: PolicyId,
    pub asset_name: AssetName,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum OrderDatum {
    Ok {
        sender_payment_hash: H224,
        ordered_class: AssetClass,
        ordered_amount: Coin,
    },
    MalformedOrderDatum,
}

impl From<OrderDatum> for Datum {
    fn from(order_datum: OrderDatum) -> Self {
        Datum(PlutusData::from(PallasPlutusData::from(order_datum)).0)
    }
}

impl From<Datum> for OrderDatum {
    fn from(datum: Datum) -> Self {
        <_>::from(PallasPlutusData::from(PlutusData(datum.0)))
    }
}

/// Bytes of a Cardano address.
#[derive(Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Clone, TypeInfo, Hash)]
pub struct Address(pub Vec<u8>);

/// Transaction outputs.
#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Eq, Clone, TypeInfo)]
pub struct Output {
    pub address: Address,
    pub value: Value,
    pub datum_option: Option<Datum>,
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0.as_slice()))
    }
}

// TODO: Is this reasonable? Should it be a more faithful repr?
impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0.as_slice()))
    }
}

impl From<(Address, Coin)> for Output {
    fn from(a_c: (Address, Coin)) -> Self {
        Self {
            address: a_c.0,
            value: Value::Coin(a_c.1),
            datum_option: None,
        }
    }
}

impl From<(Address, Value)> for Output {
    fn from((address, value): (Address, Value)) -> Self {
        Self {
            address,
            value,
            datum_option: None,
        }
    }
}

impl From<(Address, Coin, Datum)> for Output {
    fn from(a_c_d: (Address, Coin, Datum)) -> Self {
        Self {
            address: a_c_d.0,
            value: Value::Coin(a_c_d.1),
            datum_option: Some(a_c_d.2),
        }
    }
}

impl From<(Address, Value, Datum)> for Output {
    fn from((address, value, datum): (Address, Value, Datum)) -> Self {
        Self {
            address,
            value,
            datum_option: Some(datum),
        }
    }
}

impl From<(Address, Coin, Option<Datum>)> for Output {
    fn from((address, coin, datum_option): (Address, Coin, Option<Datum>)) -> Self {
        Self {
            address,
            value: Value::Coin(coin),
            datum_option,
        }
    }
}

impl From<(Address, Coin, Multiasset<Coin>, Option<Datum>)> for Output {
    fn from(
        (address, coin, ma, datum_option): (Address, Coin, Multiasset<Coin>, Option<Datum>),
    ) -> Self {
        Self {
            address,
            value: Value::Multiasset(coin, ma),
            datum_option,
        }
    }
}

impl From<(Address, Value, Option<Datum>)> for Output {
    fn from((address, value, datum_option): (Address, Value, Option<Datum>)) -> Self {
        Self {
            address,
            value,
            datum_option,
        }
    }
}

impl From<Vec<u8>> for Datum {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl From<Vec<u8>> for Address {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl From<(Vec<u8>, Vec<u8>)> for VKeyWitness {
    fn from((vkey, signature): (Vec<u8>, Vec<u8>)) -> Self {
        Self { vkey, signature }
    }
}

impl From<(Vec<Input>, Vec<Output>)> for Transaction {
    fn from((inputs, outputs): (Vec<Input>, Vec<Output>)) -> Self {
        Self {
            transaction_body: TransactionBody {
                inputs,
                outputs,
                validity_interval_start: None,
                mint: None,
                required_signers: None,
            },
            transaction_witness_set: WitnessSet::default(),
        }
    }
}

pub fn address_from_hex(hex: &str) -> Address {
    use hex::FromHex;

    Address(<Vec<u8>>::from_hex(hex).unwrap())
}

pub fn address_from_pk(pk: &Public) -> Address {
    use crate::pallas_crypto::hash::Hasher as PallasHasher;

    let mut keyhash_with_header: Vec<u8> = alloc::vec![0x61];
    let mut keyhash: Vec<u8> = PallasHasher::<224>::hash(&pk.0).to_vec();
    keyhash_with_header.append(&mut keyhash);

    Address(keyhash_with_header)
}

impl<A> From<(PolicyId, AssetName, A)> for Multiasset<A> {
    fn from((policy, name, amount): (PolicyId, AssetName, A)) -> Self {
        EncapBTree::<PolicyId, EncapBTree<AssetName, A>>(BTreeMap::from(
            [(
                policy,
                EncapBTree::<AssetName, A>(BTreeMap::from([(name, amount); 1])),
            ); 1],
        ))
    }
}

impl From<(PolicyId, AssetName, Coin)> for Value {
    fn from((policy, name, amount): (PolicyId, AssetName, Coin)) -> Self {
        Value::Multiasset(0, <_>::from((policy, name, amount)))
    }
}

impl From<(Coin, PolicyId, AssetName, Coin)> for Value {
    fn from((coin, policy, name, amount): (Coin, PolicyId, AssetName, Coin)) -> Self {
        Value::Multiasset(coin, <_>::from((policy, name, amount)))
    }
}

impl<K: Ord + Clone, V: Add<Output = V> + Clone> Add for EncapBTree<K, V> {
    type Output = Self;

    /// Coordinate-wise addition of `EncapBTree`s
    fn add(self, other: Self) -> Self {
        let mut res = other.clone();

        for (k, v) in self.0.into_iter() {
            res.0.insert(
                k.clone(),
                other.0.get(&k).map_or(v.clone(), |w| v.clone() + w.clone()),
            );
        }

        res
    }
}

impl Add for Value {
    type Output = Self;

    /// Coordinate-wise addition of `Value`s
    fn add(self, other: Self) -> Self {
        use Value::*;

        match self {
            Coin(c) => match other {
                Coin(d) => Coin(c + d),
                Multiasset(d, ma) => Multiasset(c + d, ma),
            },
            Multiasset(c, ma) => match other {
                Coin(d) => Multiasset(c + d, ma),
                Multiasset(d, mb) => Multiasset(c + d, ma + mb),
            },
        }
        .normalize()
    }
}

impl AddAssign for Value {
    fn add_assign(&mut self, other: Self) {
        *self = self.clone() + other;
    }
}

impl<K: Ord + Clone, V: Sub<Output = V> + Clone> Sub for EncapBTree<K, V> {
    type Output = Self;

    /// Coordinate-wise subtraction of `EncapBTree`s
    fn sub(self, other: Self) -> Self {
        let mut res = self.clone();

        for (k, v) in other.0.into_iter() {
            if let Some(w) = self.0.get(&k) {
                res.0.insert(k.clone(), w.clone() - v.clone());
            };
        }

        res
    }
}

impl Sub for Value {
    type Output = Self;

    /// Coordinate-wise subtraction of `Value`s
    fn sub(self, other: Self) -> Self {
        use Value::*;

        match self {
            Coin(c) => match other {
                Coin(d) => Coin(c - d),
                Multiasset(d, ma) => Multiasset(c - d, ma),
            },
            Multiasset(c, ma) => match other {
                Coin(d) => Multiasset(c - d, ma),
                Multiasset(d, mb) => Multiasset(c - d, ma - mb),
            },
        }
        .normalize()
    }
}

impl SubAssign for Value {
    fn sub_assign(&mut self, other: Self) {
        *self = self.clone() - other;
    }
}

/// Decides if the first multiasset is orderly smaller than or equal to the
/// second one. Useful before subtracting.
pub fn multiasset_leq(small: &Multiasset<Coin>, big: &Multiasset<Coin>) -> bool {
    for (pol, names_big) in big.0.iter() {
        if let Some(names_small) = small.0.get(pol) {
            for (name_big, amount_big) in names_big.0.iter() {
                if let Some(amount_small) = names_small.0.get(name_big) {
                    if amount_small > amount_big {
                        return false;
                    }
                }
            }
        }
    }
    for (pol, names_small) in small.0.iter() {
        if !big.0.contains_key(pol) {
            for (_, amount_small) in names_small.0.iter() {
                if *amount_small != 0 {
                    return false;
                }
            }
        }
    }

    true
}

/// Decides if the first `Value` is orderly smaller than or equal to the
/// second one. Useful before subtracting.
pub fn value_leq(small: &Value, big: &Value) -> bool {
    use Value::*;

    match small {
        Coin(c) => match big {
            Coin(d) => c <= d,
            Multiasset(d, _) => c <= d,
        },
        Multiasset(c, ma) => match big {
            Coin(d) => (c <= d) & ma.is_null(),
            Multiasset(d, mb) => (c <= d) & multiasset_leq(ma, mb),
        },
    }
}

impl Multiasset<Coin> {
    /// Decides if (each amount in) a [Multiasset] is null.
    pub fn is_null(&self) -> bool {
        self.0.iter().all(|(_, v)| v.0.iter().all(|(_, c)| *c == 0))
    }

    /// Puts a [Multiasset] in normal form, eliminating null amounts.
    pub fn normalize(&self) -> Self {
        let mut res = self.clone();
        for (pol, mut names) in res.clone().0.into_iter() {
            if !names.0.is_empty() {
                for (name, amount) in names.clone().0.into_iter() {
                    if amount == 0 {
                        names.0.remove(&name);
                    }
                }
            }
            // After the previous removal of names, we must re-check:
            if names.0.is_empty() {
                res.0.remove(&pol);
            }
        }
        res
    }
}

impl<T: Clone> From<&Multiasset<T>> for Vec<(PolicyId, AssetName, T)> {
    fn from(ma: &Multiasset<T>) -> Vec<(PolicyId, AssetName, T)> {
        let mut res = Vec::<(PolicyId, AssetName, T)>::new();
        for (pol, names) in ma.0.iter() {
            for (name, amount) in names.0.iter() {
                res.push((pol.clone(), name.clone(), amount.clone()));
            }
        }

        res
    }
}

impl Value {
    /// Decides if (each amount in) a [Value] is null.
    pub fn is_null(&self) -> bool {
        use Value::*;
        match self {
            Coin(c) => *c == 0,
            Multiasset(c, ma) => (*c == 0) & ma.is_null(),
        }
    }

    /// Puts a [Value] in normal form, eliminating null amounts.
    /// If it is of the form `Multiasset(c, ma)` with `ma` null, it is reduced
    /// to `Coin(c)`.
    pub fn normalize(&self) -> Self {
        use Value::*;
        match self {
            Multiasset(c, ma) => {
                if ma.is_null() {
                    Coin(*c)
                } else {
                    Multiasset(*c, ma.normalize())
                }
            }
            Coin(c) => Coin(*c),
        }
    }
}

impl From<String> for AssetName {
    fn from(string: String) -> Self {
        Self(string)
    }
}
