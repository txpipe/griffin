use parity_scale_codec::{Decode, Encode};
use pallas_codec::minicbor::{
    self, Encoder, Decoder,
    decode::Error as MiniDecError,
    encode::Error as MiniEncError,
    encode::Write as MiniWrite,
    Decode as MiniDecode,
    Encode as MiniEncode,
};
use scale_info::TypeInfo;
use serde::{Deserialize, Serialize};
use sp_core::{
    H256,
    ed25519::Public,
};
use crate::h224::H224;
use sp_runtime::{
    traits::{BlakeTwo256, Extrinsic, Hash as HashT},
    transaction_validity::InvalidTransaction,
};
use alloc::{vec::Vec, collections::BTreeMap, string::String};
use core::{fmt, ops::Deref};
use pallas_crypto::hash::Hash as PallasHash;
use pallas_applying::utils::BabbageError;
use core::ops::{Add, AddAssign, Sub, SubAssign};

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

impl<'b, C> MiniDecode<'b, C> for Input {
    fn decode(
        d: &mut Decoder<'b>, ctx: &mut C
    ) -> Result<Self, MiniDecError> {
        d.tag()?;
        d.array()?;

        let tx_hash32: PallasHash::<32> = d.decode_with(ctx)?;
        Ok(Input {
            tx_hash: H256::from(tx_hash32.deref()),
            index: d.u32()?,
        })
    }
}

impl<C> MiniEncode<C> for Input {
    fn encode<W: MiniWrite>(
        &self,
        e: &mut Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), MiniEncError<W::Error>> {
        e.array(2)?;

        let tx_hash32 = PallasHash::<32>::from(self.tx_hash.as_bytes());
        e.encode_with(tx_hash32, ctx)?;
        e.u32(self.index)?;
        
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Eq, Clone, TypeInfo, Default, MiniEncode, MiniDecode)]
#[cbor(map)]
pub struct TransactionBody {
    #[n(0)]
    pub inputs: Vec<Input>,

    #[n(1)]
    pub outputs: Vec<Output>,

    #[n(9)]
    pub mint: Option<Mint>,
}

/// Hash of a 28-byte Cardano policy ID.
pub type PolicyId = H224;

impl<'b, C> MiniDecode<'b, C> for PolicyId {
    fn decode(
        d: &mut Decoder<'b>, ctx: &mut C
    ) -> Result<Self, MiniDecError> {
        let tx_hash28: PallasHash::<28> = d.decode_with(ctx)?;

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
#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Eq, Clone, TypeInfo, Default, PartialOrd, Ord, MiniEncode, MiniDecode)]
pub struct AssetName(#[n(0)] pub String);

/// `BTreeMap`, encapsulated in order to implement relevant traits.
#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Eq, Clone, TypeInfo, Default, PartialOrd, Ord, MiniEncode, MiniDecode)]
pub struct EncapBTree<K: Ord, V>(#[n(0)] pub BTreeMap<K, V>);

impl<K: Ord, V> EncapBTree<K, V> {
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }
}

/// Port of Cardano `Multiasset`s by using encapsulated `BTreeMap`s instead of
/// `KeyValuePairs`.
pub type Multiasset<A> = EncapBTree<PolicyId, EncapBTree<AssetName, A>>;

pub type Mint = Multiasset<i64>;

/// Port of Cardano `Value` using `BTreeMap`-based Multiassets
#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Eq, Clone, TypeInfo, MiniEncode, MiniDecode)]
pub enum Value {
    #[n(0)]
    Coin(#[n(0)] Coin),

    #[n(1)]
    Multiasset(#[n(0)] Coin, #[n(1)] Multiasset<Coin>),
}

/// Verification using public key and signature (both encoded as byte
/// sequences).
#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Eq, Clone, TypeInfo, Hash, MiniEncode, MiniDecode)]
pub struct VKeyWitness {
    #[n(0)]
    pub vkey: Vec<u8>,

    #[n(1)]
    pub signature: Vec<u8>,
}

#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Eq, Clone, TypeInfo, Hash, MiniEncode, MiniDecode)]
#[cbor(transparent)]
pub struct PlutusV1Script(#[n(0)] pub Vec<u8>);

#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Eq, Clone, TypeInfo, Hash, MiniEncode, MiniDecode)]
pub struct ExUnits {
    #[n(0)]
    pub mem: u64,
    #[n(1)]
    pub steps: u64,
}

#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Eq, Clone, TypeInfo, Hash, MiniEncode, MiniDecode)]
#[cbor(index_only)]
pub enum RedeemerTag {
    #[n(0)]
    Spend,
    #[n(1)]
    Mint,
    // #[n(2)]
    // Cert,
    // #[n(3)]
    // Reward,
}

#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Eq, Clone, TypeInfo, Hash, PartialOrd, MiniEncode, MiniDecode)]
pub struct PlutusData(#[n(0)] pub Vec<u8>);

#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Eq, Clone, TypeInfo, Hash, MiniEncode, MiniDecode)]
pub struct Redeemer {
    #[n(0)]
    pub tag: RedeemerTag,

    #[n(1)]
    pub index: u32,

    #[n(2)]
    pub data: PlutusData,

    #[n(3)]
    pub ex_units: ExUnits,
}

/// Fragment of a Cardano witness set.
#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Eq, Clone, TypeInfo, Hash, MiniEncode, MiniDecode)]
#[cbor(map)]
pub struct WitnessSet {
    #[n(0)]
    pub vkeywitness: Option<Vec<VKeyWitness>>,

    #[n(3)]
    pub plutus_v1_script: Option<Vec<PlutusV1Script>>,
    
    #[n(5)]
    pub redeemer: Option<Vec<Redeemer>>,
    // 
    // #[n(6)]
    // pub plutus_v2_script: Option<Vec<PlutusV2Script>>,
}

impl Default for WitnessSet {
    fn default() -> Self {
        Self{ vkeywitness: None, plutus_v1_script: None, redeemer: None }
    }
}

impl From<Vec<VKeyWitness>> for WitnessSet {
    fn from(wits: Vec<VKeyWitness>) -> Self {
        Self{ vkeywitness: Some(wits), plutus_v1_script: None, redeemer: None }
    }
}

#[derive(Serialize, Deserialize, Default, Debug, PartialEq, Eq, Clone, TypeInfo, MiniEncode, MiniDecode)]
pub struct Transaction {
    #[n(0)]
    pub transaction_body: TransactionBody,

    #[n(1)]
    pub transaction_witness_set: WitnessSet,
}

// Manually implement Encode and Decode for the Transaction type
// so that its encoding is the same as an opaque Vec<u8>.
impl Encode for Transaction {
    fn encode_to<T: parity_scale_codec::Output + ?Sized>(&self, dest: &mut T) {
        let transaction_body = Encode::encode(&self.transaction_body);
        let transaction_witness_set = Encode::encode(&self.transaction_witness_set);

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

        Ok(Transaction { transaction_body, transaction_witness_set })
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
        use UTxOError::*;
        use InvalidTransaction::Custom;

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
                _ => Custom(255),
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
    fn encode<W: MiniWrite>(&self, e: &mut Encoder<W>, _: &mut C) -> Result<(), MiniEncError<W::Error>> {
        e.bytes(&self.0)?.ok()
    }
}

/// Fake data to be decoded from the Datum.
#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Eq, Clone, TypeInfo, MiniEncode, MiniDecode)]
pub enum FakeDatum {
    #[n(0)]
    CuteOutput,

    #[n(1)]
    UglyOutput,
}

/// Bytes of a Cardano address.
#[derive(Serialize, Deserialize, Encode, Decode, PartialEq, Eq, Clone, TypeInfo, Hash)]
pub struct Address(pub Vec<u8>);

impl<C> MiniDecode<'_, C> for Address {
    fn decode(d: &mut Decoder<'_>, _: &mut C) -> Result<Self, MiniDecError> {
        d.bytes().map(|xs| Self(xs.to_vec()))
    }
}

impl<C> MiniEncode<C> for Address {
    fn encode<W: MiniWrite>(&self, e: &mut Encoder<W>, _: &mut C) -> Result<(), MiniEncError<W::Error>> {
        e.bytes(&self.0)?.ok()
    }
}

/// Transaction outputs.
#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Eq, Clone, TypeInfo, MiniEncode, MiniDecode)]
pub struct Output {
    #[n(0)]
    pub address: Address,

    #[n(1)]
    pub value: Value,

    #[n(2)]
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
        Self { address: a_c.0, value: Value::Coin(a_c.1), datum_option: None }
    }
}

impl From<(Address, Value)> for Output {
    fn from((address, value): (Address, Value)) -> Self {
        Self { address, value, datum_option: None }
    }
}

impl From<(Address, Coin, Datum)> for Output {
    fn from(a_c_d: (Address, Coin, Datum)) -> Self {
        Self { address: a_c_d.0, value: Value::Coin(a_c_d.1), datum_option: Some(a_c_d.2) }
    }
}

impl From<(Address, Value, Datum)> for Output {
    fn from((address, value, datum): (Address, Value, Datum)) -> Self {
        Self { address, value, datum_option: Some(datum) }
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
            transaction_body: TransactionBody
            {
                inputs,
                outputs,
                mint: None,
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
    use pallas_crypto::hash::{Hasher as PallasHasher};
    
    let mut keyhash_with_header: Vec<u8> = alloc::vec![0x61];
    let mut keyhash: Vec<u8>  = PallasHasher::<224>::hash(&pk.0).to_vec();
    keyhash_with_header.append(&mut keyhash);
    
    Address(keyhash_with_header)
}

/// Addition of `Value`s
impl<K: Ord + Clone, V: Add<Output = V> + Clone> Add for EncapBTree::<K, V> {
    type Output = Self;
    
    fn add(self, other: Self) -> Self {
        let mut res = EncapBTree::<K, V>::new();

        for (k, v) in self.0.into_iter() {
            res.0.insert(k.clone(),
                         other.0.get(&k).map_or(v.clone(), |w| v.clone() + w.clone()),
            );
        }

        res
    }
}

impl Add for Value {
    type Output = Self;
    
    fn add(self, other: Self) -> Self {
        use Value::*;
        
        match self {
            Coin(c) => match other {
                Coin(d)          => Coin(c+d),
                Multiasset(d, ma) => Multiasset(c+d, ma),
            },
            Multiasset(c, ma) => match other {
                Coin(d)          => Multiasset(c+d, ma),
                Multiasset(d, mb) => Multiasset(c+d, ma+mb),
            },
        }
    }
}

impl AddAssign for Value {
    fn add_assign(&mut self, other: Self) {
        *self = self.clone() + other;
    }
}

/// Subtraction of Values
impl<K: Ord + Clone, V: Sub<Output = V> + Clone> Sub for EncapBTree::<K, V> {
    type Output = Self;
    
    fn sub(self, other: Self) -> Self {
        let mut res = EncapBTree::<K, V>::new();

        for (k, v) in self.0.into_iter() {
            res.0.insert(k.clone(),
                         other.0.get(&k).map_or(v.clone(), |w| v.clone() - w.clone()),
            );
        }

        res
    }
}

impl Sub for Value {
    type Output = Self;
    
    fn sub(self, other: Self) -> Self {
        use Value::*;
        
        match self {
            Coin(c) => match other {
                Coin(d)          => Coin(c-d),
                Multiasset(d, ma) => Multiasset(c-d, ma),
            },
            Multiasset(c, ma) => match other {
                Coin(d)          => Multiasset(c-d, ma),
                Multiasset(d, mb) => Multiasset(c-d, ma-mb),
            },
        }
    }
}

impl SubAssign for Value {
    fn sub_assign(&mut self, other: Self) {
        *self = self.clone() - other;
    }
}

impl Multiasset<Coin> {
    pub fn is_null(self) -> bool {
        self.0
            .into_iter()
            .all(|(_, v)| v.0.into_iter().all(|(_, c)| c == 0))
    }
}

impl Value {
    pub fn is_null(self) -> bool {
        use Value::*;
        match self {
            Coin(c) => c == 0,
            Multiasset(c,ma) => (c == 0) & ma.is_null(),
        }
    }
}

impl From<String> for AssetName {
    fn from(string: String) -> Self {
        Self(string)
    }
}
