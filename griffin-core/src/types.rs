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
use sp_core::H256;
use crate::h224::H224;
use sp_runtime::{
    traits::{BlakeTwo256, Extrinsic, Hash as HashT},
    transaction_validity::InvalidTransaction,
};
use alloc::{vec::Vec, collections::BTreeMap};
use core::{fmt, ops::Deref};
use pallas_crypto::hash::Hash as PallasHash;

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
}

/// Hash of a 28-byte Cardano policy ID.
#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Eq, Clone, TypeInfo, Default, PartialOrd, Ord)]
pub struct PolicyId(pub H224);

impl<'b, C> MiniDecode<'b, C> for PolicyId {
    fn decode(
        d: &mut Decoder<'b>, ctx: &mut C
    ) -> Result<Self, MiniDecError> {
        let tx_hash28: PallasHash::<28> = d.decode_with(ctx)?;

        Ok(PolicyId(H224::from(tx_hash28.deref())))
    }
}

impl<C> MiniEncode<C> for PolicyId {
    fn encode<W: MiniWrite>(
        &self,
        e: &mut Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), MiniEncError<W::Error>> {
        let tx_hash28 = PallasHash::<28>::from(&self.0.as_bytes()[0..27]);
        e.encode_with(tx_hash28, ctx)?;

        Ok(())
    }
}


/// Name of a Cardano asset as byte sequence.
#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Eq, Clone, TypeInfo, Default, PartialOrd, Ord, MiniEncode, MiniDecode)]
pub struct AssetName(#[n(0)] pub Vec<u8>);

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

/// Bytes of a Cardano witness set.
#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Eq, Clone, TypeInfo, Hash)]
pub struct WitnessSet(pub Vec<u8>);

impl Default for WitnessSet {
    fn default() -> Self {
        Self(alloc::vec![0xA0])
    }
}


impl<C> MiniDecode<'_, C> for WitnessSet {
    fn decode(d: &mut Decoder<'_>, _: &mut C) -> Result<Self, MiniDecError> {
        d.bytes().map(|xs| Self(xs.to_vec()))
    }
}

impl<C> MiniEncode<C> for WitnessSet {
    fn encode<W: MiniWrite>(&self, e: &mut Encoder<W>, _: &mut C) -> Result<(), MiniEncError<W::Error>> {
        e.bytes(&self.0)?.ok()
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

#[derive(Debug, PartialEq, Eq)]
pub enum UtxoError {
    /// This transaction defines the same input multiple times
    DuplicateInput,
    /// This transaction defines an output that already existed in the UTXO set
    PreExistingOutput,
    MissingInput,
    /// The transaction has no inputs
    NoInputs,
}

// `UtxoError`s are mapped to Substrate errors.
impl From<UtxoError> for InvalidTransaction {
    fn from(utxo_error: UtxoError) -> Self {
        match utxo_error {
            UtxoError::DuplicateInput => InvalidTransaction::Custom(255),
            UtxoError::PreExistingOutput => InvalidTransaction::Custom(254),
            UtxoError::NoInputs => InvalidTransaction::Custom(253),
            UtxoError::MissingInput => InvalidTransaction::Future,
        }
    }
}

/// The Result of dispatching a UTXO transaction.
pub type DispatchResult = Result<(), UtxoError>;

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

// TODO: Upgrade to Value
impl From<(Address, Coin)> for Output {
    fn from(a_c: (Address, Coin)) -> Self {
        Self { address: a_c.0, value: Value::Coin(a_c.1), datum_option: None }
    }
}

// TODO: Upgrade to Value
impl From<(Address, Coin, Datum)> for Output {
    fn from(a_c_d: (Address, Coin, Datum)) -> Self {
        Self { address: a_c_d.0, value: Value::Coin(a_c_d.1), datum_option: Some(a_c_d.2) }
    }
}

impl From<Vec<u8>> for Datum {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl From<(Vec<Input>, Vec<Output>)> for Transaction {
    fn from(i_o: (Vec<Input>, Vec<Output>)) -> Self {
        Self {
            transaction_body: TransactionBody
            {
                inputs: i_o.0,
                outputs: i_o.1,
            },
            transaction_witness_set: WitnessSet::default(),
        }
    }
}
