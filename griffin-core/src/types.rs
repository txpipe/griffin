use parity_scale_codec::{Decode, Encode};
use pallas_codec::minicbor::{self, Decode as MiniDecode, Encode as MiniEncode};
use scale_info::TypeInfo;
use serde::{Deserialize, Serialize};
use sp_core::H256;
use sp_runtime::{
    traits::{BlakeTwo256, Extrinsic, Hash as HashT},
    transaction_validity::InvalidTransaction,
};
use alloc::{vec::Vec, string::ToString};
use core::{fmt, str::FromStr};
use pallas_crypto::hash::Hash as PallasHash;
use hex::FromHex;

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

/// A reference to an output that is expected to exist in the state.
#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Eq, Clone, TypeInfo)]
pub struct OutputRef {
    /// A hash of the transaction that created this output
    pub tx_hash: H256,
    /// The index of this output among all outputs created by the same transaction
    pub index: u32,
}

impl<'b, C> minicbor::decode::Decode<'b, C> for OutputRef {
    fn decode(
        d: &mut minicbor::Decoder<'b>, ctx: &mut C
    ) -> Result<Self, minicbor::decode::Error> {
        d.tag()?;
        d.array()?;

        let tx_hash32: PallasHash::<32> = d.decode_with(ctx)?;
        Ok(OutputRef {
            // FIXME: Find a neater way to do this.
            tx_hash: H256::from_slice(&<[u8; 32]>::from_hex(tx_hash32.to_string()).unwrap()),
            index: d.u32()?,
        })
    }
}

impl<C> minicbor::encode::Encode<C> for OutputRef {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.array(2)?;

        // FIXME: Find a neater way to do this.
        let tx_hash32 = PallasHash::<32>::from_str(&self.tx_hash.to_string()[..]).unwrap();
        e.encode_with(tx_hash32, ctx)?;
        e.u32(self.index)?;
        
        Ok(())
    }
}


/// Bytes of a Cardano witness set.
#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Eq, Clone, TypeInfo, Hash, Default)]
pub struct WitnessSet(pub Vec<u8>);

#[derive(Serialize, Deserialize, Default, Debug, PartialEq, Eq, Clone, TypeInfo, MiniEncode, MiniDecode)]
pub struct Transaction {
    #[n(0)]
    pub inputs: Vec<Input>,

    #[n(1)]
    pub outputs: Vec<Output>,

    // #[n(2)]
    // pub transaction_witness_set: WitnessSet,
}

// Manually implement Encode and Decode for the Transaction type
// so that its encoding is the same as an opaque Vec<u8>.
impl Encode for Transaction {
    fn encode_to<T: parity_scale_codec::Output + ?Sized>(&self, dest: &mut T) {
        let inputs = parity_scale_codec::Encode::encode(&self.inputs);
        let outputs = parity_scale_codec::Encode::encode(&self.outputs);

        let total_len = (inputs.len() + outputs.len()) as u32;
        let size = parity_scale_codec::Compact::<u32>(total_len).encode();

        dest.write(&size);
        dest.write(&inputs);
        dest.write(&outputs);
    }
}

impl Decode for Transaction {
    fn decode<I: parity_scale_codec::Input>(
        input: &mut I,
    ) -> Result<Self, parity_scale_codec::Error> {
        // Throw away the length of the vec. We just want the bytes.
        <parity_scale_codec::Compact<u32>>::skip(input)?;

        let inputs = <Vec<Input> as parity_scale_codec::Decode>::decode(input)?;
        let outputs = <Vec<Output> as parity_scale_codec::Decode>::decode(input)?;

        Ok(Transaction { inputs, outputs })
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

/// A reference to a utxo that will be consumed.
#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Eq, Clone, TypeInfo, MiniEncode, MiniDecode)]
pub struct Input {
    /// a reference to the output being consumed
    #[n(0)]
    pub output_ref: OutputRef,
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
#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Eq, Clone, TypeInfo, MiniEncode, MiniDecode)]
pub struct Datum(#[n(0)] pub Vec<u8>);

/// Fake data to be decoded from the Datum.
#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Eq, Clone, TypeInfo, MiniEncode, MiniDecode)]
pub enum FakeDatum {
    #[n(0)]
    CuteOutput,

    #[n(1)]
    UglyOutput,
}

/// Bytes of a Cardano address.
#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Eq, Clone, TypeInfo, Hash, MiniEncode, MiniDecode)]
pub struct Address(#[n(0)] pub Vec<u8>);

/// An opaque piece of Transaction output data. This is how the data appears at the Runtime level.
#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Eq, Clone, TypeInfo, MiniEncode, MiniDecode)]
pub struct Output {
    #[n(0)]
    pub address: Address,

    #[n(1)]
    pub value: Coin,

    #[n(2)]
    pub datum_option: Option<Datum>,
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0.as_slice()))
    }
}

impl From<(Address, Coin)> for Output {
    fn from(p_o: (Address, Coin)) -> Self {
        Self { address: p_o.0, value: p_o.1, datum_option: None }
    }
}

impl From<(Address, Coin, Datum)> for Output {
    fn from(p_o: (Address, Coin, Datum)) -> Self {
        Self { address: p_o.0, value: p_o.1, datum_option: Some(p_o.2) }
    }
}

impl From<Vec<u8>> for Datum {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}
