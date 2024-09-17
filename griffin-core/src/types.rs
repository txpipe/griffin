use parity_scale_codec::{Decode, Encode};
use scale_info::TypeInfo;
use serde::{Deserialize, Serialize};
use sp_core::H256;
use sp_runtime::{
    traits::{BlakeTwo256, Extrinsic, Hash as HashT},
    transaction_validity::InvalidTransaction,
};
use sp_std::vec::Vec;

pub type Coin = u64;

// All Griffin chains use the same BlakeTwo256 hash.
pub type Hash = BlakeTwo256;
/// Opaque block hash type.
pub type OpaqueHash = <Hash as HashT>::Output;
/// All Griffin chains use the same u32 BlockNumber.
pub type BlockNumber = u32;
/// Because all griffin chains use the same Blocknumber and Hash types,
/// they also use the same concrete header type.
pub type Header = sp_runtime::generic::Header<BlockNumber, Hash>;
/// An alias for a Griffin block with all the common parts filled in.
pub type Block = sp_runtime::generic::Block<Header, Transaction>;
/// Opaque block type. It has a Standard Griffin header, and opaque transactions.
pub type OpaqueBlock = sp_runtime::generic::Block<Header, sp_runtime::OpaqueExtrinsic>;

/// A reference to an output that is expected to exist in the state.
#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Eq, Clone, TypeInfo)]
pub struct OutputRef {
    /// A hash of the transaction that created this output
    pub tx_hash: H256,
    /// The index of this output among all outputs created by the same transaction
    pub index: u32,
}

#[derive(Serialize, Deserialize, Default, Debug, PartialEq, Eq, Clone, TypeInfo)]
pub struct Transaction {
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
}

// Manually implement Encode and Decode for the Transaction type
// so that its encoding is the same as an opaque Vec<u8>.
impl Encode for Transaction {
    fn encode_to<T: parity_scale_codec::Output + ?Sized>(&self, dest: &mut T) {
        let inputs = self.inputs.encode();
        let outputs = self.outputs.encode();

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

        let inputs = <Vec<Input>>::decode(input)?;
        let outputs = <Vec<Output>>::decode(input)?;

        Ok(Transaction { inputs, outputs })
    }
}

// We must implement this Extrinsic trait to use our Transaction type as the Block's associated Extrinsic type.
// See https://paritytech.github.io/polkadot-sdk/master/sp_runtime/traits/trait.Block.html#associatedtype.Extrinsic
//
// This trait's design has a preference for transactions that will have a single signature over the
// entire transaction, so it is not very useful for us. We still need to implement it to satisfy the bound,
// so we do a minimal implementation.
impl Extrinsic for Transaction {
    type Call = Self;
    type SignaturePayload = ();

    fn new(data: Self, _: Option<Self::SignaturePayload>) -> Option<Self> {
        Some(data)
    }

    // The signature on this function is not the best. Ultimately it is
    // trying to distinguish between three potential types of transactions:
    // 1. Signed user transactions: `Some(true)`
    // 2. Unsigned user transactions: `None`
    // 3. Unsigned inherents: `Some(false)`
    //
    // In Substrate generally, and also in FRAME, all three of these could exist.
    // But in Griffin we will never have signed user transactions, and therefore
    // will never return `Some(true)`.
    //
    // Perhaps a dedicated enum makes more sense as the return type?
    // That would be a Substrate PR after this is more tried and true.
    fn is_signed(&self) -> Option<bool> {
        None
    }
}

/// A reference to a utxo that will be consumed.
#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Eq, Clone, TypeInfo)]
pub struct Input {
    /// a reference to the output being consumed
    pub output_ref: OutputRef,
}

#[derive(Debug, PartialEq, Eq)]
pub enum UtxoError {
    /// This transaction defines the same input multiple times
    DuplicateInput,
    /// This transaction defines an output that already existed in the UTXO set
    PreExistingOutput,
    MissingInput,
}

// Substrate requires this supposedly reusable error type, but it is actually tied pretty tightly
// to the accounts model and some specific FRAME signed extensions. We map it the best we can.
impl From<UtxoError> for InvalidTransaction {
    fn from(utxo_error: UtxoError) -> Self {
        match utxo_error {
            UtxoError::DuplicateInput => InvalidTransaction::Custom(255),
            UtxoError::PreExistingOutput => InvalidTransaction::Custom(254),
            UtxoError::MissingInput => InvalidTransaction::Future,
        }
    }
}

/// The Result of dispatching a UTXO transaction.
pub type DispatchResult = Result<(), UtxoError>;

/// An opaque piece of Transaction output data. This is how the data appears at the Runtime level.
#[derive(Serialize, Deserialize, Encode, Decode, Debug, PartialEq, Eq, Clone, TypeInfo)]
pub struct Output {
    pub payload: Coin,
    pub owner: H256,
}

impl From<(Coin, H256)> for Output {
    fn from(p_o: (Coin, H256)) -> Self {
        Self { payload: p_o.0, owner:p_o.1 }
    }
}
