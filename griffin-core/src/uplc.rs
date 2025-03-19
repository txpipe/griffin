pub mod ast;
pub mod builder;
pub mod builtins;
mod debruijn;
pub mod flat;
pub mod hamming;
pub mod machine;
pub mod optimize;
pub mod tx;

pub use crate::pallas_codec::utils::KeyValuePairs;
pub use crate::pallas_crypto::hash::Hash;
pub use crate::pallas_primitives::{
    alonzo::{BigInt, Constr, PlutusData},
    babbage::{PostAlonzoTransactionOutput, TransactionInput, TransactionOutput, Value},
    Error, Fragment,
};
pub use tx::redeemer_tag_to_string;

pub fn plutus_data(bytes: &[u8]) -> Result<PlutusData, Error> {
    PlutusData::decode_fragment(bytes)
}

pub fn plutus_data_to_bytes(data: &PlutusData) -> Result<alloc::vec::Vec<u8>, Error> {
    PlutusData::encode_fragment(data)
}
