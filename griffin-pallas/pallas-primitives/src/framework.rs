
// pub type Error = Box<dyn std::error::Error>;

use pallas_codec::minicbor::{decode, to_vec, Decode, Encode};

// no std:
pub type Error = Box<dyn core::error::Error>;
use alloc::vec::Vec;
use alloc::boxed::Box;
use crate::alloc::string::ToString;

pub trait Fragment<'a>
where
    Self: Sized,
{
    fn encode_fragment(&self) -> Result<Vec<u8>, Error>;
    fn decode_fragment(bytes: &'a [u8]) -> Result<Self, Error>;
}

impl<'a, T> Fragment<'a> for T
where
    T: Encode<()> + Decode<'a, ()> + Sized,
{
    fn encode_fragment(&self) -> Result<Vec<u8>, Error> {
        // FRANCO: THIS IS BROKEN!!
        // the trait `core::error::Error` is not implemented for 
        //   `pallas_codec::minicbor::encode::Error<Infallible>`, which is required by 
        //   `pallas_codec::minicbor::encode::Error<Infallible>: Into<_>`
        // map_err: if to_vec returns error result, apply this function
        // e :: Error<Infallible>
        // e.into() :: Error = Box<dyn core::error::Error>
        // to_vec(self).map_err(|e| e.into())
        to_vec(self).map_err(|e| (e.to_string()).into())
    }

    fn decode_fragment(bytes: &'a [u8]) -> Result<Self, Error> {
        // FRANCO: THIS IS BROKEN!!
        // the trait `core::error::Error` is not implemented for 
        //   `pallas_codec::minicbor::decode::Error`, which is required by 
        //   `pallas_codec::minicbor::decode::Error: Into<_>`
        // e :: Error
        // e.into() :: Error = Box<dyn core::error::Error>
        // decode(bytes).map_err(|e| e.into())
        decode(bytes).map_err(|e| (e.to_string()).into())
    }
}

#[cfg(feature = "json")]
pub trait ToCanonicalJson {
    fn to_json(&self) -> serde_json::Value;
}
