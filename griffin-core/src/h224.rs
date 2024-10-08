//! Implementation of Polkadot-friendly 28-byte hash `H224`
//!

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(all(not(feature = "std"), any(feature = "serde_no_std", feature = "json-schema")))]
extern crate alloc;

#[cfg(feature = "fp-conversion")]
mod fp_conversion;
#[cfg(feature = "json-schema")]
mod json_schema;

use fixed_hash::{construct_fixed_hash, impl_fixed_hash_conversions};
#[cfg(feature = "scale-info")]
use scale_info_crate::TypeInfo;
use sp_core::H256;

construct_fixed_hash! {
    /// Fixed-size uninterpreted hash type with 28 bytes (224 bits) size.
    #[cfg_attr(feature = "scale-info", derive(TypeInfo))]
    pub struct H224(28);
}
#[cfg(feature = "impl-serde")]
mod serde {
    use super::*;
    use impl_serde::{impl_fixed_hash_serde, impl_uint_serde};
    
    impl_fixed_hash_serde!(H224, 28);
}

#[cfg(feature = "impl-codec")]
mod codec {
    use super::*;
    use impl_codec::{impl_fixed_hash_codec, impl_uint_codec};
    
    impl_fixed_hash_codec!(H224, 28);
}

#[cfg(feature = "impl-rlp")]
mod rlp {
    use super::*;
    use impl_rlp::{impl_fixed_hash_rlp, impl_uint_rlp};

    impl_fixed_hash_rlp!(H224, 28);
}

impl_fixed_hash_conversions!(H256, H224);

