//! Implementation of Polkadot-friendly 28-byte hash `H224`
//!

use fixed_hash::{construct_fixed_hash, impl_fixed_hash_conversions};
use scale_info::TypeInfo;
use sp_core::H256;

construct_fixed_hash! {
    /// Fixed-size uninterpreted hash type with 28 bytes (224 bits) size.
    #[derive(TypeInfo)]
    pub struct H224(28);
}

mod serde {
    use super::H224;
    use impl_serde::impl_fixed_hash_serde;

    impl_fixed_hash_serde!(H224, 28);
}

mod codec {
    use super::H224;
    use impl_codec::impl_fixed_hash_codec;

    impl_fixed_hash_codec!(H224, 28);
}

mod rlp {
    use super::H224;
    use impl_rlp::impl_fixed_hash_rlp;

    impl_fixed_hash_rlp!(H224, 28);
}

impl_fixed_hash_conversions!(H256, H224);
