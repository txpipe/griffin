use crate::pallas_traverse::{ComputeHash, OriginalHash};
use crate::pallas_codec::utils::KeepRaw;
use crate::pallas_crypto::{
    hash::{Hash, Hasher},
    key::ed25519::PublicKey,
};
use crate::pallas_primitives::{alonzo, babbage, byron, conway};

impl ComputeHash<32> for byron::EbbHead {
    fn compute_hash(&self) -> Hash<32> {
        // hash expects to have a prefix for the type of block
        Hasher::<256>::hash_cbor(&(0, self))
    }
}

impl OriginalHash<32> for KeepRaw<'_, byron::EbbHead> {
    fn original_hash(&self) -> Hash<32> {
        // hash expects to have a prefix for the type of block
        Hasher::<256>::hash_cbor(&(0, self))
    }
}

impl ComputeHash<32> for byron::BlockHead {
    fn compute_hash(&self) -> Hash<32> {
        // hash expects to have a prefix for the type of block
        Hasher::<256>::hash_cbor(&(1, self))
    }
}

impl OriginalHash<32> for KeepRaw<'_, byron::BlockHead> {
    fn original_hash(&self) -> Hash<32> {
        // hash expects to have a prefix for the type of block
        Hasher::<256>::hash_cbor(&(1, self))
    }
}

impl ComputeHash<32> for byron::Tx {
    fn compute_hash(&self) -> Hash<32> {
        Hasher::<256>::hash_cbor(self)
    }
}

impl OriginalHash<32> for KeepRaw<'_, byron::Tx> {
    fn original_hash(&self) -> Hash<32> {
        Hasher::<256>::hash(self.raw_cbor())
    }
}

impl ComputeHash<32> for alonzo::Header {
    fn compute_hash(&self) -> crate::pallas_crypto::hash::Hash<32> {
        Hasher::<256>::hash_cbor(self)
    }
}

impl OriginalHash<32> for KeepRaw<'_, alonzo::Header> {
    fn original_hash(&self) -> crate::pallas_crypto::hash::Hash<32> {
        Hasher::<256>::hash(self.raw_cbor())
    }
}

impl ComputeHash<32> for alonzo::AuxiliaryData {
    fn compute_hash(&self) -> crate::pallas_crypto::hash::Hash<32> {
        Hasher::<256>::hash_cbor(self)
    }
}

impl ComputeHash<28> for alonzo::NativeScript {
    fn compute_hash(&self) -> Hash<28> {
        Hasher::<224>::hash_tagged_cbor(self, 0)
    }
}

impl OriginalHash<28> for KeepRaw<'_, alonzo::NativeScript> {
    fn original_hash(&self) -> Hash<28> {
        Hasher::<224>::hash_tagged(self.raw_cbor(), 0)
    }
}

impl ComputeHash<28> for alonzo::PlutusScript {
    fn compute_hash(&self) -> Hash<28> {
        Hasher::<224>::hash_tagged(&self.0, 1)
    }
}

impl ComputeHash<32> for alonzo::PlutusData {
    fn compute_hash(&self) -> Hash<32> {
        Hasher::<256>::hash_cbor(self)
    }
}

impl OriginalHash<32> for KeepRaw<'_, alonzo::PlutusData> {
    fn original_hash(&self) -> Hash<32> {
        Hasher::<256>::hash(self.raw_cbor())
    }
}

impl ComputeHash<32> for alonzo::TransactionBody {
    fn compute_hash(&self) -> Hash<32> {
        Hasher::<256>::hash_cbor(self)
    }
}

impl OriginalHash<32> for KeepRaw<'_, alonzo::TransactionBody> {
    fn original_hash(&self) -> crate::pallas_crypto::hash::Hash<32> {
        Hasher::<256>::hash(self.raw_cbor())
    }
}

impl ComputeHash<32> for babbage::Header {
    fn compute_hash(&self) -> crate::pallas_crypto::hash::Hash<32> {
        Hasher::<256>::hash_cbor(self)
    }
}

impl OriginalHash<32> for KeepRaw<'_, babbage::Header> {
    fn original_hash(&self) -> crate::pallas_crypto::hash::Hash<32> {
        Hasher::<256>::hash(self.raw_cbor())
    }
}

impl ComputeHash<28> for babbage::PlutusV2Script {
    fn compute_hash(&self) -> Hash<28> {
        Hasher::<224>::hash_tagged(&self.0, 2)
    }
}

impl ComputeHash<32> for babbage::TransactionBody {
    fn compute_hash(&self) -> Hash<32> {
        Hasher::<256>::hash_cbor(self)
    }
}

impl OriginalHash<32> for KeepRaw<'_, babbage::TransactionBody> {
    fn original_hash(&self) -> crate::pallas_crypto::hash::Hash<32> {
        Hasher::<256>::hash(self.raw_cbor())
    }
}

impl OriginalHash<32> for KeepRaw<'_, babbage::MintedTransactionBody<'_>> {
    fn original_hash(&self) -> crate::pallas_crypto::hash::Hash<32> {
        Hasher::<256>::hash(self.raw_cbor())
    }
}

impl ComputeHash<32> for babbage::DatumOption {
    fn compute_hash(&self) -> Hash<32> {
        match self {
            babbage::DatumOption::Hash(hash) => *hash,
            babbage::DatumOption::Data(data) => data.compute_hash(),
        }
    }
}

// conway

impl ComputeHash<28> for conway::PlutusV3Script {
    fn compute_hash(&self) -> Hash<28> {
        Hasher::<224>::hash_tagged(&self.0, 3)
    }
}

impl ComputeHash<32> for conway::TransactionBody {
    fn compute_hash(&self) -> Hash<32> {
        Hasher::<256>::hash_cbor(self)
    }
}

impl OriginalHash<32> for KeepRaw<'_, conway::TransactionBody> {
    fn original_hash(&self) -> crate::pallas_crypto::hash::Hash<32> {
        Hasher::<256>::hash(self.raw_cbor())
    }
}

impl OriginalHash<32> for KeepRaw<'_, conway::MintedTransactionBody<'_>> {
    fn original_hash(&self) -> crate::pallas_crypto::hash::Hash<32> {
        Hasher::<256>::hash(self.raw_cbor())
    }
}

impl ComputeHash<28> for PublicKey {
    fn compute_hash(&self) -> Hash<28> {
        Hasher::<224>::hash(&Into::<[u8; PublicKey::SIZE]>::into(*self))
    }
}
