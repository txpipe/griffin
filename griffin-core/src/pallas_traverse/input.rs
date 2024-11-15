// use std::{borrow::Cow, fmt::Display, ops::Deref, str::FromStr};
use alloc::string::String;
use alloc::boxed::Box;
use alloc::vec::Vec;
use alloc::borrow::Cow;
use core::{fmt, fmt::Display, str::FromStr};
use core::ops::Deref;

use crate::pallas_codec::utils::CborWrap;
use crate::pallas_crypto::hash::Hash;
use crate::pallas_primitives::{alonzo, byron};

use crate::pallas_traverse::{MultiEraInput, OutputRef};

impl OutputRef {
    pub fn new(hash: Hash<32>, index: u64) -> Self {
        Self(hash, index)
    }

    pub fn hash(&self) -> &Hash<32> {
        &self.0
    }

    pub fn index(&self) -> u64 {
        self.1
    }
}

impl Display for OutputRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}#{}", self.hash(), self.index())
    }
}

impl FromStr for OutputRef {
    type Err = super::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<_> = s.trim().split('#').collect();
        let (hash, idx) = match &parts[..] {
            &[a, b] => (
                Hash::<32>::from_str(a).map_err(|_| super::Error::invalid_utxo_ref(s))?,
                u64::from_str(b).map_err(|_| super::Error::invalid_utxo_ref(s))?,
            ),
            _ => return Err(super::Error::invalid_utxo_ref(s)),
        };

        Ok(Self::new(hash, idx))
    }
}

impl<'b> MultiEraInput<'b> {
    pub fn from_byron(input: &'b byron::TxIn) -> Self {
        Self::Byron(Box::new(Cow::Borrowed(input)))
    }

    pub fn from_alonzo_compatible(input: &'b alonzo::TransactionInput) -> Self {
        Self::AlonzoCompatible(Box::new(Cow::Borrowed(input)))
    }

    pub fn output_ref(&self) -> OutputRef {
        match self {
            MultiEraInput::Byron(x) => match x.deref().deref() {
                byron::TxIn::Variant0(CborWrap((tx, idx))) => OutputRef(*tx, *idx as u64),
                byron::TxIn::Other(_, _) => unreachable!(),
            },
            MultiEraInput::AlonzoCompatible(x) => OutputRef(x.transaction_id, x.index),
        }
    }

    /// Returns the key used for lexicographical ordering of the input
    pub fn lexicographical_key(&self) -> String {
        format!("{}#{}", self.hash(), self.index())
    }

    pub fn hash(&self) -> &Hash<32> {
        match self {
            MultiEraInput::Byron(x) => match x.deref().deref() {
                byron::TxIn::Variant0(CborWrap((x, _))) => x,
                byron::TxIn::Other(_, _) => unreachable!(),
            },
            MultiEraInput::AlonzoCompatible(x) => &x.transaction_id,
        }
    }

    pub fn index(&self) -> u64 {
        match self {
            MultiEraInput::Byron(x) => match x.deref().deref() {
                byron::TxIn::Variant0(CborWrap((_, x))) => *x as u64,
                byron::TxIn::Other(_, _) => unreachable!(),
            },
            MultiEraInput::AlonzoCompatible(x) => x.index,
        }
    }

    pub fn as_alonzo(&self) -> Option<&alonzo::TransactionInput> {
        match self {
            MultiEraInput::Byron(_) => None,
            MultiEraInput::AlonzoCompatible(x) => Some(x),
        }
    }

    pub fn as_byron(&self) -> Option<&byron::TxIn> {
        match self {
            MultiEraInput::Byron(x) => Some(x),
            MultiEraInput::AlonzoCompatible(_) => None,
        }
    }
}
