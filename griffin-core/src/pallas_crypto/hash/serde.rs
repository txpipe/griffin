use core::fmt;
use core::str::FromStr;

use serde::de::{Error, Unexpected, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use super::Hash;

// help: trait `ToString` which provides `to_string` is implemented but not in scope; perhaps you want to import it
use crate::alloc::string::ToString;

impl<const BYTES: usize> Serialize for Hash<BYTES> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

struct HashVisitor<const BYTES: usize> {}

impl<'de, const BYTES: usize> Visitor<'de> for HashVisitor<BYTES> {
    type Value = Hash<BYTES>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "a hex string representing {BYTES} bytes")
    }

    fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
    where
        E: Error,
    {
        match Hash::<BYTES>::from_str(s) {
            Ok(x) => Ok(x),
            Err(_) => Err(Error::invalid_value(Unexpected::Str(s), &self)),
        }
    }
}

impl<'de, const BYTES: usize> Deserialize<'de> for Hash<BYTES> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(HashVisitor::<BYTES> {})
    }
}
