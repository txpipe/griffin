use core::iter;

use crate::pallas_primitives::alonzo;

use crate::pallas_traverse::MultiEraMeta;

impl<'b> MultiEraMeta<'b> {
    pub fn as_alonzo(&self) -> Option<&alonzo::Metadata> {
        match self {
            Self::AlonzoCompatible(x) => Some(x),
            _ => None,
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            MultiEraMeta::AlonzoCompatible(x) => x.is_empty(),
            _ => true,
        }
    }

    pub fn find(&self, label: alonzo::MetadatumLabel) -> Option<&alonzo::Metadatum> {
        self.as_alonzo()?
            .iter()
            .find_map(|(key, value)| if key.eq(&label) { Some(value) } else { None })
    }

    pub fn collect<'a, T>(&'a self) -> T
    where
        T: FromIterator<(alonzo::MetadatumLabel, &'a alonzo::Metadatum)>,
    {
        match self {
            MultiEraMeta::NotApplicable => iter::empty().collect(),
            MultiEraMeta::Empty => iter::empty().collect(),
            MultiEraMeta::AlonzoCompatible(x) => x.iter().map(|(k, v)| (*k, v)).collect(),
        }
    }
}
