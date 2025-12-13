use serde::Deserialize;

use crate::cve::published::{cna_description::CnaDescription, provider_metadata::ProviderMetadata};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Cna {
    pub provider_metadata: ProviderMetadata,
    pub rejected_reasons: Vec<CnaDescription>,
    pub replaced_by: Option<Vec<String>>,
}
