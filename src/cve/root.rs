use serde::Deserialize;
use strum::{AsRefStr, EnumString};

use crate::cve::cve_metadata::CveMetadata;

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
pub enum CveDataType {
    #[strum(serialize = "CVE_RECORD")]
    CveRecord,
}

#[derive(Debug, Deserialize)]
pub struct Root {
    pub data_type: CveDataType,
    pub data_version: String,
    pub cve_meta_data: CveMetadata,
}
