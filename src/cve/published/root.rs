use serde::Deserialize;
use strum::{AsRefStr, EnumString};

use crate::cve::published::{containers::Containers, cve_metadata::CveMetadata};

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CveDataType {
    CveRecord,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CveRoot {
    pub data_type: CveDataType,
    #[serde(default = "default_data_version")]
    pub data_version: String,
    pub cve_metadata: CveMetadata,
    pub containers: Containers,
}

fn default_data_version() -> String {
    "5.1.0".to_owned()
}
