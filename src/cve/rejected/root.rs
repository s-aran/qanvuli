use serde::Deserialize;

use crate::cve::{
    published::root::CveDataType,
    rejected::{containers::Containers, cve_metadata::CveMetadata},
};

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
