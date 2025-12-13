use serde::Deserialize;

use crate::cve::base::cve_metadata::CveMetadata;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CveRoot {
    pub cve_metadata: CveMetadata,
}
