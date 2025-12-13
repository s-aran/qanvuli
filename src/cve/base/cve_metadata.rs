use serde::Deserialize;
use strum::{AsRefStr, EnumString};

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CveState {
    Reserved,
    Published,
    Rejected,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CveMetadata {
    pub cve_id: String,
    pub state: CveState,
}
