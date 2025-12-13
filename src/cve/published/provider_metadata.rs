use crate::datetime_deserialize::deserialize_cve_timestamp;
use chrono::{DateTime, FixedOffset};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderMetadata {
    pub org_id: String,
    pub short_name: Option<String>,
    #[serde(default, deserialize_with = "deserialize_cve_timestamp")]
    pub date_updated: Option<DateTime<FixedOffset>>,
}
