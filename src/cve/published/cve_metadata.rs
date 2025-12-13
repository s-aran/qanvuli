use chrono::{DateTime, FixedOffset};
use serde::Deserialize;

use crate::cve::base::cve_metadata::CveState;
use crate::datetime_deserialize::deserialize_cve_timestamp;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CveMetadata {
    pub cve_id: String,
    pub assigner_org_id: String,
    pub assigner_short_name: Option<String>,
    pub requester_user_id: Option<String>,
    #[serde(default, deserialize_with = "deserialize_cve_timestamp")]
    pub date_updated: Option<DateTime<FixedOffset>>,
    pub serial: Option<usize>,
    #[serde(default, deserialize_with = "deserialize_cve_timestamp")]
    pub date_reserved: Option<DateTime<FixedOffset>>,
    #[serde(default, deserialize_with = "deserialize_cve_timestamp")]
    pub date_published: Option<DateTime<FixedOffset>>,
    pub state: CveState,
}
