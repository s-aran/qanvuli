use chrono::{DateTime, FixedOffset};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct ProviderMetadata {
    pub org_id: String,
    pub short_name: Option<String>,
    pub date_updated: Option<DateTime<FixedOffset>>,
}
