use crate::datetime_deserialize::deserialize_required_cve_timestamp;
use chrono::{DateTime, FixedOffset};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Timeline {
    #[serde(default, deserialize_with = "deserialize_required_cve_timestamp")]
    pub time: DateTime<FixedOffset>,
    #[serde(default = "default_lang")]
    pub lang: String,
    pub value: String,
}

fn default_lang() -> String {
    "en".to_owned()
}
