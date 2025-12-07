use chrono::{DateTime, FixedOffset};
use serde::Deserialize;
use toml::value::Datetime;

#[derive(Debug, Deserialize)]
pub struct Timeline {
    pub time: DateTime<FixedOffset>,
    #[serde(default = "default_lang")]
    pub lang: String,
    pub value: String,
}

fn default_lang() -> String {
    "en".to_owned()
}
