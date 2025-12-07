use chrono::{DateTime, FixedOffset};
use serde::Deserialize;

use crate::cve::{
    cna_description::CnaDescription, impact::Impact, provider_metadata::ProviderMetadata,
    reference::Reference,
};

#[derive(Debug, Deserialize)]
pub struct Scenario {
    #[serde(default = "default_lang")]
    pub lang: String,
    #[serde(default = "default_value")]
    pub value: String,
}

fn default_lang() -> String {
    "en".to_owned()
}

fn default_value() -> String {
    "GENERAL".to_owned()
}
