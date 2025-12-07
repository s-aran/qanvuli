use serde::Deserialize;
use strum::{AsRefStr, EnumString};
use toml::de::ValueDeserializer;

#[derive(Debug, Deserialize)]
pub struct Other {
    #[serde(rename = "type")]
    pub other_type: String,
    #[serde()]
    pub contest: String,
}
