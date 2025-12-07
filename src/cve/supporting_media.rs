use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct SupportingMedia {
    #[serde(rename = "type")]
    pub media_type: String,
    #[serde(default = "default_base64")]
    pub base64: bool,
    pub value: String,
}

fn default_base64() -> bool {
    false
}
