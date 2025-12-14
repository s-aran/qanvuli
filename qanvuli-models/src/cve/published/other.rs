use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Other {
    #[serde(rename = "type")]
    pub other_type: String,
    pub content: Value,
}
