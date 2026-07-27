use serde::Deserialize;
use simd_json::OwnedValue as Value;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Other {
    #[serde(rename = "type")]
    pub other_type: String,
    pub content: Value,
}
