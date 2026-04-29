use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Reference {
    pub url: String,
    pub name: Option<String>,
    pub tags: Option<Vec<String>>,
}
