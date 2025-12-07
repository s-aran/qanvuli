use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Reference {
    pub url: String,
    pub name: Option<String>,
    pub tags: Vec<String>,
}
