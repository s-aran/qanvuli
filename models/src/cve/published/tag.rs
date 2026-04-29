use serde::{self, Deserialize};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CnaTag {
    #[serde(rename = "unsupported-when-assigned")]
    UnsupportedWhenAssigned,
    #[serde(rename = "exclusively-hosted-service")]
    ExclusivelyHostedService,
    #[serde(rename = "disputed")]
    Disputed,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum Tag {
    CnaTags(CnaTag),
    Extension(String),
}
