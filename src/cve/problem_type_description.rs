use serde::Deserialize;

use crate::cve::reference::Reference;

#[derive(Debug, Deserialize)]
pub struct ProblemTypeDescription {
    #[serde(default = "default_lang")]
    pub lang: String,
    pub description: String,
    pub cwe_id: Option<String>,
    #[serde(rename = "type")]
    pub problem_type: Option<String>,
    pub references: Vec<Reference>,
}

fn default_lang() -> String {
    "en".to_owned()
}
