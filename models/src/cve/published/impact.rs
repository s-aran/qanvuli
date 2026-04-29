use serde::Deserialize;

use crate::cve::published::cna_description::CnaDescription;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Impact {
    pub capec_id: Option<String>,
    pub descriptions: Vec<CnaDescription>,
}
