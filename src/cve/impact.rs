use serde::Deserialize;

use crate::cve::cna_description::CnaDescription;

#[derive(Debug, Deserialize)]
pub struct Impact {
    pub capec_id: Option<String>,
    pub descriptions: Vec<CnaDescription>,
}
