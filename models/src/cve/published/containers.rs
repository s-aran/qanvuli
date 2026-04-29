use serde::Deserialize;

use crate::cve::published::{atp::Atp, cna::Cna};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Containers {
    pub cna: Cna,
    pub atp: Option<Atp>,
}
