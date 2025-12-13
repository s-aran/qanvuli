use serde::Deserialize;

use crate::cve::rejected::cna::Cna;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Containers {
    pub cna: Cna,
}
