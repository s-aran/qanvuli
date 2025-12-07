use serde::Deserialize;

use crate::cve::{atp::Atp, cna::Cna};

#[derive(Debug, Deserialize)]
pub struct Containers {
    pub cna: Cna,
    pub atp: Option<Atp>,
}
