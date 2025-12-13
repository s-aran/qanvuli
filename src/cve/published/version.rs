use serde::Deserialize;

use crate::cve::published::{affected::DefaultStatus, change::Change};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Version {
    pub version: Option<String>,
    pub status: Option<DefaultStatus>,
    pub version_type: Option<String>,
    pub less_than: Option<String>,
    pub less_than_or_equal: Option<String>,
    pub changes: Option<Vec<Change>>,
}
