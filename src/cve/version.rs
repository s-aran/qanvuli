use serde::Deserialize;

use crate::cve::{affected::DefaultStatus, change::Change};

#[derive(Debug, Deserialize)]
pub struct Version {
    pub version: Option<String>,
    pub status: Option<DefaultStatus>,
    pub version_type: Option<String>,
    pub less_than: Option<String>,
    pub less_than_or_equal: Option<String>,
    pub changes: Vec<Change>,
}
