use serde::Deserialize;

use crate::cve::affected::DefaultStatus;

#[derive(Debug, Deserialize)]
pub struct Change {
    pub at: String,
    pub status: DefaultStatus,
}
