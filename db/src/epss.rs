//! FIRST EPSS database DTOs.

use sea_orm::FromQueryResult;
use serde::Serialize;

#[derive(Clone, Debug, FromQueryResult, Serialize)]
pub struct EpssInfo {
    pub cve_id: String,
    pub epss: f64,
    pub percentile: f64,
    pub score_date: Option<String>,
    pub model_version: Option<String>,
    pub fetched_at: String,
}
