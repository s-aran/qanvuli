//! SSVC assessment DTOs and search filters.

pub use qanvuli_models::ssvc::{SsvcAutomatable, SsvcExploitation, SsvcTechnicalImpact};
use serde::Serialize;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SsvcInfo {
    pub cve_id: String,
    pub provider: String,
    pub role: String,
    pub version: String,
    pub assessed_at: String,
    pub exploitation: Option<SsvcExploitation>,
    pub automatable: Option<SsvcAutomatable>,
    pub technical_impact: Option<SsvcTechnicalImpact>,
    pub fetched_at: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SsvcSearch {
    pub exploitation: Option<SsvcExploitation>,
    pub automatable: Option<SsvcAutomatable>,
    pub technical_impact: Option<SsvcTechnicalImpact>,
}

impl SsvcSearch {
    pub fn is_empty(&self) -> bool {
        self.exploitation.is_none() && self.automatable.is_none() && self.technical_impact.is_none()
    }
}
