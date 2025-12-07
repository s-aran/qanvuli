use serde::Deserialize;

use crate::cve::assigner_org_id::AssignerOrgId;

#[derive(Debug, Deserialize)]
pub struct CveMetadata {
    pub cve_id: String,
    pub assigner_org_id: AssignerOrgId,
}
