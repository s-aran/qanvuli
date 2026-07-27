//! CISA KEV database DTOs.

use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct KevInfo {
    pub cve_id: String,
    pub vendor_project: Option<String>,
    pub product: Option<String>,
    pub vulnerability_name: Option<String>,
    pub date_added: Option<String>,
    pub short_description: Option<String>,
    pub required_action: Option<String>,
    pub due_date: Option<String>,
    pub known_ransomware_campaign_use: Option<String>,
    pub notes: Option<String>,
    pub fetched_at: String,
}
