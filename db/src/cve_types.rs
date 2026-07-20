//! Public CVE DTOs and UI search options. These contain only external identifiers and never
//! SQLite row IDs.

use serde::{Serialize, Serializer};

#[derive(Clone, Debug, Serialize)]
pub struct CveSummary {
    pub cve_id: String,
    #[serde(serialize_with = "serialize_cve_state")]
    pub state: i32,
    pub published_at: String,
    pub updated_at: String,
    pub title: String,
    pub description_en: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CveSummaryWithDetail {
    pub summary: CveSummary,
    pub detail: CveDetail,
}

#[derive(Clone, Debug, Serialize)]
pub struct CveDatabaseStatus {
    pub cve_count: i64,
    pub published_count: i64,
    pub rejected_count: i64,
    pub cwe_count: i64,
    pub affected_count: i64,
    pub cvss_count: i64,
    pub latest_cve_updated_at: Option<String>,
    pub latest_zip_datetime: Option<String>,
    pub latest_zip_filename: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct CveDetail {
    pub cwes: Vec<CveCweDetail>,
    pub cvss: Vec<CveCvssDetail>,
    pub affected: Vec<CveAffectedDetail>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CveCweDetail {
    pub id: i32,
    pub description: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CveCvssDetail {
    pub version: String,
    pub base_score: Option<f64>,
    pub base_severity: Option<String>,
    pub vector_string: Option<String>,
    pub source: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CveAffectedDetail {
    pub vendor: Option<String>,
    pub product: Option<String>,
    pub package_name: Option<String>,
    pub description: Option<String>,
    pub collection_url: Option<String>,
    pub default_status: Option<String>,
    pub versions: Vec<CveAffectedVersionDetail>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct CveAffectedVersionDetail {
    pub version: Option<String>,
    pub status: Option<String>,
    pub version_type: Option<String>,
    pub less_than: Option<String>,
    pub less_than_or_equal: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CweEntry {
    pub id: i32,
    pub description: Option<String>,
    pub status: Option<String>,
    pub parent_id: Option<i32>,
    pub parent_count: usize,
    pub sibling_count: usize,
    pub child_count: usize,
}

#[derive(Clone, Debug, Default)]
pub struct CveAdvancedSearch {
    pub query: Option<String>,
    pub query_mode: Option<CveAdvancedQueryMode>,
    pub published_from: Option<String>,
    pub published_to: Option<String>,
    pub cwe: Option<String>,
    pub product: Option<String>,
    pub product_exact: Option<String>,
    pub vendor: Option<String>,
    pub vendor_exact: Option<String>,
    pub kev_only: bool,
    pub state_scope: CveStateScope,
    pub sort_order: CveSummarySortOrder,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CveAdvancedQueryMode {
    FreeText,
    Product,
    Vendor,
    Cwe,
    Cve,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CveStateScope {
    #[default]
    PublishedOnly,
    IncludeRejected,
}

impl CveStateScope {
    pub const fn from_include_rejected(include_rejected: bool) -> Self {
        if include_rejected {
            Self::IncludeRejected
        } else {
            Self::PublishedOnly
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CveSummarySortOrder {
    PublishedAsc,
    #[default]
    PublishedDesc,
    UpdatedAsc,
    UpdatedDesc,
    CveIdAsc,
    CveIdDesc,
    RelationRankAsc,
    RelationRankDesc,
    ScoreAsc,
    ScoreDesc,
}

#[derive(Clone, Debug, Serialize)]
pub struct CveReference {
    pub url: Option<String>,
    pub name: Option<String>,
    pub tags: Vec<String>,
}

pub fn cve_state_label(state: i32) -> &'static str {
    match state {
        0 => "PUBLISHED",
        1 => "REJECTED",
        _ => "UNKNOWN",
    }
}

fn serialize_cve_state<S>(state: &i32, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(cve_state_label(*state))
}
