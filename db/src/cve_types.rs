//! CVE-facing database DTOs and search option types.

use crate::entity::{cve, cve_affected, cve_cvss, cve_cwe, cwe};
use sea_orm::FromQueryResult;
use serde::{Serialize, Serializer};

/// Prepared SeaORM active models derived from one CVE record.
pub struct CveActiveModels {
    pub cve_id: String,
    pub cve: cve::ActiveModel,
    pub cvss_rows: Vec<cve_cvss::ActiveModel>,
    pub affected_rows: Vec<cve_affected::ActiveModel>,
    pub cwe_master_rows: Vec<cwe::ActiveModel>,
    pub cwe_rows: Vec<cve_cwe::ActiveModel>,
}

/// Import bookkeeping for one JSON file read from a CVE archive.
pub struct ReadJsonFileRecord {
    pub filename: String,
    pub md5hash: String,
}

#[derive(Clone, Debug)]
/// Import bookkeeping for one processed CVE zip archive.
pub struct CveZipFileRecord {
    pub zip_filename: String,
    pub zip_datetime: String,
    pub zip_type: i32,
}

#[derive(Clone, Debug, FromQueryResult, Serialize)]
/// Lightweight CVE row returned by search APIs.
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
/// CVE summary plus normalized CWE, CVSS, and affected-product detail.
pub struct CveSummaryWithDetail {
    pub summary: CveSummary,
    pub detail: CveDetail,
}

#[derive(Clone, Debug, FromQueryResult, Serialize)]
/// Aggregate counts and freshness metadata for the local CVE database.
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
/// Normalized detail attached to a CVE summary.
pub struct CveDetail {
    pub cwes: Vec<CveCweDetail>,
    pub cvss: Vec<CveCvssDetail>,
    pub affected: Vec<CveAffectedDetail>,
}

#[derive(Clone, Debug, FromQueryResult, Serialize)]
/// CWE classification attached to a CVE.
pub struct CveCweDetail {
    pub id: i32,
    pub description: Option<String>,
}

#[derive(Clone, Debug, FromQueryResult, Serialize)]
/// CVSS metric attached to a CVE.
pub struct CveCvssDetail {
    pub version: String,
    pub base_score: Option<f64>,
    pub base_severity: Option<String>,
    pub vector_string: Option<String>,
    pub source: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
/// Affected vendor, product, package, and version data attached to a CVE.
pub struct CveAffectedDetail {
    pub vendor: Option<String>,
    pub product: Option<String>,
    pub package_name: Option<String>,
    pub collection_url: Option<String>,
    pub default_status: Option<String>,
    pub versions: Vec<CveAffectedVersionDetail>,
}

#[derive(Clone, Debug, Default, Serialize)]
/// One version entry from a CVE affected product block.
pub struct CveAffectedVersionDetail {
    pub version: Option<String>,
    pub status: Option<String>,
    pub version_type: Option<String>,
    pub less_than: Option<String>,
    pub less_than_or_equal: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
/// CWE catalog entry with local tree relationship counts.
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
/// Structured search request used by the TUI and higher-level search flows.
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
/// Interprets the free query text in an advanced CVE search.
pub enum CveAdvancedQueryMode {
    FreeText,
    Product,
    Vendor,
    Cwe,
    Cve,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
/// Controls whether rejected CVE records are visible to a query.
pub enum CveStateScope {
    #[default]
    PublishedOnly,
    IncludeRejected,
}

impl CveStateScope {
    /// Creates a scope from a caller-facing rejected-record flag.
    pub const fn from_include_rejected(include_rejected: bool) -> Self {
        if include_rejected {
            Self::IncludeRejected
        } else {
            Self::PublishedOnly
        }
    }

    pub(crate) fn includes_rejected(self) -> bool {
        matches!(self, Self::IncludeRejected)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
/// Sort order for CVE summary search results.
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

#[derive(Clone, Debug, FromQueryResult)]
pub(crate) struct CveIdMapping {
    pub(crate) id: i32,
}

#[derive(Clone, Debug, FromQueryResult)]
pub(crate) struct CveDbIdByCveId {
    pub(crate) id: i32,
    pub(crate) cve_id: String,
}

#[derive(Clone, Debug, FromQueryResult)]
pub(crate) struct CweEntryRow {
    pub(crate) id: i32,
    pub(crate) description: Option<String>,
    pub(crate) status: Option<String>,
    pub(crate) parent_id: Option<i32>,
}

#[derive(Clone, Debug, FromQueryResult)]
pub(crate) struct CveCweDetailRow {
    pub(crate) cve_db_id: i32,
    pub(crate) id: i32,
    pub(crate) description: Option<String>,
}

#[derive(Clone, Debug, FromQueryResult)]
pub(crate) struct CveCvssDetailRow {
    pub(crate) cve_db_id: i32,
    pub(crate) version: String,
    pub(crate) base_score: Option<f64>,
    pub(crate) base_severity: Option<String>,
    pub(crate) vector_string: Option<String>,
    pub(crate) source: Option<String>,
}

#[derive(Clone, Debug, FromQueryResult)]
pub(crate) struct CveAffectedDetailRow {
    pub(crate) cve_db_id: i32,
    pub(crate) vendor: Option<String>,
    pub(crate) product: Option<String>,
    pub(crate) package_name: Option<String>,
    pub(crate) collection_url: Option<String>,
    pub(crate) default_status: Option<String>,
    pub(crate) raw_json: String,
}

#[derive(Clone, Debug, Serialize)]
/// Reference URL metadata attached to a CVE.
pub struct CveReference {
    pub url: Option<String>,
    pub name: Option<String>,
    pub tags: Vec<String>,
}

/// Converts the stored CVE state integer into a stable API label.
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
