//! OSV enrichment DTOs and combined enrichment response types.

use crate::{
    cve_types::{CveCvssDetail, CveDatabaseStatus, CveSummaryWithDetail},
    epss::EpssInfo,
    identifiers::SourceSyncState,
    kev::KevInfo,
};
use sea_orm::FromQueryResult;
use serde::Serialize;
use std::time::Duration;

#[derive(Clone, Debug, FromQueryResult, Serialize)]
pub struct DbSource {
    pub source: String,
    pub display_name: String,
    pub source_type: String,
    pub default_filename: String,
    pub raw_format: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct DatabaseStatus {
    #[serde(flatten)]
    pub cve: CveDatabaseStatus,
    pub sources: Vec<DbSource>,
    pub enrichment: EnrichmentDatabaseStatus,
}

#[derive(Clone, Debug, FromQueryResult, Serialize)]
pub struct EnrichmentDatabaseStatus {
    pub osv_record_count: i64,
    pub kev_entry_count: i64,
    pub epss_current_count: i64,
    pub identifier_node_count: i64,
    pub identifier_edge_count: i64,
}

#[derive(Clone, Debug)]
pub struct OsvRawRecord {
    pub source_path: Option<String>,
    pub raw_json: String,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct ImportSummary {
    pub source: String,
    pub imported: usize,
    pub skipped: usize,
    pub record_count: usize,
    pub content_hash: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct ImportTimings {
    pub hash: Duration,
    pub parse: Duration,
    pub hash_lookup: Duration,
    pub db_write: Duration,
    pub total: Duration,
}

#[derive(Clone, Debug, Serialize)]
pub struct EnrichedCve {
    pub cve_id: String,
    pub cve: Option<CveSummaryWithDetail>,
    pub aliases: Vec<String>,
    pub osv_advisories: Vec<OsvSummary>,
    pub affected_packages: Vec<AffectedPackageSummary>,
    pub kev: Option<KevInfo>,
    pub epss: Option<EpssInfo>,
    pub severity: Vec<CveCvssDetail>,
    pub cwe: Vec<String>,
    pub evidence: Vec<Evidence>,
    pub database_status: EnrichmentStatusSummary,
}

#[derive(Clone, Debug, FromQueryResult, Serialize)]
pub struct EnrichedCveSummary {
    pub cve_id: String,
    pub aliases: String,
    pub osv_ids: String,
    pub osv_summaries: String,
    pub affected_packages: String,
    pub kev_listed: bool,
    pub kev_date_added: Option<String>,
    pub kev_due_date: Option<String>,
    pub kev_known_ransomware_campaign_use: Option<String>,
    pub epss: Option<f64>,
    pub epss_percentile: Option<f64>,
    pub epss_score_date: Option<String>,
    pub epss_model_version: Option<String>,
}

#[derive(Clone, Debug, FromQueryResult, Serialize)]
pub struct OsvSummary {
    pub osv_id: String,
    pub schema_version: Option<String>,
    pub published_at: Option<String>,
    pub modified_at: Option<String>,
    pub withdrawn_at: Option<String>,
    pub summary: Option<String>,
    pub details: Option<String>,
}

#[derive(Clone, Debug, FromQueryResult, Serialize)]
pub struct AffectedPackageSummary {
    pub osv_id: String,
    pub ecosystem: Option<String>,
    pub package_name: Option<String>,
    pub purl: Option<String>,
    pub fixed_versions: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct Evidence {
    pub kind: String,
    pub source: String,
    pub from: Option<String>,
    pub to: Option<String>,
    pub cve_id: Option<String>,
    pub osv_id: Option<String>,
    pub detail: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct EnrichmentStatusSummary {
    pub source_sync: Vec<SourceSyncState>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PackageQuery {
    pub ecosystem: String,
    pub package: String,
    pub version: String,
    pub purl: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct EnrichedFinding {
    pub primary_id: String,
    pub cve_ids: Vec<String>,
    pub aliases: Vec<String>,
    pub package: PackageQuery,
    pub affected: AffectedStatus,
    pub fixed_versions: Vec<String>,
    pub enrichment: FindingEnrichment,
    pub priority_signals: PrioritySignals,
    pub evidence: Vec<Evidence>,
}

#[derive(Clone, Debug, Serialize)]
pub struct AffectedStatus {
    pub status: String,
    pub confidence: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct FindingEnrichment {
    pub kev: Option<KevInfo>,
    pub epss: Option<EpssInfo>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PrioritySignals {
    pub known_exploited: bool,
    pub epss_percentile: Option<f64>,
    pub has_fixed_version: bool,
    pub affected_confidence: String,
    pub suggested_priority: String,
    pub reasons: Vec<String>,
}
