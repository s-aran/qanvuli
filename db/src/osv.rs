//! OSV enrichment DTOs and combined enrichment response types.

use crate::{
    cve_types::{CveCvssDetail, CveDatabaseStatus, CveSummaryWithDetail},
    epss::EpssInfo,
    identifiers::SourceSyncState,
    kev::KevInfo,
    ssvc::SsvcInfo,
};
use serde::Serialize;
use std::time::Duration;

#[derive(Clone, Debug, Serialize)]
/// Registered enrichment source known to the local database.
pub struct DbSource {
    pub source: String,
    pub display_name: String,
    pub source_type: String,
    pub default_filename: String,
    pub raw_format: String,
}

#[derive(Clone, Debug, Serialize)]
/// Combined CVE and enrichment database status.
pub struct DatabaseStatus {
    #[serde(flatten)]
    pub cve: CveDatabaseStatus,
    pub sources: Vec<DbSource>,
    pub enrichment: EnrichmentDatabaseStatus,
}

#[derive(Clone, Debug, Serialize)]
/// Aggregate counts for enrichment tables.
pub struct EnrichmentDatabaseStatus {
    pub osv_record_count: i64,
    pub kev_entry_count: i64,
    pub epss_current_count: i64,
    pub ssvc_assessment_count: i64,
    pub identifier_node_count: i64,
    pub identifier_edge_count: i64,
}

#[derive(Clone, Debug)]
/// Raw OSV advisory JSON staged for import.
pub struct OsvRawRecord {
    pub source_path: Option<String>,
    pub raw_json: String,
}

#[derive(Clone, Debug, Default, Serialize)]
/// Summary of an enrichment import run.
pub struct ImportSummary {
    pub source: String,
    pub imported: usize,
    pub skipped: usize,
    pub record_count: usize,
    pub content_hash: Option<String>,
}

#[derive(Clone, Debug, Default)]
/// Timing breakdown for an enrichment import run.
pub struct ImportTimings {
    pub hash: Duration,
    pub parse: Duration,
    pub hash_lookup: Duration,
    pub db_write: Duration,
    pub total: Duration,
}

#[derive(Clone, Debug, Serialize)]
/// CVE record with locally joined OSV, KEV, EPSS, and graph evidence.
pub struct EnrichedCve {
    pub cve_id: String,
    pub cve: Option<CveSummaryWithDetail>,
    pub aliases: Vec<String>,
    pub osv_advisories: Vec<OsvSummary>,
    pub affected_packages: Vec<AffectedPackageSummary>,
    pub kev: Option<KevInfo>,
    pub epss: Option<EpssInfo>,
    pub ssvc: Vec<SsvcInfo>,
    pub severity: Vec<CveCvssDetail>,
    pub cwe: Vec<String>,
    pub evidence: Vec<Evidence>,
    pub database_status: EnrichmentStatusSummary,
}

#[derive(Clone, Debug, Serialize)]
/// Compact enriched CVE row used by list and search responses.
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
    pub ssvc_exploitation: Option<String>,
    pub ssvc_automatable: Option<String>,
    pub ssvc_technical_impact: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
/// Compact risk row for CVE triage.
pub struct CveRiskSummary {
    pub cve_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<i32>,
    pub kev_listed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kev_date_added: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kev_due_date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kev_known_ransomware_campaign_use: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epss: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epss_percentile: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epss_score_date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epss_model_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_cvss_score: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_cvss_severity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_cvss_version: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
/// Lightweight OSV advisory summary.
pub struct OsvSummary {
    pub osv_id: String,
    pub schema_version: Option<String>,
    pub published_at: Option<String>,
    pub modified_at: Option<String>,
    pub withdrawn_at: Option<String>,
    pub summary: Option<String>,
    pub details: Option<String>,
    pub package_summary: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
/// Package affected by an OSV advisory.
pub struct AffectedPackageSummary {
    pub osv_id: String,
    pub ecosystem: Option<String>,
    pub package_name: Option<String>,
    pub purl: Option<String>,
    pub fixed_versions: String,
}

#[derive(Clone, Debug, Serialize)]
/// Human-readable evidence showing why records were linked or matched.
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
/// Source freshness data attached to enriched responses.
pub struct EnrichmentStatusSummary {
    pub source_sync: Vec<SourceSyncState>,
}

#[derive(Clone, Debug, Serialize)]
/// Package/version lookup input echoed in enriched package findings.
pub struct PackageQuery {
    pub ecosystem: String,
    pub package: String,
    pub version: String,
    pub purl: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
/// Vulnerability finding for one package/version lookup.
pub struct EnrichedFinding {
    /// Originating advisory corpus: `osv` or `cve-list`.
    pub source: String,
    pub primary_id: String,
    pub cve_ids: Vec<String>,
    pub aliases: Vec<String>,
    pub aliases_status: String,
    pub package: PackageQuery,
    pub affected: AffectedStatus,
    pub fixed_versions: Vec<String>,
    pub fixed_versions_status: String,
    pub enrichment: FindingEnrichment,
    pub priority_signals: PrioritySignals,
    pub evidence: Vec<Evidence>,
    pub evidence_status: String,
}

#[derive(Clone, Debug, Serialize)]
/// Affected/not-affected status and confidence for a package finding.
pub struct AffectedStatus {
    pub status: String,
    pub confidence: String,
}

#[derive(Clone, Debug, Serialize)]
/// Risk enrichment attached to a package finding.
pub struct FindingEnrichment {
    pub kev: Option<KevInfo>,
    pub kev_status: String,
    pub epss: Option<EpssInfo>,
    pub epss_status: String,
}

#[derive(Clone, Debug, Serialize)]
/// Derived triage signals for ordering package findings.
pub struct PrioritySignals {
    pub known_exploited: bool,
    pub epss_percentile: Option<f64>,
    pub has_fixed_version: bool,
    pub affected_confidence: String,
    pub suggested_priority: String,
    pub reasons: Vec<String>,
    pub enrichment_status: String,
}
