//! SQLx-only database handle for destructive rebuilds.

use super::{
    maintenance::rebuild_cve_search,
    package_eval::{OsvRange, evaluate_version},
    schema,
    search::fts_query,
    timestamps::{canonical_cve_utc, canonical_utc},
    writer::SqliteWriter,
};
use crate::{
    AffectedStatus, CveAffectedDetail, CveAffectedVersionDetail, CveCvssDetail, CveCweDetail,
    CveDetail, CveStateScope, CveSummary, CveSummaryWithDetail, EnrichedFinding, FindingEnrichment,
    OsvRawRecord, PackageQuery, PrioritySignals,
};
use md5::{Digest, Md5};
use qanvuli_models::cwe::WeaknessCatalog;
use qanvuli_models::cwe::enumeration::RelatedNature;
use qanvuli_models::epss::EpssCurrentCsv;
use qanvuli_models::kev::KevCatalog;
use qanvuli_models::osv::OsvAdvisory;
use rayon::prelude::*;
use serde_json::Value;
use sqlx::{Acquire, QueryBuilder, Row, Sqlite};
use std::collections::{BTreeMap, BTreeSet};

type AffectedRow = (i64, Option<String>, Option<String>, Option<String>, String);

struct CveParentInput {
    cve_id: String,
    state: i64,
    published_at: String,
    updated_at: String,
    title: String,
    description_en: Option<String>,
    serial: i64,
    reference_text: String,
    raw_json: String,
}

struct OsvBatchInput {
    advisory: OsvAdvisory,
    source_path: Option<String>,
    raw_json: String,
    modified_at: String,
    published_at: Option<String>,
    withdrawn_at: Option<String>,
    content_hash: String,
    search_aliases: String,
    search_packages: String,
}

type CvssInput = (
    i64,
    String,
    Option<f64>,
    Option<String>,
    Option<String>,
    String,
);
type AffectedInput = (
    i64,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    String,
    String,
);

/// Public CVE projection. Internal SQLite row IDs never leave the database layer.
#[derive(Clone, Debug, serde::Serialize, sqlx::FromRow)]
pub struct SqlxCveSummary {
    pub cve_id: String,
    pub state: i64,
    pub published_at: String,
    pub updated_at: String,
    pub title: String,
    pub description_en: Option<String>,
}

/// Fully normalized CVE detail for SQLx query consumers.
#[derive(Clone, Debug, Default, PartialEq, serde::Serialize)]
pub struct SqlxCveDetail {
    pub cvss: Vec<SqlxCvss>,
    pub cwes: Vec<SqlxCwe>,
    pub affected: Vec<SqlxAffected>,
    pub references: Vec<SqlxCveReference>,
    pub epss: Option<SqlxEpss>,
    pub kev: Option<SqlxKev>,
    pub osv_advisories: Vec<SqlxOsvSummary>,
}

/// SQLx-only CVE display record preserving the public external identifier.
#[derive(Clone, Debug, serde::Serialize)]
pub struct SqlxCveSummaryWithDetail {
    pub summary: SqlxCveSummary,
    pub detail: SqlxCveDetail,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, sqlx::FromRow)]
pub struct SqlxCvss {
    pub version: String,
    pub base_score: Option<f64>,
    pub base_severity: Option<String>,
    pub vector_string: Option<String>,
    pub source: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct SqlxCvssSearch {
    pub min_score: Option<f64>,
    pub max_score: Option<f64>,
    pub severity: Option<String>,
    pub version: Option<String>,
}

/// Composable CVE search filters. Every value is bound; this type only selects documented
/// normalized predicates and never exposes SQLite internal keys.
#[derive(Clone, Debug, Default)]
pub struct SqlxCveSearch {
    pub text: Option<String>,
    pub cwe_ids: Vec<String>,
    pub vendor_like: Option<String>,
    pub product_like: Option<String>,
    pub vendor_exact: Option<String>,
    pub product_exact: Option<String>,
    pub cvss: SqlxCvssSearch,
    pub published_since: Option<String>,
    pub published_until: Option<String>,
    pub updated_since: Option<String>,
    pub updated_until: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, sqlx::FromRow)]
pub struct SqlxCwe {
    pub id: i64,
    pub description: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct SqlxAffected {
    pub vendor: Option<String>,
    pub product: Option<String>,
    pub package_name: Option<String>,
    pub versions: Vec<SqlxAffectedVersion>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, sqlx::FromRow)]
pub struct SqlxAffectedVersion {
    pub version: Option<String>,
    pub status: Option<String>,
    pub version_type: Option<String>,
    pub less_than: Option<String>,
    pub less_than_or_equal: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, sqlx::FromRow)]
pub struct SqlxCveReference {
    pub url: String,
    pub name: Option<String>,
    pub tags_json: String,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, sqlx::FromRow)]
pub struct SqlxEpss {
    pub epss: f64,
    pub percentile: f64,
    pub score_date: Option<String>,
    pub model_version: Option<String>,
}

#[derive(Clone, Debug, serde::Serialize, sqlx::FromRow)]
pub struct SqlxEpssRisk {
    pub cve_id: String,
    pub epss: f64,
    pub percentile: f64,
    pub kev_listed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, sqlx::FromRow)]
pub struct SqlxKev {
    pub vendor_project: Option<String>,
    pub product: Option<String>,
    pub vulnerability_name: Option<String>,
    pub date_added: String,
    pub due_date: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, sqlx::FromRow)]
pub struct SqlxKevEntry {
    pub cve_id: String,
    pub vendor_project: Option<String>,
    pub product: Option<String>,
    pub vulnerability_name: Option<String>,
    pub date_added: String,
    pub due_date: Option<String>,
}

/// Public OSV search projection; the advisory's internal row ID remains private.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, sqlx::FromRow)]
pub struct SqlxOsvSummary {
    pub osv_id: String,
    pub modified_at: String,
    pub summary: Option<String>,
    pub withdrawn_at: Option<String>,
}

#[derive(Clone, Debug, serde::Serialize, sqlx::FromRow)]
pub struct SqlxDatabaseStatus {
    pub cve_count: i64,
    pub osv_count: i64,
    pub cwe_count: i64,
    pub affected_count: i64,
    pub cvss_count: i64,
    pub latest_cve_updated_at: Option<String>,
}

#[derive(Clone, Debug, serde::Serialize, sqlx::FromRow)]
pub struct SqlxSourceSyncState {
    pub source: String,
    pub status: String,
    pub last_cursor: Option<String>,
    pub error_message: Option<String>,
}

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct SqlxIdentifierResolution {
    pub identifier: String,
    pub related_cve_ids: Vec<String>,
    pub related_osv_ids: Vec<String>,
}

#[derive(Clone, Debug, serde::Serialize, sqlx::FromRow)]
pub struct SqlxIdentifierEdge {
    pub from_identifier: String,
    pub to_identifier: String,
    pub relation_type: String,
    pub source: String,
    pub confidence: String,
    pub evidence_json: String,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct SqlxPackageFinding {
    pub osv_id: String,
    pub cve_ids: Vec<String>,
    pub status: String,
    pub confidence: String,
}

impl From<SqlxCveSummary> for CveSummary {
    fn from(value: SqlxCveSummary) -> Self {
        Self {
            cve_id: value.cve_id,
            state: i32::try_from(value.state).unwrap_or_default(),
            published_at: value.published_at,
            updated_at: value.updated_at,
            title: value.title,
            description_en: value.description_en,
        }
    }
}

impl From<SqlxCveSummaryWithDetail> for CveSummaryWithDetail {
    fn from(value: SqlxCveSummaryWithDetail) -> Self {
        let detail = value.detail;
        Self {
            summary: value.summary.into(),
            detail: CveDetail {
                cwes: detail
                    .cwes
                    .into_iter()
                    .map(|row| CveCweDetail {
                        id: i32::try_from(row.id).unwrap_or_default(),
                        description: row.description,
                    })
                    .collect(),
                cvss: detail
                    .cvss
                    .into_iter()
                    .map(|row| CveCvssDetail {
                        version: row.version,
                        base_score: row.base_score,
                        base_severity: row.base_severity,
                        vector_string: row.vector_string,
                        source: row.source,
                    })
                    .collect(),
                affected: detail
                    .affected
                    .into_iter()
                    .map(|row| CveAffectedDetail {
                        vendor: row.vendor,
                        product: row.product,
                        package_name: row.package_name,
                        collection_url: None,
                        default_status: None,
                        versions: row
                            .versions
                            .into_iter()
                            .map(|version| CveAffectedVersionDetail {
                                version: version.version,
                                status: version.status,
                                version_type: version.version_type,
                                less_than: version.less_than,
                                less_than_or_equal: version.less_than_or_equal,
                            })
                            .collect(),
                    })
                    .collect(),
            },
        }
    }
}

/// A database handle with one physical writer connection.
///
/// It is the sole database handle for imports, replacement databases, and queries.
#[derive(Clone, Debug)]
pub struct SqlxDatabase {
    pub(crate) writer: SqliteWriter,
}

impl SqlxDatabase {
    pub async fn connect(url: &str) -> Result<Self, sqlx::Error> {
        Ok(Self {
            writer: SqliteWriter::connect(url).await?,
        })
    }

    pub async fn initialize(&self) -> Result<(), sqlx::Error> {
        self.writer.initialize_schema().await
    }

    /// Compatibility name retained for existing database callers.
    pub async fn initialize_schema(&self) -> Result<(), sqlx::Error> {
        self.initialize().await
    }

    pub async fn search_cve_summaries_by_affected_component_with_state_scope(
        &self,
        vendor: Option<&str>,
        component: &str,
        published_since: Option<&str>,
        updated_since: Option<&str>,
        state_scope: CveStateScope,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, sqlx::Error> {
        let vendor = vendor.map(str::to_owned);
        let component = component.to_owned();
        let published_since = published_since.map(str::to_owned);
        let updated_since = updated_since.map(str::to_owned);
        let include_rejected = state_scope == CveStateScope::IncludeRejected;
        self.writer
            .with_connection(|connection| {
                Box::pin(async move {
                    let rows: Vec<SqlxCveSummary> = sqlx::query_as(
                        "SELECT DISTINCT c.cve_id, c.state, c.published_at, c.updated_at, c.title, c.description_en FROM cve c JOIN cve_affected a ON a.cve_db_id=c.id WHERE (? OR c.state=0) AND (? IS NULL OR a.vendor LIKE '%' || ? || '%') AND (a.product LIKE '%' || ? || '%' OR a.package_name LIKE '%' || ? || '%') AND (? IS NULL OR c.published_at>=?) AND (? IS NULL OR c.updated_at>=?) ORDER BY c.published_at DESC, c.cve_id DESC LIMIT ? OFFSET ?",
                    )
                    .bind(include_rejected)
                    .bind(&vendor)
                    .bind(&vendor)
                    .bind(&component)
                    .bind(&component)
                    .bind(&published_since)
                    .bind(&published_since)
                    .bind(&updated_since)
                    .bind(&updated_since)
                    .bind(i64::try_from(limit).unwrap_or(i64::MAX).max(1))
                    .bind(i64::try_from(offset).unwrap_or(i64::MAX))
                    .fetch_all(connection)
                    .await?;
                    Ok(rows.into_iter().map(CveSummary::from).collect())
                })
            })
            .await
    }

    pub async fn query_package_enriched(
        &self,
        ecosystem: &str,
        package: &str,
        version: &str,
        purl: Option<&str>,
    ) -> Result<Vec<EnrichedFinding>, sqlx::Error> {
        let findings = self
            .query_osv_package_with_purl(ecosystem, package, version, purl)
            .await?;
        Ok(findings
            .into_iter()
            .filter(|finding| finding.status != "not_affected")
            .map(|finding| {
                let affected = AffectedStatus {
                    status: finding.status,
                    confidence: finding.confidence,
                };
                EnrichedFinding {
                    primary_id: finding.osv_id,
                    cve_ids: finding.cve_ids,
                    aliases: Vec::new(),
                    package: PackageQuery {
                        ecosystem: ecosystem.to_owned(),
                        package: package.to_owned(),
                        version: version.to_owned(),
                        purl: purl.map(str::to_owned),
                    },
                    affected: affected.clone(),
                    fixed_versions: Vec::new(),
                    enrichment: FindingEnrichment {
                        kev: None,
                        epss: None,
                    },
                    priority_signals: PrioritySignals {
                        known_exploited: false,
                        epss_percentile: None,
                        has_fixed_version: false,
                        affected_confidence: affected.confidence,
                        suggested_priority: "unknown".to_owned(),
                        reasons: Vec::new(),
                    },
                    evidence: Vec::new(),
                }
            })
            .collect())
    }

    pub async fn find_cve_summary_with_detail_with_state_scope(
        &self,
        cve_id: &str,
        state_scope: CveStateScope,
    ) -> Result<Option<CveSummaryWithDetail>, sqlx::Error> {
        let row = self.cve_summary_with_detail(cve_id).await?;
        Ok(row
            .filter(|row| state_scope == CveStateScope::IncludeRejected || row.summary.state == 0)
            .map(CveSummaryWithDetail::from))
    }

    /// Closes the dedicated physical connection before a database file is replaced.
    pub async fn close(self) -> Result<(), sqlx::Error> {
        self.writer.close().await
    }

    pub async fn rebuild_search(&self) -> Result<(), sqlx::Error> {
        self.writer.rebuild_search().await
    }

    pub async fn rebuild_osv_search(&self) -> Result<(), sqlx::Error> {
        self.writer.rebuild_osv_search().await
    }

    /// Verifies the required schema objects and version without scanning the full database.
    pub async fn check_schema(&self) -> Result<(), sqlx::Error> {
        self.writer.check_schema().await
    }

    /// Prepares a replacement database for devel-compatible full CVE bulk loading.
    pub async fn prepare_cve_bulk_load(&self) -> Result<(), sqlx::Error> {
        self.writer.prepare_cve_bulk_load().await
    }

    /// Builds deferred indexes/search data and restores normal SQLite durability.
    pub async fn finish_cve_bulk_load(&self) -> Result<(), sqlx::Error> {
        self.writer.finish_cve_bulk_load().await
    }

    pub async fn prepare_osv_bulk_load(&self) -> Result<(), sqlx::Error> {
        self.writer.prepare_osv_bulk_load().await
    }

    pub async fn finish_osv_bulk_load(&self) -> Result<(), sqlx::Error> {
        self.writer.finish_osv_bulk_load().await
    }

    /// Rebuilds derived identifier edges from the normalized OSV relation source of truth.
    pub async fn rebuild_identifier_graph(&self) -> Result<(), sqlx::Error> {
        self.writer
            .with_connection(|connection| {
                Box::pin(async move {
                    let mut transaction = connection.begin().await?;
                    rebuild_osv_identifier_edges(
                        &mut transaction,
                        &chrono::Utc::now().to_rfc3339(),
                    )
                    .await?;
                    transaction.commit().await
                })
            })
            .await
    }

    pub async fn check(&self) -> Result<(), sqlx::Error> {
        self.writer.check_schema().await?;
        self.writer.check_integrity().await
    }

    pub const fn schema_version() -> i64 {
        schema::SCHEMA_VERSION
    }

    /// Looks up a CVE by its external identifier without exposing its internal row ID.
    pub async fn find_cve_summary(
        &self,
        cve_id: &str,
    ) -> Result<Option<SqlxCveSummary>, sqlx::Error> {
        let cve_id = cve_id.to_owned();
        self.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query_as("SELECT cve_id, state, published_at, updated_at, title, description_en FROM cve WHERE cve_id=?")
                .bind(cve_id).fetch_optional(connection).await
        })).await
    }

    /// Returns the preserved provider CVE JSON only when a caller explicitly requests it.
    pub async fn cve_raw_json(&self, cve_id: &str) -> Result<Option<String>, sqlx::Error> {
        let cve_id = cve_id.to_owned();
        self.writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query_scalar("SELECT raw_json FROM cve WHERE cve_id=?")
                        .bind(cve_id)
                        .fetch_optional(connection)
                        .await
                })
            })
            .await
    }

    /// Searches external CVE identifiers by prefix without exposing internal keys.
    pub async fn search_cves_by_id_prefix(
        &self,
        prefix: &str,
        include_rejected: bool,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SqlxCveSummary>, sqlx::Error> {
        let prefix = format!("{}%", prefix.trim());
        self.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query_as("SELECT cve_id, state, published_at, updated_at, title, description_en FROM cve WHERE cve_id LIKE ? AND (? OR state=0) ORDER BY cve_id LIMIT ? OFFSET ?")
                .bind(prefix).bind(include_rejected).bind(limit.max(1)).bind(offset.max(0)).fetch_all(connection).await
        })).await
    }

    /// Searches the stable external-content CVE FTS index and returns public identifiers.
    pub async fn search_cves(
        &self,
        query: &str,
        include_rejected: bool,
        limit: i64,
    ) -> Result<Vec<SqlxCveSummary>, sqlx::Error> {
        let Some(query) = fts_query(query) else {
            return Ok(Vec::new());
        };
        self.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query_as("SELECT c.cve_id, c.state, c.published_at, c.updated_at, c.title, c.description_en FROM cve_summary_fts AS fts JOIN cve AS c ON c.cve_id=fts.cve_id WHERE cve_summary_fts MATCH ? AND (? OR c.state=0) ORDER BY bm25(cve_summary_fts), c.updated_at DESC LIMIT ?")
                .bind(query).bind(include_rejected).bind(limit.max(1)).fetch_all(connection).await
        })).await
    }

    /// Searches only the normalized CVE reference projection, not title or description text.
    pub async fn search_cves_by_reference_text(
        &self,
        query: &str,
        include_rejected: bool,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SqlxCveSummary>, sqlx::Error> {
        let Some(query) = fts_query(query) else {
            return Ok(Vec::new());
        };
        let query = format!("reference_text : ({query})");
        self.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query_as("SELECT c.cve_id, c.state, c.published_at, c.updated_at, c.title, c.description_en FROM cve_summary_fts AS fts JOIN cve AS c ON c.cve_id=fts.cve_id WHERE cve_summary_fts MATCH ? AND (? OR c.state=0) ORDER BY bm25(cve_summary_fts), c.updated_at DESC LIMIT ? OFFSET ?")
                .bind(query).bind(include_rejected).bind(limit.max(1)).bind(offset.max(0)).fetch_all(connection).await
        })).await
    }

    /// Lists recent CVEs using canonical UTC timestamps.
    pub async fn recent_cves(
        &self,
        include_rejected: bool,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SqlxCveSummary>, sqlx::Error> {
        self.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query_as("SELECT cve_id, state, published_at, updated_at, title, description_en FROM cve WHERE (? OR state=0) ORDER BY updated_at DESC, cve_id DESC LIMIT ? OFFSET ?")
                .bind(include_rejected).bind(limit.max(1)).bind(offset.max(0)).fetch_all(connection).await
        })).await
    }

    /// Searches CVEs by CWE IDs using a bound JSON array, not dynamically generated SQL.
    pub async fn search_cves_by_cwes(
        &self,
        cwe_ids: &[String],
        include_rejected: bool,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SqlxCveSummary>, sqlx::Error> {
        let ids = cwe_ids
            .iter()
            .filter_map(|id| {
                id.trim()
                    .strip_prefix("CWE-")
                    .unwrap_or(id.trim())
                    .parse::<i64>()
                    .ok()
            })
            .collect::<Vec<_>>();
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let ids = serde_json::to_string(&ids)
            .map_err(|error| sqlx::Error::Protocol(format!("failed to encode CWE IDs: {error}")))?;
        self.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query_as("SELECT DISTINCT c.cve_id, c.state, c.published_at, c.updated_at, c.title, c.description_en FROM cve AS c JOIN cve_cwe ON cve_cwe.cve_db_id=c.id WHERE cve_cwe.cwe_id IN (SELECT value FROM json_each(?)) AND (? OR c.state=0) ORDER BY c.updated_at DESC, c.cve_id DESC LIMIT ? OFFSET ?")
                .bind(ids).bind(include_rejected).bind(limit.max(1)).bind(offset.max(0)).fetch_all(connection).await
        })).await
    }

    /// Searches the normalized CWE catalog by numeric ID or description text.
    pub async fn search_cwes(
        &self,
        query: Option<&str>,
        limit: i64,
    ) -> Result<Vec<SqlxCwe>, sqlx::Error> {
        let query = query.map(str::trim).filter(|query| !query.is_empty());
        let id = query.and_then(|query| {
            query
                .trim_start_matches("CWE-")
                .trim_start_matches("CWE")
                .parse::<i64>()
                .ok()
        });
        let text = if id.is_none() {
            query.map(|query| format!("%{query}%"))
        } else {
            None
        };
        self.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query_as("SELECT id, description FROM cwe WHERE (? IS NULL OR id=?) AND (? IS NULL OR description LIKE ?) ORDER BY id LIMIT ?")
                .bind(id).bind(id).bind(&text).bind(&text).bind(limit.max(1)).fetch_all(connection).await
        })).await
    }

    /// Looks up a CWE by its external numeric identifier.
    pub async fn find_cwe(&self, id: i64) -> Result<Option<SqlxCwe>, sqlx::Error> {
        self.writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query_as("SELECT id, description FROM cwe WHERE id=?")
                        .bind(id)
                        .fetch_optional(connection)
                        .await
                })
            })
            .await
    }

    /// Searches normalized affected vendor/product/package fields with bound LIKE predicates.
    pub async fn search_cves_by_affected(
        &self,
        vendor: Option<String>,
        product: Option<String>,
        exact: bool,
        include_rejected: bool,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SqlxCveSummary>, sqlx::Error> {
        let vendor = vendor.map(|value| if exact { value } else { format!("%{value}%") });
        let product = product.map(|value| if exact { value } else { format!("%{value}%") });
        self.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query_as("SELECT DISTINCT c.cve_id, c.state, c.published_at, c.updated_at, c.title, c.description_en FROM cve AS c JOIN cve_affected AS affected ON affected.cve_db_id=c.id WHERE (? OR c.state=0) AND (? IS NULL OR CASE WHEN ? THEN affected.vendor=? ELSE affected.vendor LIKE ? END) AND (? IS NULL OR CASE WHEN ? THEN (affected.product=? OR affected.package_name=?) ELSE (affected.product LIKE ? OR affected.package_name LIKE ?) END) ORDER BY c.updated_at DESC, c.cve_id DESC LIMIT ? OFFSET ?")
                .bind(include_rejected)
                .bind(&vendor).bind(exact).bind(&vendor).bind(&vendor)
                .bind(&product).bind(exact).bind(&product).bind(&product).bind(&product).bind(&product)
                .bind(limit.max(1)).bind(offset.max(0)).fetch_all(connection).await
        })).await
    }

    /// Searches affected records and, when supplied, a provider-declared affected version value.
    /// This is intentionally a candidate lookup: CVE version expressions are not interpreted as
    /// a vulnerability verdict here.
    pub async fn search_cves_by_affected_version(
        &self,
        vendor: Option<String>,
        product: Option<String>,
        version: Option<String>,
        include_rejected: bool,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SqlxCveSummary>, sqlx::Error> {
        let vendor = vendor.map(|value| format!("%{value}%"));
        let product = product.map(|value| format!("%{value}%"));
        let version = version.filter(|value| !value.trim().is_empty());
        self.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query_as("SELECT DISTINCT c.cve_id, c.state, c.published_at, c.updated_at, c.title, c.description_en FROM cve AS c JOIN cve_affected AS affected ON affected.cve_db_id=c.id WHERE (? OR c.state=0) AND (? IS NULL OR affected.vendor LIKE ?) AND (? IS NULL OR affected.product LIKE ? OR affected.package_name LIKE ?) AND (? IS NULL OR affected.version_text LIKE '%' || ? || '%') ORDER BY c.updated_at DESC, c.cve_id DESC LIMIT ? OFFSET ?")
                .bind(include_rejected)
                .bind(&vendor).bind(&vendor)
                .bind(&product).bind(&product).bind(&product)
                .bind(&version).bind(&version)
                .bind(limit.max(1)).bind(offset.max(0)).fetch_all(connection).await
        })).await
    }

    /// Searches normalized CVSS fields with optional score, severity, and version filters.
    pub async fn search_cves_by_cvss(
        &self,
        options: SqlxCvssSearch,
        include_rejected: bool,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SqlxCveSummary>, sqlx::Error> {
        self.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query_as("SELECT DISTINCT c.cve_id, c.state, c.published_at, c.updated_at, c.title, c.description_en FROM cve AS c JOIN cve_cvss AS cvss ON cvss.cve_db_id=c.id WHERE (? OR c.state=0) AND (? IS NULL OR cvss.base_score >= ?) AND (? IS NULL OR cvss.base_score <= ?) AND (? IS NULL OR UPPER(cvss.base_severity)=UPPER(?)) AND (? IS NULL OR cvss.version=?) ORDER BY cvss.base_score DESC, c.updated_at DESC, c.cve_id DESC LIMIT ? OFFSET ?")
                .bind(include_rejected)
                .bind(options.min_score).bind(options.min_score)
                .bind(options.max_score).bind(options.max_score)
                .bind(&options.severity).bind(&options.severity)
                .bind(&options.version).bind(&options.version)
                .bind(limit.max(1)).bind(offset.max(0)).fetch_all(connection).await
        })).await
    }

    /// Searches canonical UTC published/updated timestamps.
    pub async fn search_cves_by_dates(
        &self,
        published_since: Option<String>,
        updated_since: Option<String>,
        include_rejected: bool,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SqlxCveSummary>, sqlx::Error> {
        self.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query_as("SELECT cve_id, state, published_at, updated_at, title, description_en FROM cve WHERE (? OR state=0) AND (? IS NULL OR published_at >= ?) AND (? IS NULL OR updated_at >= ?) ORDER BY updated_at DESC, cve_id DESC LIMIT ? OFFSET ?")
                .bind(include_rejected)
                .bind(&published_since).bind(&published_since)
                .bind(&updated_since).bind(&updated_since)
                .bind(limit.max(1)).bind(offset.max(0)).fetch_all(connection).await
        })).await
    }

    /// Runs a combined normalized search in one query while preserving AND semantics between
    /// supplied filters.
    pub async fn search_cves_advanced(
        &self,
        filters: SqlxCveSearch,
        include_rejected: bool,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SqlxCveSummary>, sqlx::Error> {
        let cwe_ids = filters
            .cwe_ids
            .iter()
            .filter_map(|value| {
                value
                    .trim()
                    .strip_prefix("CWE-")
                    .unwrap_or(value.trim())
                    .parse::<i64>()
                    .ok()
            })
            .collect::<Vec<_>>();
        let cwe_ids = (!cwe_ids.is_empty())
            .then(|| serde_json::to_string(&cwe_ids))
            .transpose()
            .map_err(|error| sqlx::Error::Protocol(format!("failed to encode CWE IDs: {error}")))?;
        let text = filters.text.as_deref().and_then(fts_query);
        self.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query_as("SELECT DISTINCT c.cve_id, c.state, c.published_at, c.updated_at, c.title, c.description_en FROM cve AS c WHERE (? OR c.state=0) AND (? IS NULL OR c.published_at >= ?) AND (? IS NULL OR c.published_at <= ?) AND (? IS NULL OR c.updated_at >= ?) AND (? IS NULL OR c.updated_at <= ?) AND (? IS NULL OR c.cve_id IN (SELECT cve_id FROM cve_summary_fts WHERE cve_summary_fts MATCH ?)) AND (? IS NULL OR EXISTS (SELECT 1 FROM cve_cwe WHERE cve_cwe.cve_db_id=c.id AND cve_cwe.cwe_id IN (SELECT value FROM json_each(?)))) AND ((? IS NULL AND ? IS NULL AND ? IS NULL AND ? IS NULL) OR EXISTS (SELECT 1 FROM cve_affected AS affected WHERE affected.cve_db_id=c.id AND (? IS NULL OR affected.vendor LIKE ?) AND (? IS NULL OR affected.product LIKE ?) AND (? IS NULL OR affected.vendor=?) AND (? IS NULL OR affected.product=?))) AND ((? IS NULL AND ? IS NULL AND ? IS NULL AND ? IS NULL) OR EXISTS (SELECT 1 FROM cve_cvss AS cvss WHERE cvss.cve_db_id=c.id AND (? IS NULL OR cvss.base_score >= ?) AND (? IS NULL OR cvss.base_score <= ?) AND (? IS NULL OR lower(cvss.base_severity)=lower(?)) AND (? IS NULL OR cvss.version=?))) ORDER BY c.updated_at DESC, c.cve_id DESC LIMIT ? OFFSET ?")
                .bind(include_rejected)
                .bind(&filters.published_since).bind(&filters.published_since)
                .bind(&filters.published_until).bind(&filters.published_until)
                .bind(&filters.updated_since).bind(&filters.updated_since)
                .bind(&filters.updated_until).bind(&filters.updated_until)
                .bind(&text).bind(&text)
                .bind(&cwe_ids).bind(&cwe_ids)
                .bind(&filters.vendor_like).bind(&filters.product_like).bind(&filters.vendor_exact).bind(&filters.product_exact)
                .bind(&filters.vendor_like).bind(&filters.vendor_like)
                .bind(&filters.product_like).bind(&filters.product_like)
                .bind(&filters.vendor_exact).bind(&filters.vendor_exact)
                .bind(&filters.product_exact).bind(&filters.product_exact)
                .bind(filters.cvss.min_score).bind(filters.cvss.max_score).bind(&filters.cvss.severity).bind(&filters.cvss.version)
                .bind(filters.cvss.min_score).bind(filters.cvss.min_score)
                .bind(filters.cvss.max_score).bind(filters.cvss.max_score)
                .bind(&filters.cvss.severity).bind(&filters.cvss.severity)
                .bind(&filters.cvss.version).bind(&filters.cvss.version)
                .bind(limit.max(1)).bind(offset.max(0)).fetch_all(connection).await
        })).await
    }

    /// Loads full normalized detail in batches per CVE, preserving source ordering in each detail.
    pub async fn cve_detail(&self, cve_id: &str) -> Result<Option<SqlxCveDetail>, sqlx::Error> {
        let cve_id = cve_id.to_owned();
        self.writer.with_connection(|connection| Box::pin(async move {
            let Some(id): Option<i64> = sqlx::query_scalar("SELECT id FROM cve WHERE cve_id=?").bind(&cve_id).fetch_optional(&mut *connection).await? else { return Ok(None); };
            let cvss = sqlx::query_as("SELECT version, base_score, base_severity, vector_string, source FROM cve_cvss WHERE cve_db_id=? ORDER BY id").bind(id).fetch_all(&mut *connection).await?;
            let cwes = sqlx::query_as("SELECT cwe.id, cwe.description FROM cve_cwe JOIN cwe ON cwe.id=cve_cwe.cwe_id WHERE cve_cwe.cve_db_id=? ORDER BY cwe.id").bind(id).fetch_all(&mut *connection).await?;
            let affected_rows: Vec<AffectedRow> = sqlx::query_as("SELECT id, vendor, product, package_name, raw_json FROM cve_affected WHERE cve_db_id=? ORDER BY id").bind(id).fetch_all(&mut *connection).await?;
            let mut affected = Vec::with_capacity(affected_rows.len());
            for (_affected_id, vendor, product, package_name, raw_json) in affected_rows {
                let versions = serde_json::from_str::<Vec<(Option<String>, Option<String>, Option<String>, Option<String>, Option<String>)>>(&raw_json)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|(version, status, version_type, less_than, less_than_or_equal)| SqlxAffectedVersion { version, status, version_type, less_than, less_than_or_equal })
                    .collect();
                affected.push(SqlxAffected { vendor, product, package_name, versions });
            }
            let raw_json: String = sqlx::query_scalar("SELECT raw_json FROM cve WHERE id=?").bind(id).fetch_one(&mut *connection).await?;
            let references = serde_json::from_str::<Value>(&raw_json)
                .map(|value| cve_references(value.pointer("/containers/cna"), value.pointer("/containers/adp")))
                .unwrap_or_default();
            let epss = sqlx::query_as("SELECT epss, percentile, score_date, model_version FROM epss_current WHERE cve_id=?").bind(&cve_id).fetch_optional(&mut *connection).await?;
            let kev = sqlx::query_as("SELECT vendor_project, product, vulnerability_name, COALESCE(date_added, '') AS date_added, due_date FROM kev_entries WHERE cve_id=?").bind(&cve_id).fetch_optional(&mut *connection).await?;
            let osv_advisories = sqlx::query_as("SELECT advisory.osv_id, COALESCE(advisory.modified_at, '') AS modified_at, advisory.summary, advisory.withdrawn_at FROM osv_aliases AS alias JOIN osv_advisories AS advisory ON advisory.osv_id=alias.osv_id WHERE alias.alias_id=? ORDER BY advisory.modified_at DESC, advisory.osv_id").bind(&cve_id).fetch_all(&mut *connection).await?;
            Ok(Some(SqlxCveDetail { cvss, cwes, affected, references, epss, kev, osv_advisories }))
        })).await
    }

    pub async fn cve_summary_with_detail(
        &self,
        cve_id: &str,
    ) -> Result<Option<SqlxCveSummaryWithDetail>, sqlx::Error> {
        let Some(summary) = self.find_cve_summary(cve_id).await? else {
            return Ok(None);
        };
        let detail = self
            .cve_detail(cve_id)
            .await?
            .expect("summary and detail share the CVE parent row");
        Ok(Some(SqlxCveSummaryWithDetail { summary, detail }))
    }

    /// Loads full normalized details in caller order. This deliberately reuses the canonical
    /// single-CVE path so batch callers cannot silently omit CVSS or CWE data.
    pub async fn cve_details(
        &self,
        cve_ids: &[String],
    ) -> Result<Vec<Option<SqlxCveDetail>>, sqlx::Error> {
        let mut details = Vec::with_capacity(cve_ids.len());
        for cve_id in cve_ids {
            details.push(self.cve_detail(cve_id).await?);
        }
        Ok(details)
    }

    pub async fn database_status(&self) -> Result<SqlxDatabaseStatus, sqlx::Error> {
        self.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query_as("SELECT (SELECT COUNT(*) FROM cve) AS cve_count, (SELECT COUNT(*) FROM osv_advisories) AS osv_count, (SELECT COUNT(*) FROM cwe) AS cwe_count, (SELECT COUNT(*) FROM cve_affected) AS affected_count, (SELECT COUNT(*) FROM cve_cvss) AS cvss_count, (SELECT MAX(updated_at) FROM cve) AS latest_cve_updated_at")
                .fetch_one(connection).await
        })).await
    }

    pub async fn kev_entries(
        &self,
        cve_id: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SqlxKevEntry>, sqlx::Error> {
        let cve_id = cve_id.map(str::to_owned);
        self.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query_as("SELECT kev.cve_id, kev.vendor_project, kev.product, kev.vulnerability_name, COALESCE(kev.date_added, '') AS date_added, kev.due_date FROM kev_entries AS kev WHERE (? IS NULL OR kev.cve_id=?) ORDER BY kev.date_added DESC, kev.cve_id LIMIT ? OFFSET ?")
                .bind(&cve_id).bind(&cve_id).bind(limit.max(1)).bind(offset.max(0)).fetch_all(connection).await
        })).await
    }

    pub async fn search_epss_risk(
        &self,
        min_score: Option<f64>,
        min_percentile: Option<f64>,
        include_rejected: bool,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SqlxEpssRisk>, sqlx::Error> {
        self.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query_as("SELECT cve.cve_id, epss.epss, epss.percentile, EXISTS(SELECT 1 FROM kev_entries WHERE kev_entries.cve_id=cve.cve_id) AS kev_listed FROM epss_current AS epss JOIN cve ON cve.cve_id=epss.cve_id WHERE (? OR cve.state=0) AND (? IS NULL OR epss.epss>=?) AND (? IS NULL OR epss.percentile>=?) ORDER BY epss.epss DESC, epss.percentile DESC, cve.cve_id LIMIT ? OFFSET ?")
                .bind(include_rejected).bind(min_score).bind(min_score).bind(min_percentile).bind(min_percentile).bind(limit.max(1)).bind(offset.max(0)).fetch_all(connection).await
        })).await
    }

    pub async fn source_sync_states(&self) -> Result<Vec<SqlxSourceSyncState>, sqlx::Error> {
        self.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query_as("SELECT source, status, last_cursor, error_message FROM source_sync_state ORDER BY source")
                .fetch_all(connection).await
        })).await
    }

    pub async fn metadata_value(&self, key: &str) -> Result<Option<String>, sqlx::Error> {
        let key = key.to_owned();
        self.writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query_scalar("SELECT value FROM app_metadata WHERE key=?")
                        .bind(key)
                        .fetch_optional(connection)
                        .await
                })
            })
            .await
    }

    /// Resolves only alias-equivalent identifiers transitively. Upstream and related edges are
    /// intentionally excluded because they do not establish vulnerability identity.
    pub async fn resolve_identifier(
        &self,
        identifier: &str,
    ) -> Result<SqlxIdentifierResolution, sqlx::Error> {
        let identifier = identifier.to_owned();
        self.writer.with_connection(|connection| Box::pin(async move {
            let related: Vec<String> = sqlx::query_scalar("WITH RECURSIVE related(identifier) AS (SELECT identifier FROM vulnerability_identifiers WHERE identifier=? COLLATE NOCASE UNION SELECT edge.to_identifier FROM vulnerability_identifier_edges AS edge JOIN related ON edge.from_identifier=related.identifier WHERE edge.relation_type='alias' UNION SELECT edge.from_identifier FROM vulnerability_identifier_edges AS edge JOIN related ON edge.to_identifier=related.identifier WHERE edge.relation_type='alias') SELECT identifier FROM related ORDER BY identifier")
                .bind(&identifier).fetch_all(&mut *connection).await?;
            let related_cve_ids = related.iter().filter(|value| value.starts_with("CVE-")).cloned().collect();
            let related_osv_ids = related.iter().filter(|value| !value.starts_with("CVE-")).cloned().collect();
            Ok(SqlxIdentifierResolution { identifier, related_cve_ids, related_osv_ids })
        })).await
    }

    /// Returns typed graph edges incident to a public identifier without exposing internal IDs.
    pub async fn identifier_edges(
        &self,
        identifier: &str,
    ) -> Result<Vec<SqlxIdentifierEdge>, sqlx::Error> {
        let identifier = identifier.to_owned();
        self.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query_as("SELECT from_identifier, to_identifier, relation_type, source, confidence, evidence_json FROM vulnerability_identifier_edges WHERE from_identifier=? COLLATE NOCASE OR to_identifier=? COLLATE NOCASE ORDER BY relation_type, from_identifier, to_identifier, source")
                .bind(&identifier).bind(&identifier).fetch_all(connection).await
        })).await
    }

    /// Finds OSV package candidates and evaluates supported version ranges. A name match alone
    /// remains `unknown` rather than a confirmed vulnerability.
    pub async fn query_osv_package(
        &self,
        ecosystem: &str,
        package_name: &str,
        version: &str,
    ) -> Result<Vec<SqlxPackageFinding>, sqlx::Error> {
        self.query_osv_package_with_purl(ecosystem, package_name, version, None)
            .await
    }

    /// Queries OSV package records by normalized ecosystem/name and, when available, purl.
    /// A purl is an additional locator rather than a replacement for the source package name:
    /// feeds commonly omit it, so exact name matches must remain discoverable.
    pub async fn query_osv_package_with_purl(
        &self,
        ecosystem: &str,
        package_name: &str,
        version: &str,
        purl: Option<&str>,
    ) -> Result<Vec<SqlxPackageFinding>, sqlx::Error> {
        let ecosystem = ecosystem.to_owned();
        let package_name = package_name.to_owned();
        let version = version.to_owned();
        let purl = purl.map(str::to_owned);
        self.writer.with_connection(|connection| Box::pin(async move {
            let packages: Vec<(i64, String)> = sqlx::query_as("SELECT package.id, package.osv_id FROM osv_affected_packages AS package JOIN osv_advisories AS advisory ON advisory.osv_id=package.osv_id WHERE advisory.withdrawn_at IS NULL AND package.ecosystem=? COLLATE NOCASE AND (package.package_name=? COLLATE NOCASE OR (? IS NOT NULL AND package.purl=?)) ORDER BY package.osv_id")
                .bind(&ecosystem).bind(&package_name).bind(&purl).bind(&purl).fetch_all(&mut *connection).await?;
            let mut findings = Vec::with_capacity(packages.len());
            for (package_id, osv_id) in packages {
                let events: Vec<(i64, String, String, String)> = sqlx::query_as("SELECT range.id, range.range_type, event.event_type, event.value FROM osv_ranges AS range JOIN osv_range_events AS event ON event.range_id=range.id WHERE range.affected_package_id=? ORDER BY range.id, event.id")
                    .bind(package_id).fetch_all(&mut *connection).await?;
                let mut ranges = Vec::<OsvRange>::new();
                let mut current_id = None;
                for (range_id, range_type, event_type, value) in events {
                    if current_id != Some(range_id) {
                        current_id = Some(range_id);
                        ranges.push(OsvRange { range_type, events: Vec::new() });
                    }
                    if let Some(range) = ranges.last_mut() { range.events.push((event_type, value)); }
                }
                let explicit_version: Option<i64> = sqlx::query_scalar(
                    "SELECT 1 FROM osv_versions WHERE affected_package_id=? AND version=? LIMIT 1",
                )
                .bind(package_id)
                .bind(&version)
                .fetch_optional(&mut *connection)
                .await?;
                let matched = explicit_version.map_or_else(
                    || evaluate_version(&ecosystem, &version, &ranges),
                    |_| super::package_eval::VersionMatch {
                        status: "affected".to_owned(),
                        confidence: "high".to_owned(),
                    },
                );
                let cve_ids = sqlx::query_scalar("SELECT alias_id FROM osv_aliases WHERE osv_id=? AND alias_id LIKE 'CVE-%' ORDER BY alias_id")
                    .bind(&osv_id).fetch_all(&mut *connection).await?;
                findings.push(SqlxPackageFinding { osv_id, cve_ids, status: matched.status, confidence: matched.confidence });
            }
            Ok(findings)
        })).await
    }

    pub async fn set_metadata_value(&self, key: &str, value: &str) -> Result<(), sqlx::Error> {
        let key = key.to_owned();
        let value = value.to_owned();
        self.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query("INSERT INTO app_metadata (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at")
                .bind(key).bind(value).bind(chrono::Utc::now().to_rfc3339()).execute(connection).await?;
            Ok(())
        })).await
    }

    /// Replaces CWE catalog metadata, including status and the primary `ChildOf` relationship.
    /// CVE records may create a placeholder row first; catalog data deliberately takes precedence.
    pub async fn upsert_cwe_catalog(
        &self,
        catalog: &WeaknessCatalog,
    ) -> Result<usize, sqlx::Error> {
        let mut entries = Vec::new();
        if let Some(weaknesses) = &catalog.weaknesses {
            entries.extend(weaknesses.weakness.iter().map(|weakness| {
                let parent_id = weakness.related_weaknesses.as_ref().and_then(|relations| {
                    relations
                        .related_weakness
                        .iter()
                        .find(|relation| matches!(relation.nature, RelatedNature::ChildOf))
                        .map(|relation| relation.cwe_id)
                });
                (
                    weakness.id,
                    weakness.description.clone(),
                    weakness.status.as_ref().to_owned(),
                    parent_id,
                )
            }));
        }
        if let Some(categories) = &catalog.categories {
            entries.extend(categories.category.iter().map(|category| {
                (
                    category.id,
                    category.name.clone(),
                    category.status.as_ref().to_owned(),
                    None,
                )
            }));
        }
        if let Some(views) = &catalog.views {
            entries.extend(views.view.iter().map(|view| {
                (
                    view.id,
                    view.name.clone(),
                    view.status.as_ref().to_owned(),
                    None,
                )
            }));
        }
        let count = entries.len();
        self.writer
            .with_connection(|connection| {
                Box::pin(async move {
                    let mut transaction = connection.begin().await?;
                    for chunk in entries.chunks(2_000) {
                        let mut query = QueryBuilder::<Sqlite>::new(
                            "INSERT INTO cwe (id, description, status, parent_id) ",
                        );
                        query.push_values(chunk, |mut row, (id, description, status, parent_id)| {
                            row.push_bind(id)
                                .push_bind(description)
                                .push_bind(status)
                                .push_bind(parent_id);
                        });
                        query.push(" ON CONFLICT(id) DO UPDATE SET description=excluded.description, status=excluded.status, parent_id=excluded.parent_id");
                        query.build().execute(&mut *transaction).await?;
                    }
                    transaction.commit().await?;
                    Ok(count)
                })
            })
            .await
    }

    pub async fn mark_cve_asset_applied(
        &self,
        filename: &str,
        source_url: &str,
    ) -> Result<(), sqlx::Error> {
        let filename = filename.to_owned();
        let source_url = source_url.to_owned();
        self.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query("INSERT INTO app_metadata (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at")
                .bind(format!("cve_asset:{filename}")).bind(source_url).bind(chrono::Utc::now().to_rfc3339()).execute(connection).await?;
            Ok(())
        })).await
    }

    /// Searches OSV advisories through the stable external-content FTS index.
    pub async fn search_osv(
        &self,
        query: &str,
        limit: i64,
    ) -> Result<Vec<SqlxOsvSummary>, sqlx::Error> {
        let Some(query) = fts_query(query) else {
            return Ok(Vec::new());
        };
        self.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query_as("SELECT advisory.osv_id, COALESCE(advisory.modified_at, '') AS modified_at, advisory.summary, advisory.withdrawn_at FROM osv_text_fts JOIN osv_advisories AS advisory ON advisory.osv_id=osv_text_fts.osv_id WHERE osv_text_fts MATCH ? ORDER BY bm25(osv_text_fts), advisory.modified_at DESC LIMIT ?")
                .bind(query).bind(limit.max(1)).fetch_all(connection).await
        })).await
    }

    /// Finds one OSV advisory by its public identifier.
    pub async fn find_osv_summary(
        &self,
        osv_id: &str,
    ) -> Result<Option<SqlxOsvSummary>, sqlx::Error> {
        let osv_id = osv_id.to_owned();
        self.writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query_as("SELECT osv_id, COALESCE(modified_at, '') AS modified_at, summary, withdrawn_at FROM osv_advisories WHERE osv_id=? COLLATE NOCASE")
                        .bind(osv_id)
                        .fetch_optional(connection)
                        .await
                })
            })
            .await
    }

    /// Marks an OSV synchronization as running and returns its last completed cursor.
    ///
    /// Import batches deliberately do not touch the cursor. Call `complete_osv_sync` only after
    /// all batches, derived indexes, and integrity checks have succeeded.
    pub async fn begin_osv_sync(&self) -> Result<Option<String>, sqlx::Error> {
        self.writer
            .with_connection(|connection| {
                Box::pin(async move {
                    let mut transaction = connection.begin().await?;
                    sqlx::query("INSERT OR IGNORE INTO db_sources (source, display_name, source_type, default_filename, raw_format) VALUES ('OSV', 'OSV.dev', 'vulnerability_db', 'all.zip', 'json')")
                        .execute(&mut *transaction)
                        .await?;
                    let cursor = sqlx::query("SELECT last_cursor FROM source_sync_state WHERE source='OSV'")
                        .fetch_optional(&mut *transaction)
                        .await?
                        .map(|row| row.try_get::<Option<String>, _>(0))
                        .transpose()?
                        .flatten();
                    sqlx::query("INSERT INTO source_sync_state (source, status) VALUES ('OSV', 'running') ON CONFLICT(source) DO UPDATE SET status='running', error_message=NULL")
                        .execute(&mut *transaction)
                        .await?;
                    transaction.commit().await?;
                    Ok(cursor)
                })
            })
            .await
    }

    /// Records a successful complete OSV synchronization and advances the cursor once.
    pub async fn complete_osv_sync(&self, cursor: &str) -> Result<(), sqlx::Error> {
        let cursor = cursor.to_owned();
        self.writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query("UPDATE source_sync_state SET status='success', last_cursor=?, error_message=NULL WHERE source='OSV'")
                        .bind(cursor)
                        .execute(connection)
                        .await?;
                    Ok(())
                })
            })
            .await
    }

    /// Records a failed OSV synchronization without advancing the previous completed cursor.
    pub async fn fail_osv_sync(&self, error: &str) -> Result<(), sqlx::Error> {
        let error = error.to_owned();
        self.writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query("UPDATE source_sync_state SET status='failed', error_message=? WHERE source='OSV'")
                        .bind(error)
                        .execute(connection)
                        .await?;
                    Ok(())
                })
            })
            .await
    }

    /// Imports a parsed batch in one transaction. Cursor advancement remains the caller's
    /// explicit all-or-nothing completion step, so retries are safe after a partial failure.
    pub async fn import_osv_records(
        &self,
        records: Vec<OsvRawRecord>,
    ) -> Result<usize, sqlx::Error> {
        self.import_osv_record_batch(records, true, false).await
    }

    /// Imports OSV batches while deferring the global FTS rebuild to the ZIP-level caller.
    pub async fn import_osv_records_deferred_search(
        &self,
        records: Vec<OsvRawRecord>,
    ) -> Result<usize, sqlx::Error> {
        self.import_osv_record_batch(records, false, false).await
    }

    /// Inserts an OSV batch into an empty replacement database. Unlike the update path, this
    /// avoids conflict handling and child-row deletion while bulk-load indexes are absent.
    pub async fn import_osv_records_bulk_init(
        &self,
        records: Vec<OsvRawRecord>,
    ) -> Result<usize, sqlx::Error> {
        self.import_osv_record_batch(records, false, true).await
    }

    /// Imports one current-schema OSV advisory atomically on the dedicated writer.
    pub async fn import_osv_record(&self, record: OsvRawRecord) -> Result<(), sqlx::Error> {
        self.import_osv_record_with_search(record, true).await
    }

    async fn import_osv_record_with_search(
        &self,
        record: OsvRawRecord,
        update_search: bool,
    ) -> Result<(), sqlx::Error> {
        let advisory = OsvAdvisory::parse_json(record.raw_json.as_bytes())
            .map_err(|error| sqlx::Error::Protocol(format!("invalid OSV JSON: {error}")))?;
        advisory
            .validate_schema_shape()
            .map_err(|error| sqlx::Error::Protocol(error.to_string()))?;
        let raw_json = record.raw_json;
        let modified_at = canonical_utc(advisory.modified.as_deref().expect("validated modified"))
            .map_err(|error| {
                sqlx::Error::Protocol(format!("invalid OSV modified timestamp: {error}"))
            })?;
        let published_at = advisory
            .published
            .as_deref()
            .map(canonical_utc)
            .transpose()
            .map_err(|error| {
                sqlx::Error::Protocol(format!("invalid OSV published timestamp: {error}"))
            })?;
        let withdrawn_at = advisory
            .withdrawn
            .as_deref()
            .map(canonical_utc)
            .transpose()
            .map_err(|error| {
                sqlx::Error::Protocol(format!("invalid OSV withdrawn timestamp: {error}"))
            })?;
        let search_aliases = advisory.aliases.join(" ");
        let search_packages = advisory
            .affected
            .iter()
            .filter_map(|affected| affected.package.as_ref())
            .flat_map(|package| {
                [
                    package.ecosystem.as_deref(),
                    package.name.as_deref(),
                    package.purl.as_deref(),
                ]
            })
            .flatten()
            .collect::<Vec<_>>()
            .join(" ");
        self.writer
            .with_connection(|connection| {
                Box::pin(async move {
                    let mut transaction = connection.begin().await?;
                    sqlx::query("INSERT OR IGNORE INTO db_sources (source, display_name, source_type, default_filename, raw_format) VALUES ('OSV', 'OSV.dev', 'vulnerability_db', 'all.zip', 'json')")
                        .execute(&mut *transaction).await?;
                    sqlx::query("INSERT INTO osv_raw_records (osv_id, source_path, provider_published_at, provider_modified_at, fetched_at, content_hash, raw_json) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(osv_id) DO UPDATE SET source_path=excluded.source_path, provider_published_at=excluded.provider_published_at, provider_modified_at=excluded.provider_modified_at, fetched_at=excluded.fetched_at, content_hash=excluded.content_hash, raw_json=excluded.raw_json")
                        .bind(&advisory.id)
                        .bind(&record.source_path)
                        .bind(&published_at)
                        .bind(&modified_at)
                        .bind(chrono::Utc::now().to_rfc3339())
                        .bind(Md5::digest(raw_json.as_bytes()).iter().map(|byte| format!("{byte:02x}")).collect::<String>())
                        .bind(&raw_json)
                        .execute(&mut *transaction).await?;
                    let raw_record_id: i64 = sqlx::query_scalar("SELECT id FROM osv_raw_records WHERE osv_id=?")
                        .bind(&advisory.id).fetch_one(&mut *transaction).await?;
                    sqlx::query("INSERT INTO osv_advisories (osv_id, schema_version, published_at, modified_at, withdrawn_at, summary, details, raw_record_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(osv_id) DO UPDATE SET schema_version=excluded.schema_version, published_at=excluded.published_at, modified_at=excluded.modified_at, withdrawn_at=excluded.withdrawn_at, summary=excluded.summary, details=excluded.details, raw_record_id=excluded.raw_record_id")
                        .bind(&advisory.id)
                        .bind(advisory.schema_version.as_deref().unwrap_or_default())
                        .bind(&published_at)
                        .bind(&modified_at)
                        .bind(&withdrawn_at)
                        .bind(&advisory.summary)
                        .bind(&advisory.details)
                        .bind(raw_record_id)
                        .execute(&mut *transaction).await?;
                    let now = chrono::Utc::now().to_rfc3339();
                    sqlx::query("INSERT INTO vulnerability_identifiers (identifier, identifier_type, source, first_seen_at, last_seen_at) VALUES (?, 'osv', 'OSV', ?, ?) ON CONFLICT(identifier) DO UPDATE SET last_seen_at=excluded.last_seen_at")
                        .bind(&advisory.id).bind(&now).bind(&now).execute(&mut *transaction).await?;
                    sqlx::query("DELETE FROM osv_aliases WHERE osv_id=?").bind(&advisory.id).execute(&mut *transaction).await?;
                    sqlx::query("DELETE FROM osv_references WHERE osv_id=?").bind(&advisory.id).execute(&mut *transaction).await?;
                    sqlx::query("DELETE FROM osv_range_events WHERE range_id IN (SELECT id FROM osv_ranges WHERE affected_package_id IN (SELECT id FROM osv_affected_packages WHERE osv_id=?))").bind(&advisory.id).execute(&mut *transaction).await?;
                    sqlx::query("DELETE FROM osv_ranges WHERE affected_package_id IN (SELECT id FROM osv_affected_packages WHERE osv_id=?)").bind(&advisory.id).execute(&mut *transaction).await?;
                    sqlx::query("DELETE FROM osv_versions WHERE affected_package_id IN (SELECT id FROM osv_affected_packages WHERE osv_id=?)").bind(&advisory.id).execute(&mut *transaction).await?;
                    sqlx::query("DELETE FROM osv_affected_packages WHERE osv_id=?").bind(&advisory.id).execute(&mut *transaction).await?;
                    sqlx::query("DELETE FROM vulnerability_identifier_edges WHERE from_identifier=? AND source='OSV'").bind(&advisory.id).execute(&mut *transaction).await?;
                    for (relation_type, identifiers) in [("alias", &advisory.aliases), ("upstream", &advisory.upstream), ("related", &advisory.related)] {
                        for identifier in identifiers {
                            let identifier_type = if identifier.starts_with("CVE-") { "cve" } else if identifier.starts_with("GHSA-") { "ghsa" } else { "other" };
                            sqlx::query("INSERT INTO vulnerability_identifiers (identifier, identifier_type, source, first_seen_at, last_seen_at) VALUES (?, ?, 'OSV', ?, ?) ON CONFLICT(identifier) DO UPDATE SET last_seen_at=excluded.last_seen_at")
                                .bind(identifier).bind(identifier_type).bind(&now).bind(&now).execute(&mut *transaction).await?;
                            if relation_type == "alias" {
                                sqlx::query("INSERT OR IGNORE INTO osv_aliases(osv_id, alias_id) VALUES (?, ?)")
                                    .bind(&advisory.id).bind(identifier).execute(&mut *transaction).await?;
                            }
                            sqlx::query("INSERT OR REPLACE INTO vulnerability_identifier_edges(from_identifier, to_identifier, relation_type, source, confidence, evidence_json, created_at) VALUES (?, ?, ?, 'OSV', 'high', '{}', ?)")
                                .bind(&advisory.id).bind(identifier).bind(relation_type).bind(&now).execute(&mut *transaction).await?;
                            if relation_type != "upstream" {
                                sqlx::query("INSERT OR REPLACE INTO vulnerability_identifier_edges(from_identifier, to_identifier, relation_type, source, confidence, evidence_json, created_at) VALUES (?, ?, ?, 'OSV', 'high', '{}', ?)")
                                    .bind(identifier).bind(&advisory.id).bind(relation_type).bind(&now).execute(&mut *transaction).await?;
                            }
                        }
                    }
                    for reference in &advisory.references {
                        sqlx::query("INSERT OR IGNORE INTO osv_references(osv_id, reference_type, url) VALUES (?, ?, ?)")
                            .bind(&advisory.id).bind(&reference.reference_type).bind(&reference.url).execute(&mut *transaction).await?;
                    }
                    for (affected_order, affected) in advisory.affected.iter().enumerate() {
                        let package = affected.package.as_ref();
                        sqlx::query("INSERT INTO osv_affected_packages (osv_id, affected_order, ecosystem, package_name, purl) VALUES (?, ?, ?, ?, ?)")
                            .bind(&advisory.id)
                            .bind(i64::try_from(affected_order).unwrap_or(i64::MAX))
                            .bind(package.and_then(|value| value.ecosystem.as_deref()))
                            .bind(package.and_then(|value| value.name.as_deref()))
                            .bind(package.and_then(|value| value.purl.as_deref()))
                            .execute(&mut *transaction).await?;
                        let package_id: i64 = sqlx::query_scalar("SELECT last_insert_rowid()").fetch_one(&mut *transaction).await?;
                        for (range_order, range) in affected.ranges.iter().enumerate() {
                            sqlx::query("INSERT INTO osv_ranges (affected_package_id, affected_order, range_order, range_type) VALUES (?, ?, ?, ?)")
                                .bind(package_id)
                                .bind(i64::try_from(affected_order).unwrap_or(i64::MAX))
                                .bind(i64::try_from(range_order).unwrap_or(i64::MAX))
                                .bind(range.range_type.as_deref().unwrap_or("ECOSYSTEM"))
                                .execute(&mut *transaction).await?;
                            let range_id: i64 = sqlx::query_scalar("SELECT last_insert_rowid()").fetch_one(&mut *transaction).await?;
                            let mut event_order = 0_i64;
                            for event in &range.events {
                                for (kind, value) in event.event_pairs() {
                                    sqlx::query("INSERT INTO osv_range_events (range_id, event_type, value, event_order) VALUES (?, ?, ?, ?)")
                                        .bind(range_id).bind(kind).bind(value).bind(event_order).execute(&mut *transaction).await?;
                                    event_order += 1;
                                }
                            }
                        }
                        for version in &affected.versions {
                            sqlx::query("INSERT OR IGNORE INTO osv_versions VALUES (?, ?)")
                                .bind(package_id).bind(version).execute(&mut *transaction).await?;
                        }
                    }
                    if update_search {
                        sqlx::query("DELETE FROM osv_text_fts WHERE osv_id=?").bind(&advisory.id).execute(&mut *transaction).await?;
                        sqlx::query("INSERT INTO osv_text_fts(osv_id, summary, details, aliases, packages) VALUES (?, ?, ?, ?, ?)")
                            .bind(&advisory.id).bind(advisory.summary.as_deref().unwrap_or_default()).bind(advisory.details.as_deref().unwrap_or_default()).bind(search_aliases).bind(search_packages).execute(&mut *transaction).await?;
                    }
                    transaction.commit().await
                })
            })
            .await
    }

    async fn import_osv_record_batch(
        &self,
        records: Vec<OsvRawRecord>,
        update_search: bool,
        bulk_init: bool,
    ) -> Result<usize, sqlx::Error> {
        let count = records.len();
        if records.is_empty() {
            return Ok(0);
        }
        let parsed_records = tokio::task::spawn_blocking(move || {
            records
                .into_par_iter()
                .map(Self::osv_batch_input)
                .collect::<Result<Vec<_>, _>>()
        })
        .await
        .map_err(|error| sqlx::Error::Protocol(format!("OSV parser task panicked: {error}")))?
        .map_err(sqlx::Error::Protocol)?;
        let fetched_at = chrono::Utc::now().to_rfc3339();
        self.writer
            .with_connection(|connection| {
                Box::pin(async move {
                    let mut transaction = connection.begin().await?;
                    sqlx::query("INSERT OR IGNORE INTO db_sources (source, display_name, source_type, default_filename, raw_format) VALUES ('OSV', 'OSV.dev', 'vulnerability_db', 'all.zip', 'json')")
                        .execute(&mut *transaction)
                        .await?;
                    for record in parsed_records {
                        Self::write_osv_batch_record(
                            &mut transaction,
                            record,
                            &fetched_at,
                            update_search,
                            bulk_init,
                        )
                        .await?;
                    }
                    transaction.commit().await
                })
            })
            .await?;
        Ok(count)
    }

    fn osv_batch_input(record: OsvRawRecord) -> Result<OsvBatchInput, String> {
        let advisory = OsvAdvisory::parse_json(record.raw_json.as_bytes())
            .map_err(|error| format!("invalid OSV JSON: {error}"))?;
        advisory
            .validate_schema_shape()
            .map_err(|error| error.to_string())?;
        let modified_at = canonical_utc(advisory.modified.as_deref().expect("validated modified"))
            .map_err(|error| format!("invalid OSV modified timestamp: {error}"))?;
        let published_at = advisory
            .published
            .as_deref()
            .map(canonical_utc)
            .transpose()
            .map_err(|error| format!("invalid OSV published timestamp: {error}"))?;
        let withdrawn_at = advisory
            .withdrawn
            .as_deref()
            .map(canonical_utc)
            .transpose()
            .map_err(|error| format!("invalid OSV withdrawn timestamp: {error}"))?;
        let search_aliases = advisory.aliases.join(" ");
        let search_packages = advisory
            .affected
            .iter()
            .filter_map(|affected| affected.package.as_ref())
            .flat_map(|package| {
                [
                    package.ecosystem.as_deref(),
                    package.name.as_deref(),
                    package.purl.as_deref(),
                ]
            })
            .flatten()
            .collect::<Vec<_>>()
            .join(" ");
        let content_hash = Md5::digest(record.raw_json.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        Ok(OsvBatchInput {
            advisory,
            source_path: record.source_path,
            raw_json: record.raw_json,
            modified_at,
            published_at,
            withdrawn_at,
            content_hash,
            search_aliases,
            search_packages,
        })
    }

    async fn write_osv_batch_record(
        transaction: &mut sqlx::Transaction<'_, Sqlite>,
        record: OsvBatchInput,
        fetched_at: &str,
        update_search: bool,
        bulk_init: bool,
    ) -> Result<(), sqlx::Error> {
        let advisory = record.advisory;
        let raw_record_sql = if bulk_init {
            "INSERT INTO osv_raw_records (osv_id, source_path, provider_published_at, provider_modified_at, fetched_at, content_hash, raw_json) VALUES (?, ?, ?, ?, ?, ?, ?)"
        } else {
            "INSERT INTO osv_raw_records (osv_id, source_path, provider_published_at, provider_modified_at, fetched_at, content_hash, raw_json) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(osv_id) DO UPDATE SET source_path=excluded.source_path, provider_published_at=excluded.provider_published_at, provider_modified_at=excluded.provider_modified_at, fetched_at=excluded.fetched_at, content_hash=excluded.content_hash, raw_json=excluded.raw_json"
        };
        sqlx::query(raw_record_sql)
            .bind(&advisory.id)
            .bind(&record.source_path)
            .bind(&record.published_at)
            .bind(&record.modified_at)
            .bind(fetched_at)
            .bind(&record.content_hash)
            .bind(&record.raw_json)
            .execute(&mut **transaction)
            .await?;
        let raw_record_id: i64 =
            sqlx::query_scalar("SELECT id FROM osv_raw_records WHERE osv_id=?")
                .bind(&advisory.id)
                .fetch_one(&mut **transaction)
                .await?;
        let advisory_sql = if bulk_init {
            "INSERT INTO osv_advisories (osv_id, schema_version, published_at, modified_at, withdrawn_at, summary, details, raw_record_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
        } else {
            "INSERT INTO osv_advisories (osv_id, schema_version, published_at, modified_at, withdrawn_at, summary, details, raw_record_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(osv_id) DO UPDATE SET schema_version=excluded.schema_version, published_at=excluded.published_at, modified_at=excluded.modified_at, withdrawn_at=excluded.withdrawn_at, summary=excluded.summary, details=excluded.details, raw_record_id=excluded.raw_record_id"
        };
        sqlx::query(advisory_sql)
            .bind(&advisory.id)
            .bind(advisory.schema_version.as_deref().unwrap_or_default())
            .bind(&record.published_at)
            .bind(&record.modified_at)
            .bind(&record.withdrawn_at)
            .bind(&advisory.summary)
            .bind(&advisory.details)
            .bind(raw_record_id)
            .execute(&mut **transaction)
            .await?;
        sqlx::query("INSERT INTO vulnerability_identifiers (identifier, identifier_type, source, first_seen_at, last_seen_at) VALUES (?, 'osv', 'OSV', ?, ?) ON CONFLICT(identifier) DO UPDATE SET last_seen_at=excluded.last_seen_at")
            .bind(&advisory.id)
            .bind(fetched_at)
            .bind(fetched_at)
            .execute(&mut **transaction)
            .await?;
        if !bulk_init {
            for sql in [
                "DELETE FROM osv_aliases WHERE osv_id=?",
                "DELETE FROM osv_references WHERE osv_id=?",
                "DELETE FROM osv_range_events WHERE range_id IN (SELECT id FROM osv_ranges WHERE affected_package_id IN (SELECT id FROM osv_affected_packages WHERE osv_id=?))",
                "DELETE FROM osv_ranges WHERE affected_package_id IN (SELECT id FROM osv_affected_packages WHERE osv_id=?)",
                "DELETE FROM osv_versions WHERE affected_package_id IN (SELECT id FROM osv_affected_packages WHERE osv_id=?)",
                "DELETE FROM osv_affected_packages WHERE osv_id=?",
                "DELETE FROM vulnerability_identifier_edges WHERE from_identifier=? AND source='OSV'",
            ] {
                sqlx::query(sql)
                    .bind(&advisory.id)
                    .execute(&mut **transaction)
                    .await?;
            }
        }
        for (relation_type, identifiers) in [
            ("alias", &advisory.aliases),
            ("upstream", &advisory.upstream),
            ("related", &advisory.related),
        ] {
            for identifier in identifiers {
                let identifier_type = if identifier.starts_with("CVE-") {
                    "cve"
                } else if identifier.starts_with("GHSA-") {
                    "ghsa"
                } else {
                    "other"
                };
                sqlx::query("INSERT INTO vulnerability_identifiers (identifier, identifier_type, source, first_seen_at, last_seen_at) VALUES (?, ?, 'OSV', ?, ?) ON CONFLICT(identifier) DO UPDATE SET last_seen_at=excluded.last_seen_at")
                    .bind(identifier)
                    .bind(identifier_type)
                    .bind(fetched_at)
                    .bind(fetched_at)
                    .execute(&mut **transaction)
                    .await?;
                if relation_type == "alias" {
                    sqlx::query(
                        "INSERT OR IGNORE INTO osv_aliases(osv_id, alias_id) VALUES (?, ?)",
                    )
                    .bind(&advisory.id)
                    .bind(identifier)
                    .execute(&mut **transaction)
                    .await?;
                }
                sqlx::query("INSERT OR REPLACE INTO vulnerability_identifier_edges(from_identifier, to_identifier, relation_type, source, confidence, evidence_json, created_at) VALUES (?, ?, ?, 'OSV', 'high', '{}', ?)")
                    .bind(&advisory.id)
                    .bind(identifier)
                    .bind(relation_type)
                    .bind(fetched_at)
                    .execute(&mut **transaction)
                    .await?;
                if relation_type != "upstream" {
                    sqlx::query("INSERT OR REPLACE INTO vulnerability_identifier_edges(from_identifier, to_identifier, relation_type, source, confidence, evidence_json, created_at) VALUES (?, ?, ?, 'OSV', 'high', '{}', ?)")
                        .bind(identifier)
                        .bind(&advisory.id)
                        .bind(relation_type)
                        .bind(fetched_at)
                        .execute(&mut **transaction)
                        .await?;
                }
            }
        }
        for reference in &advisory.references {
            sqlx::query("INSERT OR IGNORE INTO osv_references(osv_id, reference_type, url) VALUES (?, ?, ?)")
                .bind(&advisory.id)
                .bind(&reference.reference_type)
                .bind(&reference.url)
                .execute(&mut **transaction)
                .await?;
        }
        for (affected_order, affected) in advisory.affected.iter().enumerate() {
            let package = affected.package.as_ref();
            sqlx::query("INSERT INTO osv_affected_packages (osv_id, affected_order, ecosystem, package_name, purl) VALUES (?, ?, ?, ?, ?)")
                .bind(&advisory.id)
                .bind(i64::try_from(affected_order).unwrap_or(i64::MAX))
                .bind(package.and_then(|value| value.ecosystem.as_deref()))
                .bind(package.and_then(|value| value.name.as_deref()))
                .bind(package.and_then(|value| value.purl.as_deref()))
                .execute(&mut **transaction)
                .await?;
            let package_id: i64 = sqlx::query_scalar("SELECT last_insert_rowid()")
                .fetch_one(&mut **transaction)
                .await?;
            for (range_order, range) in affected.ranges.iter().enumerate() {
                sqlx::query("INSERT INTO osv_ranges (affected_package_id, affected_order, range_order, range_type) VALUES (?, ?, ?, ?)")
                    .bind(package_id)
                    .bind(i64::try_from(affected_order).unwrap_or(i64::MAX))
                    .bind(i64::try_from(range_order).unwrap_or(i64::MAX))
                    .bind(range.range_type.as_deref().unwrap_or("ECOSYSTEM"))
                    .execute(&mut **transaction)
                    .await?;
                let range_id: i64 = sqlx::query_scalar("SELECT last_insert_rowid()")
                    .fetch_one(&mut **transaction)
                    .await?;
                let mut event_order = 0_i64;
                for event in &range.events {
                    for (kind, value) in event.event_pairs() {
                        sqlx::query("INSERT INTO osv_range_events (range_id, event_type, value, event_order) VALUES (?, ?, ?, ?)")
                            .bind(range_id)
                            .bind(kind)
                            .bind(value)
                            .bind(event_order)
                            .execute(&mut **transaction)
                            .await?;
                        event_order += 1;
                    }
                }
            }
            for version in &affected.versions {
                sqlx::query("INSERT OR IGNORE INTO osv_versions VALUES (?, ?)")
                    .bind(package_id)
                    .bind(version)
                    .execute(&mut **transaction)
                    .await?;
            }
        }
        if update_search {
            sqlx::query("DELETE FROM osv_text_fts WHERE osv_id=?")
                .bind(&advisory.id)
                .execute(&mut **transaction)
                .await?;
            sqlx::query("INSERT INTO osv_text_fts(osv_id, summary, details, aliases, packages) VALUES (?, ?, ?, ?, ?)")
                .bind(&advisory.id)
                .bind(advisory.summary.as_deref().unwrap_or_default())
                .bind(advisory.details.as_deref().unwrap_or_default())
                .bind(record.search_aliases)
                .bind(record.search_packages)
                .execute(&mut **transaction)
                .await?;
        }
        Ok(())
    }

    /// Imports the CVE parent row, source record, and stable FTS projection atomically.
    pub async fn import_cve_raw_json(&self, raw_json: String) -> Result<(), sqlx::Error> {
        self.import_cve_raw_jsons(vec![raw_json]).await.map(|_| ())
    }

    /// Imports a CVE batch in one writer transaction. Parsing and ZIP decoding happen before this
    /// call, while every normalized write remains owned by the single physical SQLite connection.
    pub async fn import_cve_raw_jsons(&self, records: Vec<String>) -> Result<usize, sqlx::Error> {
        self.import_cve_raw_jsons_with_search(records, true).await
    }

    /// Imports a batch while deferring global search-index maintenance to the caller.
    pub async fn import_cve_raw_jsons_deferred_search(
        &self,
        records: Vec<String>,
    ) -> Result<usize, sqlx::Error> {
        self.import_cve_raw_jsons_with_search(records, false).await
    }

    async fn import_cve_raw_jsons_with_search(
        &self,
        records: Vec<String>,
        update_search: bool,
    ) -> Result<usize, sqlx::Error> {
        let count = records.len();
        let parsed_records = tokio::task::spawn_blocking(move || {
            records
                .into_par_iter()
                .map(|raw_json| {
                    // `simd-json` performs the structural scan with SIMD before materializing the
                    // serde value used by the normalizer. Keep `raw_json` unchanged because it is
                    // the provider record persisted in `source_raw_records`.
                    let mut bytes = raw_json.as_bytes().to_vec();
                    simd_json::from_slice(&mut bytes)
                        .map(|value| (raw_json, value))
                        .map_err(|error| format!("invalid CVE JSON: {error}"))
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .await
        .map_err(|error| sqlx::Error::Protocol(format!("CVE parser task panicked: {error}")))?
        .map_err(sqlx::Error::Protocol)?;
        self.writer
            .with_connection(|connection| {
                Box::pin(async move {
                    let mut transaction = connection.begin().await?;
                    // Updating external-content FTS once per normalized CVE is substantially
                    // slower than rebuilding its stable-rowid index once for the whole batch.
                    // DDL is transactional in SQLite: any error rolls the trigger drop back.
                    schema::suspend_cve_search_sync(&mut transaction).await?;
                    sqlx::query("INSERT OR IGNORE INTO db_sources (source, display_name, source_type, default_filename, raw_format) VALUES ('CVE', 'CVE List V5', 'vulnerability_db', 'all_CVEs_at_midnight.zip', 'json')")
                        .execute(&mut *transaction)
                        .await?;
                    let records = parsed_records
                        .into_iter()
                        .map(|(raw_json, value)| {
                            Self::cve_parent_input(raw_json, &value)
                                .map(|parent| (parent, value))
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    Self::upsert_cve_identifiers(&mut transaction, &records).await?;
                    let cve_ids = Self::upsert_cve_parents(&mut transaction, &records).await?;
                    Self::delete_existing_cve_children(&mut transaction, &records).await?;
                    Self::insert_cve_children(&mut transaction, &records, &cve_ids).await?;
                    if update_search {
                        rebuild_cve_search(&mut transaction).await?;
                    }
                    schema::restore_cve_search_sync(&mut transaction).await?;
                    transaction.commit().await
                })
            })
            .await?;
        Ok(count)
    }

    /// Populates CVE identifier master nodes in bulk. Edges are rebuilt from their normalized
    /// sources after the import, so this needs no row-at-a-time graph maintenance.
    async fn upsert_cve_identifiers(
        transaction: &mut sqlx::SqliteConnection,
        records: &[(CveParentInput, Value)],
    ) -> Result<(), sqlx::Error> {
        let now = chrono::Utc::now().to_rfc3339();
        // Five bindings per row: keep each statement below SQLite's variable limit.
        for chunk in records.chunks(5_000) {
            let mut builder = QueryBuilder::<Sqlite>::new(
                "INSERT INTO vulnerability_identifiers (identifier, identifier_type, source, first_seen_at, last_seen_at) ",
            );
            builder.push_values(chunk, |mut row, (parent, _)| {
                row.push_bind(&parent.cve_id)
                    .push_bind("cve")
                    .push_bind("CVE")
                    .push_bind(&now)
                    .push_bind(&now);
            });
            builder.push(" ON CONFLICT(identifier) DO UPDATE SET identifier_type='cve', last_seen_at=excluded.last_seen_at");
            builder.build().execute(&mut *transaction).await?;
        }
        Ok(())
    }

    /// Removes stale normalized children in set-based statements before re-inserting a batch.
    /// Cascades from `cve_affected` also remove affected-version descendants.
    async fn delete_existing_cve_children(
        transaction: &mut sqlx::SqliteConnection,
        records: &[(CveParentInput, Value)],
    ) -> Result<(), sqlx::Error> {
        for chunk in records.chunks(900) {
            for table in ["cve_affected", "cve_cvss", "cve_cwe"] {
                let mut query = QueryBuilder::<Sqlite>::new(format!(
                    "DELETE FROM {table} WHERE cve_db_id IN (SELECT id FROM cve WHERE cve_id IN ("
                ));
                let mut separated = query.separated(", ");
                for (parent, _) in chunk {
                    separated.push_bind(&parent.cve_id);
                }
                query.push("))");
                query.build().execute(&mut *transaction).await?;
            }
        }
        Ok(())
    }

    fn cve_parent_input(raw_json: String, value: &Value) -> Result<CveParentInput, sqlx::Error> {
        let metadata = value
            .get("cveMetadata")
            .ok_or_else(|| sqlx::Error::Protocol("CVE record is missing cveMetadata".to_owned()))?;
        let cve_id = metadata
            .get("cveId")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                sqlx::Error::Protocol("CVE record is missing cveMetadata.cveId".to_owned())
            })?
            .to_owned();
        let state = match metadata.get("state").and_then(Value::as_str) {
            Some("PUBLISHED") => 0,
            Some("REJECTED") => 1,
            Some(other) => {
                return Err(sqlx::Error::Protocol(format!(
                    "unsupported CVE state: {other}"
                )));
            }
            None => {
                return Err(sqlx::Error::Protocol(
                    "CVE record is missing cveMetadata.state".to_owned(),
                ));
            }
        };
        let published_value = metadata
            .get("datePublished")
            .and_then(Value::as_str)
            .unwrap_or("1970-01-01T00:00:00Z");
        let published_at = canonical_cve_utc(published_value).map_err(|error| {
            sqlx::Error::Protocol(format!(
                "invalid CVE published timestamp for {cve_id} ({published_value:?}): {error}"
            ))
        })?;
        let updated_value = metadata
            .get("dateUpdated")
            .and_then(Value::as_str)
            .unwrap_or(&published_at);
        let updated_at = canonical_cve_utc(updated_value).map_err(|error| {
            sqlx::Error::Protocol(format!(
                "invalid CVE updated timestamp for {cve_id} ({updated_value:?}): {error}"
            ))
        })?;
        let cna = value.pointer("/containers/cna");
        let title = cna
            .and_then(|cna| cna.get("title"))
            .and_then(Value::as_str)
            .unwrap_or(&cve_id)
            .to_owned();
        let description_en = cna
            .and_then(|cna| cna.get("descriptions"))
            .and_then(Value::as_array)
            .and_then(|descriptions| {
                descriptions
                    .iter()
                    .find(|description| {
                        description.get("lang").and_then(Value::as_str) == Some("en")
                    })
                    .or_else(|| descriptions.first())
            })
            .and_then(|description| description.get("value"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let references = cve_references(cna, value.pointer("/containers/adp"));
        let reference_text = references
            .iter()
            .map(|reference| {
                format!(
                    "{} {} {}",
                    reference.url,
                    reference.name.clone().unwrap_or_default(),
                    reference.tags_json
                )
            })
            .collect::<Vec<_>>()
            .join(" ");
        Ok(CveParentInput {
            cve_id,
            state,
            published_at,
            updated_at,
            title,
            description_en,
            serial: metadata.get("serial").and_then(Value::as_i64).unwrap_or(0),
            reference_text,
            raw_json,
        })
    }

    async fn upsert_cve_parents(
        transaction: &mut sqlx::SqliteConnection,
        records: &[(CveParentInput, Value)],
    ) -> Result<ahash::AHashMap<String, i64>, sqlx::Error> {
        for chunk in records.chunks(2_000) {
            let mut builder = QueryBuilder::<Sqlite>::new(
                "INSERT INTO cve (cve_id, state, published_at, updated_at, serial, title, description_en, reference_text, raw_json) ",
            );
            builder.push_values(chunk, |mut row, (parent, _)| {
                row.push_bind(&parent.cve_id)
                    .push_bind(parent.state)
                    .push_bind(&parent.published_at)
                    .push_bind(&parent.updated_at)
                    .push_bind(parent.serial)
                    .push_bind(&parent.title)
                    .push_bind(&parent.description_en)
                    .push_bind(&parent.reference_text)
                    .push_bind(&parent.raw_json);
            });
            builder.push(" ON CONFLICT(cve_id) DO UPDATE SET state=excluded.state, published_at=excluded.published_at, updated_at=excluded.updated_at, serial=excluded.serial, title=excluded.title, description_en=excluded.description_en, reference_text=excluded.reference_text, raw_json=excluded.raw_json");
            builder.build().execute(&mut *transaction).await?;
        }
        let mut ids = ahash::AHashMap::with_capacity(records.len());
        for chunk in records.chunks(900) {
            let mut query =
                QueryBuilder::<Sqlite>::new("SELECT cve_id, id FROM cve WHERE cve_id IN (");
            let mut separated = query.separated(", ");
            for (parent, _) in chunk {
                separated.push_bind(&parent.cve_id);
            }
            query.push(")");
            for row in query.build().fetch_all(&mut *transaction).await? {
                ids.insert(row.try_get("cve_id")?, row.try_get("id")?);
            }
        }
        Ok(ids)
    }

    async fn insert_cve_children(
        transaction: &mut sqlx::SqliteConnection,
        records: &[(CveParentInput, Value)],
        cve_ids: &ahash::AHashMap<String, i64>,
    ) -> Result<(), sqlx::Error> {
        let mut cvss_rows = Vec::<CvssInput>::new();
        let mut affected_rows = Vec::<AffectedInput>::new();
        let mut cwe_catalog = BTreeMap::<i64, Option<String>>::new();
        let mut cwe_links = Vec::<(i64, i64)>::new();

        for (parent, value) in records {
            let cve_db_id = *cve_ids.get(&parent.cve_id).ok_or_else(|| {
                sqlx::Error::Protocol(format!("missing staged CVE row: {}", parent.cve_id))
            })?;
            let cna = value.pointer("/containers/cna");
            if let Some(metrics) = cna
                .and_then(|value| value.get("metrics"))
                .and_then(Value::as_array)
            {
                for (source, metric) in metrics
                    .iter()
                    .flat_map(|metric| metric.as_object().into_iter().flat_map(|map| map.iter()))
                {
                    let Some(metric) = metric.as_object() else {
                        continue;
                    };
                    let Some(version) = metric.get("version").and_then(Value::as_str) else {
                        continue;
                    };
                    cvss_rows.push((
                        cve_db_id,
                        version.to_owned(),
                        metric.get("baseScore").and_then(Value::as_f64),
                        metric
                            .get("baseSeverity")
                            .and_then(Value::as_str)
                            .map(ToOwned::to_owned),
                        metric
                            .get("vectorString")
                            .and_then(Value::as_str)
                            .map(ToOwned::to_owned),
                        source.to_owned(),
                    ));
                }
            }
            if let Some(problem_types) = cna
                .and_then(|value| value.get("problemTypes"))
                .and_then(Value::as_array)
            {
                for description in problem_types.iter().flat_map(|problem_type| {
                    problem_type
                        .get("descriptions")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                }) {
                    let Some(cwe_id) = description
                        .get("cweId")
                        .and_then(Value::as_str)
                        .and_then(|value| value.strip_prefix("CWE-"))
                        .and_then(|value| value.parse::<i64>().ok())
                    else {
                        continue;
                    };
                    let description = description
                        .get("description")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned);
                    cwe_catalog
                        .entry(cwe_id)
                        .and_modify(|current| {
                            if current.is_none() {
                                *current = description.clone();
                            }
                        })
                        .or_insert(description);
                    cwe_links.push((cve_db_id, cwe_id));
                }
            }
            if let Some(affected) = cna
                .and_then(|value| value.get("affected"))
                .and_then(Value::as_array)
            {
                for item in affected {
                    let versions = item
                        .get("versions")
                        .and_then(Value::as_array)
                        .map(|versions| {
                            versions
                                .iter()
                                .map(|version| {
                                    (
                                        version
                                            .get("version")
                                            .and_then(Value::as_str)
                                            .map(ToOwned::to_owned),
                                        version
                                            .get("status")
                                            .and_then(Value::as_str)
                                            .map(ToOwned::to_owned),
                                        version
                                            .get("versionType")
                                            .and_then(Value::as_str)
                                            .map(ToOwned::to_owned),
                                        version
                                            .get("lessThan")
                                            .and_then(Value::as_str)
                                            .map(ToOwned::to_owned),
                                        version
                                            .get("lessThanOrEqual")
                                            .and_then(Value::as_str)
                                            .map(ToOwned::to_owned),
                                    )
                                })
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default();
                    let version_text = versions
                        .iter()
                        .filter_map(|version| version.0.as_deref())
                        .collect::<Vec<_>>()
                        .join(" ");
                    let versions_json = serde_json::to_string(&versions).map_err(|error| {
                        sqlx::Error::Protocol(format!(
                            "failed to encode affected versions: {error}"
                        ))
                    })?;
                    affected_rows.push((
                        cve_db_id,
                        item.get("vendor")
                            .and_then(Value::as_str)
                            .map(ToOwned::to_owned),
                        item.get("product")
                            .and_then(Value::as_str)
                            .map(ToOwned::to_owned),
                        item.get("packageName")
                            .and_then(Value::as_str)
                            .map(ToOwned::to_owned),
                        item.get("collectionURL")
                            .and_then(Value::as_str)
                            .map(ToOwned::to_owned),
                        item.get("defaultStatus")
                            .and_then(Value::as_str)
                            .map(ToOwned::to_owned),
                        version_text,
                        versions_json,
                    ));
                }
            }
        }

        let cwe_rows = cwe_catalog.into_iter().collect::<Vec<_>>();
        for chunk in cwe_rows.chunks(8_000) {
            let mut query = QueryBuilder::<Sqlite>::new("INSERT INTO cwe(id, description) ");
            query.push_values(chunk, |mut row, (id, description)| {
                row.push_bind(id).push_bind(description);
            });
            query.push(" ON CONFLICT(id) DO UPDATE SET description=COALESCE(excluded.description, cwe.description)");
            query.build().execute(&mut *transaction).await?;
        }
        for chunk in cvss_rows.chunks(4_000) {
            let mut query = QueryBuilder::<Sqlite>::new(
                "INSERT INTO cve_cvss(cve_db_id, version, base_score, base_severity, vector_string, source, raw_json) ",
            );
            query.push_values(chunk, |mut row, value| {
                row.push_bind(value.0)
                    .push_bind(&value.1)
                    .push_bind(value.2)
                    .push_bind(&value.3)
                    .push_bind(&value.4)
                    .push_bind(&value.5)
                    .push_bind("{}");
            });
            query.build().execute(&mut *transaction).await?;
        }
        for chunk in cwe_links.chunks(8_000) {
            let mut query =
                QueryBuilder::<Sqlite>::new("INSERT OR IGNORE INTO cve_cwe(cve_db_id, cwe_id) ");
            query.push_values(chunk, |mut row, value| {
                row.push_bind(value.0).push_bind(value.1);
            });
            query.build().execute(&mut *transaction).await?;
        }
        for chunk in affected_rows.chunks(3_000) {
            let mut query = QueryBuilder::<Sqlite>::new(
                "INSERT INTO cve_affected(cve_db_id, vendor, product, package_name, collection_url, default_status, version_text, raw_json) ",
            );
            query.push_values(chunk, |mut row, value| {
                row.push_bind(value.0)
                    .push_bind(&value.1)
                    .push_bind(&value.2)
                    .push_bind(&value.3)
                    .push_bind(&value.4)
                    .push_bind(&value.5)
                    .push_bind(&value.6)
                    .push_bind(&value.7);
            });
            query.build().execute(&mut *transaction).await?;
        }
        Ok(())
    }

    /// Imports a CISA KEV catalog and attaches entries only to known CVE rows.
    ///
    /// Keeping KEV entries dependent on imported CVEs gives the foreign key a real ownership
    /// meaning and makes retrying feed imports idempotent.
    pub async fn import_kev_json(&self, raw_json: String) -> Result<usize, sqlx::Error> {
        let catalog = KevCatalog::parse_json(raw_json.as_bytes())
            .map_err(|error| sqlx::Error::Protocol(format!("invalid KEV JSON: {error}")))?;
        catalog
            .validate_schema_shape()
            .map_err(|error| sqlx::Error::Protocol(format!("invalid KEV catalog: {error}")))?;
        let count = catalog.vulnerabilities.len();
        self.writer.with_connection(|connection| Box::pin(async move {
            let mut transaction = connection.begin().await?;
            sqlx::query("INSERT OR IGNORE INTO db_sources (source, display_name, source_type, default_filename, raw_format) VALUES ('KEV', 'CISA KEV', 'enrichment', 'known_exploited_vulnerabilities.json', 'json')")
                .execute(&mut *transaction).await?;
            let now = chrono::Utc::now().to_rfc3339();
            let hash = Md5::digest(raw_json.as_bytes()).iter().map(|byte| format!("{byte:02x}")).collect::<String>();
            sqlx::query("INSERT INTO kev_raw_records (record_id, source_path, provider_modified_at, score_date, fetched_at, content_hash, raw_json) VALUES (?, NULL, NULL, NULL, ?, ?, ?) ON CONFLICT(record_id) DO UPDATE SET fetched_at=excluded.fetched_at, content_hash=excluded.content_hash, raw_json=excluded.raw_json")
                .bind(&catalog.catalog_version).bind(&now).bind(hash).bind(&raw_json)
                .execute(&mut *transaction).await?;
            let raw_record_id: i64 = sqlx::query_scalar("SELECT id FROM kev_raw_records WHERE record_id=?")
                .bind(&catalog.catalog_version).fetch_one(&mut *transaction).await?;
            for entry in catalog.vulnerabilities {
                sqlx::query("INSERT INTO kev_entries (cve_id, raw_record_id, vendor_project, product, vulnerability_name, date_added, short_description, required_action, due_date, known_ransomware_campaign_use, notes, fetched_at) SELECT cve_id, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? FROM cve WHERE cve_id=? ON CONFLICT(cve_id) DO UPDATE SET raw_record_id=excluded.raw_record_id, vendor_project=excluded.vendor_project, product=excluded.product, vulnerability_name=excluded.vulnerability_name, date_added=excluded.date_added, short_description=excluded.short_description, required_action=excluded.required_action, due_date=excluded.due_date, known_ransomware_campaign_use=excluded.known_ransomware_campaign_use, notes=excluded.notes, fetched_at=excluded.fetched_at")
                    .bind(raw_record_id)
                    .bind(entry.vendor_project)
                    .bind(entry.product)
                    .bind(entry.vulnerability_name)
                    .bind(entry.date_added)
                    .bind(entry.short_description)
                    .bind(entry.required_action)
                    .bind(entry.due_date)
                    .bind(entry.known_ransomware_campaign_use)
                    .bind(entry.notes)
                    .bind(&now)
                    .bind(entry.cve_id)
                    .execute(&mut *transaction).await?;
            }
            transaction.commit().await
        })).await?;
        Ok(count)
    }

    /// Imports one EPSS current CSV snapshot without exposing internal CVE IDs.
    pub async fn import_epss_csv(&self, csv: String) -> Result<usize, sqlx::Error> {
        let parsed = EpssCurrentCsv::parse(&csv)
            .map_err(|error| sqlx::Error::Protocol(format!("invalid EPSS CSV: {error}")))?;
        let count = parsed.rows.len();
        self.writer.with_connection(|connection| Box::pin(async move {
            let mut transaction = connection.begin().await?;
            sqlx::query("INSERT OR IGNORE INTO db_sources (source, display_name, source_type, default_filename, raw_format) VALUES ('EPSS', 'FIRST EPSS', 'enrichment', 'epss_scores-current.csv', 'csv')")
                .execute(&mut *transaction).await?;
            let now = chrono::Utc::now().to_rfc3339();
            let hash = Md5::digest(csv.as_bytes()).iter().map(|byte| format!("{byte:02x}")).collect::<String>();
            sqlx::query("INSERT INTO epss_raw_records (score_date, fetched_at, content_hash, raw_csv) VALUES (?, ?, ?, ?) ON CONFLICT(score_date) DO UPDATE SET fetched_at=excluded.fetched_at, content_hash=excluded.content_hash, raw_csv=excluded.raw_csv")
                .bind(&parsed.score_date).bind(&now).bind(hash).bind(&csv).execute(&mut *transaction).await?;
            let raw_record_id: i64 = sqlx::query_scalar("SELECT id FROM epss_raw_records WHERE score_date=?")
                .bind(&parsed.score_date)
                .fetch_one(&mut *transaction).await?;
            for row in parsed.rows {
                sqlx::query("INSERT INTO epss_current (cve_id, raw_record_id, epss, percentile, score_date, model_version, fetched_at) SELECT cve_id, ?, ?, ?, ?, ?, ? FROM cve WHERE cve_id=? ON CONFLICT(cve_id) DO UPDATE SET raw_record_id=excluded.raw_record_id, epss=excluded.epss, percentile=excluded.percentile, score_date=excluded.score_date, model_version=excluded.model_version, fetched_at=excluded.fetched_at")
                    .bind(raw_record_id).bind(row.epss).bind(row.percentile).bind(&parsed.score_date).bind(&parsed.model_version).bind(&now).bind(&row.cve_id)
                    .execute(&mut *transaction).await?;
            }
            transaction.commit().await
        })).await?;
        Ok(count)
    }
}

fn cve_references(cna: Option<&Value>, adp: Option<&Value>) -> Vec<SqlxCveReference> {
    let mut rows: BTreeMap<String, (Option<String>, BTreeSet<String>)> = BTreeMap::new();
    let containers = cna.into_iter().chain(adp.into_iter().flat_map(|value| {
        value
            .as_array()
            .map(|items| items.iter().collect::<Vec<_>>())
            .unwrap_or_else(|| vec![value])
    }));
    for container in containers {
        let references = container
            .get("references")
            .and_then(Value::as_array)
            .into_iter()
            .flatten();
        for reference in references {
            let Some(url) = reference.get("url").and_then(Value::as_str) else {
                continue;
            };
            let row = rows.entry(url.to_owned()).or_default();
            if row.0.is_none() {
                row.0 = reference
                    .get("name")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned);
            }
            if let Some(tags) = reference.get("tags").and_then(Value::as_array) {
                row.1
                    .extend(tags.iter().filter_map(Value::as_str).map(ToOwned::to_owned));
            }
        }
    }
    rows.into_iter()
        .map(|(url, (name, tags))| SqlxCveReference {
            url,
            name,
            tags_json: serde_json::to_string(&tags.into_iter().collect::<Vec<_>>())
                .expect("serializing strings cannot fail"),
        })
        .collect()
}

/// Rebuilds derived OSV graph edges from the normalized relation table.
///
/// `osv_identifier_relations` is the source of truth. Rebuilding prevents stale graph edges
/// when an advisory's aliases, upstream IDs, or related IDs change on a later feed import.
async fn rebuild_osv_identifier_edges(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    now: &str,
) -> Result<(), sqlx::Error> {
    let relations: Vec<(String, String)> =
        sqlx::query_as("SELECT osv_id, alias_id FROM osv_aliases ORDER BY osv_id, alias_id")
            .fetch_all(&mut **transaction)
            .await?;
    for (osv_id, identifier) in relations {
        let evidence = serde_json::json!({"osv_id": osv_id, "identifier": identifier, "relation_type": "alias"}).to_string();
        sqlx::query("INSERT OR REPLACE INTO vulnerability_identifier_edges (from_identifier, to_identifier, relation_type, source, confidence, evidence_json, created_at) VALUES (?, ?, 'alias', 'OSV', 'high', ?, ?)")
            .bind(&osv_id).bind(&identifier).bind(&evidence).bind(now)
            .execute(&mut **transaction).await?;
        sqlx::query("INSERT OR REPLACE INTO vulnerability_identifier_edges (from_identifier, to_identifier, relation_type, source, confidence, evidence_json, created_at) VALUES (?, ?, 'alias', 'OSV', 'high', ?, ?)")
            .bind(&identifier).bind(&osv_id).bind(&evidence).bind(now)
            .execute(&mut **transaction).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn database_handle_is_send_and_sync_for_spawned_command_tasks() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SqlxDatabase>();
    }

    #[tokio::test]
    async fn initializes_and_checks_a_new_database_on_one_writer() {
        let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        assert!(database.check_schema().await.is_err());
        database.initialize().await.unwrap();
        database.check_schema().await.unwrap();
        database.rebuild_search().await.unwrap();
        database.check().await.unwrap();
        assert_eq!(SqlxDatabase::schema_version(), 7);
    }

    #[tokio::test]
    async fn bulk_cve_load_defers_search_and_restores_indexes_and_pragmas() {
        let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        database.initialize().await.unwrap();
        database.prepare_cve_bulk_load().await.unwrap();
        database
            .import_cve_raw_jsons_deferred_search(vec![
                r#"{"cveMetadata":{"cveId":"CVE-2099-9001","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-01T00:00:00Z"},"containers":{"cna":{"title":"Deferred bulk search fixture"}}}"#.to_owned(),
            ])
            .await
            .unwrap();

        assert!(
            database
                .search_cves("deferred", false, 10)
                .await
                .unwrap()
                .is_empty()
        );
        database.finish_cve_bulk_load().await.unwrap();
        assert_eq!(
            database
                .search_cves("deferred", false, 10)
                .await
                .unwrap()
                .len(),
            1
        );

        let (foreign_keys, index_exists): (i64, i64) = database
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    let foreign_keys = sqlx::query_scalar("PRAGMA foreign_keys")
                        .fetch_one(&mut *connection)
                        .await?;
                    let index_exists = sqlx::query_scalar("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_cve_updated_at'")
                        .fetch_one(&mut *connection)
                        .await?;
                    Ok((foreign_keys, index_exists))
                })
            })
            .await
            .unwrap();
        assert_eq!(foreign_keys, 1);
        assert_eq!(index_exists, 1);
    }

    #[tokio::test]
    async fn persists_update_metadata_without_exposing_database_ids() {
        let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        database.initialize().await.unwrap();
        database
            .set_metadata_value("cve_asset:test", "applied")
            .await
            .unwrap();
        database
            .mark_cve_asset_applied("delta.zip", "local")
            .await
            .unwrap();
        assert_eq!(
            database.metadata_value("cve_asset:test").await.unwrap(),
            Some("applied".to_owned())
        );
        database.check().await.unwrap();
    }

    #[tokio::test]
    async fn imports_osv_relations_ranges_and_repo_in_one_writer_transaction() {
        let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        database.initialize().await.unwrap();
        database
            .import_osv_record(OsvRawRecord {
                source_path: None,
                raw_json: include_str!("../../../fixtures/osv/GHSA-TEST-0001.json").to_owned(),
            })
            .await
            .unwrap();
        let relation_count: i64 = database
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query_scalar("SELECT COUNT(*) FROM osv_aliases")
                        .fetch_one(connection)
                        .await
                })
            })
            .await
            .unwrap();
        assert!(relation_count > 0);
        let indexed: i64 = database
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query_scalar("SELECT COUNT(*) FROM osv_text_fts")
                        .fetch_one(connection)
                        .await
                })
            })
            .await
            .unwrap();
        assert_eq!(indexed, 1);
        let matches = database.search_osv("fixture", 10).await.unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(
            database
                .find_osv_summary("GHSA-TEST-0001")
                .await
                .unwrap()
                .unwrap()
                .osv_id,
            "GHSA-TEST-0001"
        );
    }

    #[tokio::test]
    async fn loads_tui_enrichment_summaries_for_cve_results() {
        let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        database.initialize().await.unwrap();
        database
            .import_cve_raw_json(
                r#"{"cveMetadata":{"cveId":"CVE-2099-7001","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-01T00:00:00Z"},"containers":{"cna":{"title":"TUI enrichment fixture"}}}"#.to_owned(),
            )
            .await
            .unwrap();

        let rows = database
            .enriched_cve_summaries(&["CVE-2099-7001".to_owned()])
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].cve_id, "CVE-2099-7001");
    }

    #[tokio::test]
    async fn batches_tui_overview_details_and_preserves_result_order() {
        let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        database.initialize().await.unwrap();
        database
            .import_cve_raw_jsons(vec![
                r#"{"cveMetadata":{"cveId":"CVE-2099-7101","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-01T00:00:00Z"},"containers":{"cna":{"title":"First overview fixture","affected":[{"vendor":"Acme","product":"widget"}],"metrics":[{"cvssV3_1":{"version":"3.1","baseScore":9.8,"baseSeverity":"CRITICAL"}}],"problemTypes":[{"descriptions":[{"cweId":"CWE-79","description":"XSS"}]}]}}}"#.to_owned(),
                r#"{"cveMetadata":{"cveId":"CVE-2099-7102","state":"PUBLISHED","datePublished":"2099-01-02T00:00:00Z","dateUpdated":"2099-01-02T00:00:00Z"},"containers":{"cna":{"title":"Second overview fixture","affected":[{"vendor":"Example","product":"service"}],"metrics":[{"cvssV4_0":{"version":"4.0","baseScore":7.2,"baseSeverity":"HIGH"}}],"problemTypes":[{"descriptions":[{"cweId":"CWE-89","description":"SQL injection"}]}]}}}"#.to_owned(),
            ])
            .await
            .unwrap();

        let mut summaries = database
            .search_cve_summaries_by_cve_id_prefix_with_state_scope(
                "CVE-2099-71",
                CveStateScope::PublishedOnly,
                10,
                0,
            )
            .await
            .unwrap();
        summaries.reverse();
        let expected_order = summaries
            .iter()
            .map(|row| row.cve_id.clone())
            .collect::<Vec<_>>();
        let rows = database
            .attach_cve_overview_details(summaries)
            .await
            .unwrap();

        assert_eq!(
            rows.iter()
                .map(|row| row.summary.cve_id.clone())
                .collect::<Vec<_>>(),
            expected_order
        );
        assert!(rows.iter().all(|row| row.detail.cwes.len() == 1));
        assert!(rows.iter().all(|row| row.detail.cvss.len() == 1));
        assert!(rows.iter().all(|row| row.detail.affected.len() == 1));
        assert!(
            rows.iter()
                .all(|row| row.detail.affected[0].versions.is_empty())
        );
    }

    #[tokio::test]
    async fn imports_and_searches_cwe_catalog_statuses_and_tree_relationships() {
        let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        database.initialize().await.unwrap();
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../collector/src/cwec_latest.xml.zip");
        let catalog = qanvuli_models::cwe::read_cwe_catalog_zip(path).unwrap();
        let imported = database.upsert_cwe_catalog(&catalog).await.unwrap();
        assert!(imported > 1_000);

        let populated: (i64, i64) = database
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query_as(
                        "SELECT COUNT(status), COUNT(parent_id) FROM cwe WHERE status IS NOT NULL",
                    )
                    .fetch_one(connection)
                    .await
                })
            })
            .await
            .unwrap();
        assert!(populated.0 > 1_000);
        assert!(populated.1 > 0);

        let all_statuses = [
            "Stable",
            "Usable",
            "Draft",
            "Incomplete",
            "Obsolete",
            "Deprecated",
        ]
        .map(str::to_owned);
        let rows = database
            .search_cwe_entries("", 2_000, &all_statuses)
            .await
            .unwrap();
        assert!(rows.iter().all(|row| row.status.is_some()));
        assert!(rows.iter().any(|row| row.parent_count > 0));
        assert!(rows.iter().any(|row| row.child_count > 0));
        for row in rows.iter().filter(|row| row.parent_id.is_some()) {
            let parent = row.parent_id.unwrap();
            assert!(
                rows.iter().position(|entry| entry.id == parent)
                    < rows.iter().position(|entry| entry.id == row.id)
            );
        }

        let stable = database
            .search_cwe_entries("", 2_000, &["Stable".to_owned()])
            .await
            .unwrap();
        assert!(!stable.is_empty());
        assert!(
            stable
                .iter()
                .all(|row| row.status.as_deref() == Some("Stable"))
        );
        assert!(
            database
                .search_cwe_entries("", 2_000, &[])
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn bulk_osv_init_uses_insert_only_while_updates_remain_idempotent() {
        let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        database.initialize().await.unwrap();
        database.prepare_osv_bulk_load().await.unwrap();
        let record = OsvRawRecord {
            source_path: None,
            raw_json: include_str!("../../../fixtures/osv/GHSA-TEST-0001.json").to_owned(),
        };

        assert_eq!(
            database
                .import_osv_records_bulk_init(vec![record.clone()])
                .await
                .unwrap(),
            1
        );
        assert!(
            database
                .import_osv_records_bulk_init(vec![record.clone()])
                .await
                .is_err()
        );
        database.finish_osv_bulk_load().await.unwrap();

        assert_eq!(
            database
                .import_osv_records_deferred_search(vec![record])
                .await
                .unwrap(),
            1
        );
        let advisory_count: i64 = database
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query_scalar("SELECT COUNT(*) FROM osv_advisories")
                        .fetch_one(connection)
                        .await
                })
            })
            .await
            .unwrap();
        assert_eq!(advisory_count, 1);
    }

    #[tokio::test]
    async fn file_backed_osv_bulk_finish_restores_wal_without_locks() {
        let path = std::env::temp_dir().join(format!(
            "qanvuli-osv-bulk-finish-{}-{}.sqlite",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let database_url = format!(
            "sqlite:///{}?mode=rwc",
            path.to_string_lossy().replace('\\', "/")
        );
        let database = SqlxDatabase::connect(&database_url).await.unwrap();
        database.initialize().await.unwrap();
        database.prepare_osv_bulk_load().await.unwrap();
        let records = (0..500)
            .map(|index| OsvRawRecord {
                source_path: None,
                raw_json: format!(
                    r#"{{"schema_version":"1.8.0","id":"OSV-2099-{index}","modified":"2099-01-01T00:00:00Z","aliases":["CVE-2099-{index}"],"affected":[{{"package":{{"ecosystem":"Go","name":"example/{index}"}},"ranges":[{{"type":"SEMVER","events":[{{"introduced":"0"}}]}}]}}]}}"#
                ),
            })
            .collect();
        assert_eq!(
            database
                .import_osv_records_bulk_init(records)
                .await
                .unwrap(),
            500
        );
        database.finish_osv_bulk_load().await.unwrap();
        let modes: (String, String, i64) = database
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    let journal: String = sqlx::query_scalar("PRAGMA journal_mode")
                        .fetch_one(&mut *connection)
                        .await?;
                    let locking: String = sqlx::query_scalar("PRAGMA locking_mode")
                        .fetch_one(&mut *connection)
                        .await?;
                    let foreign_keys: i64 = sqlx::query_scalar("PRAGMA foreign_keys")
                        .fetch_one(&mut *connection)
                        .await?;
                    Ok((journal, locking, foreign_keys))
                })
            })
            .await
            .unwrap();
        assert_eq!(modes, ("wal".to_owned(), "normal".to_owned(), 1));
        database
            .set_metadata_value("osv_bulk_close_test", "written_after_wal_restore")
            .await
            .unwrap();
        database.close().await.unwrap();
        assert!(!path.with_extension("sqlite-wal").exists());
        assert!(!path.with_extension("sqlite-shm").exists());
        let reopened = SqlxDatabase::connect(&database_url).await.unwrap();
        assert_eq!(
            reopened
                .metadata_value("osv_bulk_close_test")
                .await
                .unwrap(),
            Some("written_after_wal_restore".to_owned())
        );
        reopened.close().await.unwrap();
        for candidate in [
            path.clone(),
            path.with_extension("sqlite-wal"),
            path.with_extension("sqlite-shm"),
        ] {
            let _ = std::fs::remove_file(candidate);
        }
    }

    #[tokio::test]
    async fn keeps_alias_upstream_and_related_as_distinct_graph_edges() {
        let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        database.initialize().await.unwrap();
        database.import_osv_record(OsvRawRecord {
            source_path: None,
            raw_json: r#"{"schema_version":"1.8.0","id":"GHSA-2099-test","modified":"2099-01-01T00:00:00Z","aliases":["CVE-2099-1"],"upstream":["UPSTREAM-1"],"related":["RELATED-1"]}"#.to_owned(),
        }).await.unwrap();
        let edge_counts: Vec<(String, i64)> = database.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query_as("SELECT relation_type, COUNT(*) FROM vulnerability_identifier_edges GROUP BY relation_type ORDER BY relation_type")
                .fetch_all(connection).await
        })).await.unwrap();
        assert_eq!(
            edge_counts,
            vec![
                ("alias".to_owned(), 2),
                ("related".to_owned(), 2),
                ("upstream".to_owned(), 1),
            ]
        );
        let resolution = database.resolve_identifier("GHSA-2099-test").await.unwrap();
        assert_eq!(resolution.related_cve_ids, vec!["CVE-2099-1"]);
        assert!(
            !resolution
                .related_osv_ids
                .iter()
                .any(|id| id == "UPSTREAM-1" || id == "RELATED-1")
        );
        let edges = database.identifier_edges("GHSA-2099-test").await.unwrap();
        assert!(edges.iter().any(|edge| edge.relation_type == "alias"));
        assert!(edges.iter().any(|edge| edge.relation_type == "upstream"));
        database.rebuild_identifier_graph().await.unwrap();
        assert_eq!(
            database
                .identifier_edges("GHSA-2099-test")
                .await
                .unwrap()
                .len(),
            edges.len()
        );
    }

    #[tokio::test]
    async fn repeated_osv_import_rebuilds_derived_edges_without_stale_duplicates() {
        let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        database.initialize().await.unwrap();
        database.import_osv_record(OsvRawRecord {
            source_path: None,
            raw_json: r#"{"schema_version":"1.8.0","id":"GHSA-2099-edge","modified":"2099-01-01T00:00:00Z","aliases":["CVE-2099-old"]}"#.to_owned(),
        }).await.unwrap();
        database.import_osv_record(OsvRawRecord {
            source_path: None,
            raw_json: r#"{"schema_version":"1.8.0","id":"GHSA-2099-edge","modified":"2099-01-02T00:00:00Z","aliases":["CVE-2099-new"]}"#.to_owned(),
        }).await.unwrap();
        let edges: Vec<String> = database.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query_scalar("SELECT to_identifier FROM vulnerability_identifier_edges WHERE source='OSV' AND from_identifier='GHSA-2099-edge' ORDER BY to_identifier")
                .fetch_all(connection).await
        })).await.unwrap();
        assert_eq!(edges, vec!["CVE-2099-new".to_owned()]);
    }

    #[tokio::test]
    async fn imports_cve_with_stable_fts_rowid() {
        let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        database.initialize().await.unwrap();
        database.import_cve_raw_json(r#"{"cveMetadata":{"cveId":"CVE-2099-1","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-01T00:00:00Z"},"containers":{"cna":{"title":"Example CVE","affected":[{"vendor":"Acme","product":"widget","versions":[{"version":"1.0","status":"affected","versionType":"semver","lessThan":"2.0","lessThanOrEqual":"1.9"}]}],"metrics":[{"cvssV3_1":{"version":"3.1","baseScore":9.8,"baseSeverity":"CRITICAL","vectorString":"CVSS:3.1/AV:N"}}],"problemTypes":[{"descriptions":[{"cweId":"CWE-79","description":"XSS"}]}]}}}"#.to_owned()).await.unwrap();
        let rowid: i64 = database
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query_scalar(
                        "SELECT rowid FROM cve_summary_fts WHERE cve_summary_fts MATCH 'example'",
                    )
                    .fetch_one(connection)
                    .await
                })
            })
            .await
            .unwrap();
        assert_eq!(rowid, 1);
        let affected: i64 = database
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query_scalar("SELECT COUNT(*) FROM cve_affected")
                        .fetch_one(connection)
                        .await
                })
            })
            .await
            .unwrap();
        assert_eq!(affected, 1);
        let normalized: (i64, i64) = database
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query_as(
                        "SELECT (SELECT COUNT(*) FROM cve_cvss), (SELECT COUNT(*) FROM cve_cwe)",
                    )
                    .fetch_one(connection)
                    .await
                })
            })
            .await
            .unwrap();
        assert_eq!(normalized, (1, 1));
        let identifier: String = database
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query_scalar("SELECT identifier FROM vulnerability_identifiers WHERE identifier='CVE-2099-1'")
                        .fetch_one(connection)
                        .await
                })
            })
            .await
            .unwrap();
        assert_eq!(identifier, "CVE-2099-1");
        let found = database
            .find_cve_summary("CVE-2099-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.cve_id, "CVE-2099-1");
        assert!(database.cve_raw_json("CVE-2099-1").await.unwrap().is_some());
        assert_eq!(
            database
                .search_cves_by_id_prefix("CVE-2099", false, 10, 0)
                .await
                .unwrap()
                .len(),
            1
        );
        let search = database.search_cves("example", false, 10).await.unwrap();
        assert_eq!(search.len(), 1);
        let detail = database.cve_detail("CVE-2099-1").await.unwrap().unwrap();
        assert_eq!(
            database
                .cve_summary_with_detail("CVE-2099-1")
                .await
                .unwrap()
                .unwrap()
                .summary
                .cve_id,
            "CVE-2099-1"
        );
        assert_eq!(detail.cvss.len(), 1);
        assert_eq!(
            detail.affected[0].versions[0].less_than.as_deref(),
            Some("2.0")
        );
        assert_eq!(
            detail.cwes,
            vec![SqlxCwe {
                id: 79,
                description: Some("XSS".to_owned())
            }]
        );
        assert_eq!(
            database
                .search_cves_by_cwes(&["CWE-79".to_owned()], false, 10, 0)
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            database.search_cwes(Some("CWE-79"), 10).await.unwrap(),
            vec![SqlxCwe {
                id: 79,
                description: Some("XSS".to_owned())
            }]
        );
        assert_eq!(database.find_cwe(79).await.unwrap().unwrap().id, 79);
        assert_eq!(
            database
                .search_cves_by_affected(
                    Some("Acme".to_owned()),
                    Some("widget".to_owned()),
                    true,
                    false,
                    10,
                    0,
                )
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            database
                .search_cves_by_affected_version(
                    Some("Acme".to_owned()),
                    Some("widget".to_owned()),
                    Some("1.0".to_owned()),
                    false,
                    10,
                    0,
                )
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            database
                .search_cves_by_cvss(
                    SqlxCvssSearch {
                        min_score: Some(9.0),
                        max_score: None,
                        severity: Some("critical".to_owned()),
                        version: Some("3.1".to_owned()),
                    },
                    false,
                    10,
                    0,
                )
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            database
                .cve_details(&["missing".to_owned(), "CVE-2099-1".to_owned()])
                .await
                .unwrap(),
            vec![None, Some(detail)]
        );
    }

    #[tokio::test]
    async fn cve_batch_import_is_atomic_when_a_later_record_is_invalid() {
        let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        database.initialize().await.unwrap();
        let result = database
            .import_cve_raw_jsons(vec![
                r#"{"cveMetadata":{"cveId":"CVE-2099-batch","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-01T00:00:00Z"},"containers":{"cna":{"title":"valid"}}}"#.to_owned(),
                "{invalid JSON}".to_owned(),
            ])
            .await;
        assert!(result.is_err());
        assert!(
            database
                .find_cve_summary("CVE-2099-batch")
                .await
                .unwrap()
                .is_none()
        );
        database.close().await.unwrap();
    }

    #[tokio::test]
    async fn cve_bulk_raw_and_identifier_upserts_cross_the_sqlite_bind_boundary() {
        let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        database.initialize().await.unwrap();
        let records = (0..5_001)
            .map(|index| {
                format!(
                    r#"{{"cveMetadata":{{"cveId":"CVE-2099-{index:04}","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-01T00:00:00Z"}},"containers":{{"cna":{{"title":"bulk"}}}}}}"#
                )
            })
            .collect();
        assert_eq!(database.import_cve_raw_jsons(records).await.unwrap(), 5_001);
        let counts: (i64, i64) = database
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query_as(
                        "SELECT (SELECT COUNT(*) FROM cve), (SELECT COUNT(*) FROM vulnerability_identifiers WHERE identifier_type='cve')",
                    )
                    .fetch_one(connection)
                    .await
                })
            })
            .await
            .unwrap();
        assert_eq!(counts, (5_001, 5_001));
        database.close().await.unwrap();
    }

    #[tokio::test]
    async fn fts_indexes_cve_description_references_and_osv_details() {
        let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        database.initialize().await.unwrap();
        database.import_cve_raw_json(r#"{"cveMetadata":{"cveId":"CVE-2099-fts","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-01T00:00:00Z"},"containers":{"cna":{"title":"Title","descriptions":[{"lang":"en","value":"needle-description"}],"references":[{"url":"https://example.invalid/needle-reference","tags":["patch"]}]}}}"#.to_owned()).await.unwrap();
        database.import_osv_record(OsvRawRecord { source_path: None, raw_json: r#"{"schema_version":"1.8.0","id":"GHSA-2099-fts","modified":"2099-01-01T00:00:00Z","summary":"Summary","details":"needle-osv-details","aliases":["CVE-2099-fts"],"affected":[{"package":{"ecosystem":"crates.io","name":"needle-package"}}]}"#.to_owned() }).await.unwrap();
        assert_eq!(
            database
                .search_cves("needle-description", false, 10)
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            database
                .search_cves("needle-reference", false, 10)
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            database
                .search_cves_by_reference_text("needle-reference", false, 10, 0)
                .await
                .unwrap()
                .len(),
            1
        );
        let references = database
            .cve_detail("CVE-2099-fts")
            .await
            .unwrap()
            .unwrap()
            .references;
        assert_eq!(references.len(), 1);
        assert_eq!(
            references[0].url,
            "https://example.invalid/needle-reference"
        );
        assert_eq!(references[0].tags_json, r#"["patch"]"#);
        assert_eq!(
            database
                .search_osv("needle-osv-details", 10)
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            database
                .search_osv("needle-package", 10)
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn combined_sqlx_search_keeps_cwe_affected_and_cvss_filters_as_and_conditions() {
        let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        database.initialize().await.unwrap();
        database.import_cve_raw_json(r#"{"cveMetadata":{"cveId":"CVE-2099-advanced","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-02T00:00:00Z"},"containers":{"cna":{"title":"Advanced Example","affected":[{"vendor":"Acme","product":"widget"}],"metrics":[{"cvssV3_1":{"version":"3.1","baseScore":9.8,"baseSeverity":"CRITICAL"}}],"problemTypes":[{"descriptions":[{"cweId":"CWE-79"}]}]}}}"#.to_owned()).await.unwrap();
        let matches = database
            .search_cves_advanced(
                SqlxCveSearch {
                    text: Some("advanced".to_owned()),
                    cwe_ids: vec!["CWE-79".to_owned()],
                    vendor_like: Some("%Acme%".to_owned()),
                    product_like: Some("%widget%".to_owned()),
                    cvss: SqlxCvssSearch {
                        min_score: Some(9.0),
                        severity: Some("critical".to_owned()),
                        ..SqlxCvssSearch::default()
                    },
                    ..SqlxCveSearch::default()
                },
                false,
                10,
                0,
            )
            .await
            .unwrap();
        assert_eq!(
            matches
                .iter()
                .map(|row| row.cve_id.as_str())
                .collect::<Vec<_>>(),
            vec!["CVE-2099-advanced"]
        );
        let no_match = database
            .search_cves_advanced(
                SqlxCveSearch {
                    product_exact: Some("other".to_owned()),
                    ..SqlxCveSearch::default()
                },
                false,
                10,
                0,
            )
            .await
            .unwrap();
        assert!(no_match.is_empty());
        let outside_range = database
            .search_cves_advanced(
                SqlxCveSearch {
                    published_until: Some("2098-12-31T23:59:59Z".to_owned()),
                    ..SqlxCveSearch::default()
                },
                false,
                10,
                0,
            )
            .await
            .unwrap();
        assert!(outside_range.is_empty());
    }

    #[tokio::test]
    async fn imports_epss_for_existing_cves_with_checked_scores() {
        let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        database.initialize().await.unwrap();
        database.import_cve_raw_json(r#"{"cveMetadata":{"cveId":"CVE-2099-0001","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-01T00:00:00Z"},"containers":{"cna":{"title":"Example CVE"}}}"#.to_owned()).await.unwrap();
        database
            .import_epss_csv(include_str!("../../../fixtures/epss/epss-test.csv").to_owned())
            .await
            .unwrap();
        let count: i64 = database
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query_scalar("SELECT COUNT(*) FROM epss_current")
                        .fetch_one(connection)
                        .await
                })
            })
            .await
            .unwrap();
        assert_eq!(count, 1);
        let risks = database
            .search_epss_risk(Some(0.1), Some(0.1), false, 10, 0)
            .await
            .unwrap();
        assert_eq!(risks.len(), 1);
        assert_eq!(risks[0].cve_id, "CVE-2099-0001");
        assert!(!risks[0].kev_listed);
    }

    #[tokio::test]
    async fn full_detail_includes_epss_kev_and_related_osv() {
        let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        database.initialize().await.unwrap();
        database.import_cve_raw_json(r#"{"cveMetadata":{"cveId":"CVE-2099-0001","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-01T00:00:00Z"},"containers":{"cna":{"title":"Enriched fixture"}}}"#.to_owned()).await.unwrap();
        database.import_osv_record(OsvRawRecord {
            source_path: None,
            raw_json: r#"{"schema_version":"1.8.0","id":"GHSA-2099-enriched","modified":"2099-01-01T00:00:00Z","aliases":["CVE-2099-0001"]}"#.to_owned(),
        }).await.unwrap();
        database
            .import_epss_csv(include_str!("../../../fixtures/epss/epss-test.csv").to_owned())
            .await
            .unwrap();
        database
            .import_kev_json(include_str!("../../../fixtures/kev/kev-test.json").to_owned())
            .await
            .unwrap();
        let detail = database.cve_detail("CVE-2099-0001").await.unwrap().unwrap();
        assert!(detail.epss.is_some());
        assert!(detail.kev.is_some());
        assert_eq!(
            detail
                .osv_advisories
                .iter()
                .map(|advisory| advisory.osv_id.as_str())
                .collect::<Vec<_>>(),
            vec!["GHSA-2099-enriched"]
        );
    }

    #[tokio::test]
    async fn package_query_requires_a_verified_range_for_confirmed_status() {
        let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        database.initialize().await.unwrap();
        database
            .import_osv_record(OsvRawRecord {
                source_path: None,
                raw_json: r#"{"schema_version":"1.8.0","id":"GHSA-2099-package","modified":"2099-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"crates.io","name":"example"},"versions":["3.0.0"],"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"2.0.0"}]}]}]}"#.to_owned(),
            })
            .await
            .unwrap();
        assert_eq!(
            database
                .query_osv_package("crates.io", "example", "1.5.0")
                .await
                .unwrap()[0]
                .status,
            "affected"
        );
        assert_eq!(
            database
                .query_osv_package("crates.io", "example", "2.0.0")
                .await
                .unwrap()[0]
                .status,
            "not_affected"
        );
        assert_eq!(
            database
                .query_osv_package("crates.io", "example", "3.0.0")
                .await
                .unwrap()[0]
                .status,
            "affected"
        );
        assert!(
            database
                .query_osv_package("npm", "example", "1.5.0")
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn package_query_accepts_purl_without_confirming_an_unverified_name_match() {
        let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        database.initialize().await.unwrap();
        database
            .import_osv_record(OsvRawRecord {
                source_path: None,
                raw_json: r#"{"schema_version":"1.8.0","id":"GHSA-2099-purl","modified":"2099-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"crates.io","name":"different-name","purl":"pkg:cargo/example@1.5.0"}}]}"#.to_owned(),
            })
            .await
            .unwrap();
        let findings = database
            .query_osv_package_with_purl(
                "crates.io",
                "example",
                "1.5.0",
                Some("pkg:cargo/example@1.5.0"),
            )
            .await
            .unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].status, "unknown");
        assert_eq!(findings[0].confidence, "low");
    }

    #[tokio::test]
    async fn imports_kev_through_integer_cve_foreign_keys_idempotently() {
        let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        database.initialize().await.unwrap();
        database.import_cve_raw_json(r#"{"cveMetadata":{"cveId":"CVE-2099-0001","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-01T00:00:00Z"},"containers":{"cna":{"title":"Example CVE"}}}"#.to_owned()).await.unwrap();
        let fixture = include_str!("../../../fixtures/kev/kev-test.json").to_owned();
        assert_eq!(database.import_kev_json(fixture.clone()).await.unwrap(), 1);
        assert_eq!(database.import_kev_json(fixture).await.unwrap(), 1);
        let row: (String, String) = database.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query_as("SELECT kev_entries.cve_id, cve.cve_id FROM kev_entries JOIN cve ON cve.cve_id = kev_entries.cve_id")
                .fetch_one(connection).await
        })).await.unwrap();
        assert_eq!(
            row,
            ("CVE-2099-0001".to_owned(), "CVE-2099-0001".to_owned())
        );
        assert_eq!(
            database
                .kev_entries(Some("CVE-2099-0001"), 10, 0)
                .await
                .unwrap()
                .into_iter()
                .map(|entry| entry.cve_id)
                .collect::<Vec<_>>(),
            vec!["CVE-2099-0001"]
        );
    }

    #[tokio::test]
    async fn osv_cursor_advances_only_after_a_complete_retryable_sync() {
        let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        database.initialize().await.unwrap();
        assert_eq!(database.begin_osv_sync().await.unwrap(), None);
        let valid = OsvRawRecord {
            source_path: None,
            raw_json: r#"{"schema_version":"1.8.0","id":"GHSA-2099-retry","modified":"2099-01-01T00:00:00Z"}"#.to_owned(),
        };
        let invalid = OsvRawRecord {
            source_path: None,
            raw_json: r#"{"schema_version":"1.7.3","id":"GHSA-2099-invalid"}"#.to_owned(),
        };
        assert!(
            database
                .import_osv_records(vec![valid.clone(), invalid])
                .await
                .is_err()
        );
        let imported_after_failed_batch: i64 = database
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query_scalar("SELECT COUNT(*) FROM osv_advisories")
                        .fetch_one(connection)
                        .await
                })
            })
            .await
            .unwrap();
        assert_eq!(imported_after_failed_batch, 0);
        database.fail_osv_sync("later batch failed").await.unwrap();
        let failed: (String, Option<String>) = database
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query_as(
                        "SELECT status, last_cursor FROM source_sync_state WHERE source='OSV'",
                    )
                    .fetch_one(connection)
                    .await
                })
            })
            .await
            .unwrap();
        assert_eq!(failed, ("failed".to_owned(), None));
        assert_eq!(database.begin_osv_sync().await.unwrap(), None);
        database.import_osv_records(vec![valid]).await.unwrap();
        database.rebuild_search().await.unwrap();
        database.check().await.unwrap();
        database
            .complete_osv_sync("2099-01-02T00:00:00Z")
            .await
            .unwrap();
        let completed: (String, String, i64) = database.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query_as("SELECT status, last_cursor, (SELECT COUNT(*) FROM osv_advisories) FROM source_sync_state WHERE source='OSV'").fetch_one(connection).await
        })).await.unwrap();
        assert_eq!(
            completed,
            ("success".to_owned(), "2099-01-02T00:00:00Z".to_owned(), 1)
        );
    }
}
