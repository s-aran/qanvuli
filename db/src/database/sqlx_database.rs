//! SQLite database implementation.

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
    CveDetail, CveStateScope, CveSummary, CveSummarySortOrder, CveSummaryWithDetail,
    EnrichedFinding, FindingEnrichment, OsvRawRecord, PackageQuery, PrioritySignals,
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

/// Maximum number of caller package queries encoded in one SQLite JSON input.
const PACKAGE_QUERY_BATCH_SIZE: usize = 200;
/// Maximum number of affected-package IDs used by one range/version statement.
const PACKAGE_ID_BATCH_SIZE: usize = 2_000;
/// Maximum number of OSV IDs used by one alias statement.
const OSV_ID_BATCH_SIZE: usize = 2_000;
/// Maximum number of OSV IDs used by one advisory-date statement.
const OSV_DATE_BATCH_SIZE: usize = 2_000;
/// Above this FTS candidate count, walking the published-date index can stop at the requested
/// page and is substantially cheaper than sorting every FTS match.
const FTS_PUBLISHED_INDEX_MIN_CANDIDATES: i64 = 128;

type AffectedRow = (i64, Option<String>, Option<String>, Option<String>, String);
type BatchedCvssRow = (
    i64,
    String,
    Option<f64>,
    Option<String>,
    Option<String>,
    Option<String>,
);
type BatchedAffectedRow = (i64, Option<String>, Option<String>, Option<String>, String);
type BatchedEpssRow = (String, f64, f64, Option<String>, Option<String>);
type BatchedKevRow = (
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    String,
    Option<String>,
);
type BatchedOsvRow = (
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
);
const CVE_NORMALIZE_BATCH_SIZE: usize = 2_000;

/// Applies PEP 503 normalization to published and queried package names.
fn normalized_package_name(name: &str) -> String {
    let mut normalized = String::with_capacity(name.len());
    let mut previous_separator = false;
    for character in name.chars() {
        if matches!(character, '-' | '_' | '.') {
            if !previous_separator {
                normalized.push('-');
            }
            previous_separator = true;
        } else {
            normalized.push(character.to_ascii_lowercase());
            previous_separator = false;
        }
    }
    normalized
}

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

/// Outcome of one bounded OSV database batch.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub struct OsvImportStats {
    pub examined: usize,
    pub inserted: usize,
    pub updated: usize,
    pub unchanged: usize,
}

impl OsvImportStats {
    pub fn changed(self) -> usize {
        self.inserted + self.updated
    }
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

/// CVE search result.
#[derive(Clone, Debug, serde::Serialize, sqlx::FromRow)]
pub struct SqlxCveSummary {
    pub cve_id: String,
    pub state: i64,
    pub published_at: String,
    pub updated_at: String,
    pub title: String,
    pub description_en: Option<String>,
}

/// Normalized CVE details.
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

/// CVE result with normalized details.
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

/// Bound filters for normalized CVE searches.
#[derive(Clone, Debug, Default)]
pub struct SqlxCveSearch {
    pub text: Option<String>,
    pub cwe_ids: Vec<String>,
    pub capec_ids: Vec<String>,
    pub vendor_like: Option<String>,
    pub product_like: Option<String>,
    pub vendor_exact: Option<String>,
    pub product_exact: Option<String>,
    pub cvss: SqlxCvssSearch,
    pub published_since: Option<String>,
    pub published_until: Option<String>,
    pub updated_since: Option<String>,
    pub updated_until: Option<String>,
    pub sort_order: CveSummarySortOrder,
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
    pub description: Option<String>,
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
    pub details: Option<String>,
    pub withdrawn_at: Option<String>,
}

#[derive(Clone, Debug, serde::Serialize, sqlx::FromRow)]
pub struct SqlxDatabaseStatus {
    pub cve_count: i64,
    pub osv_count: i64,
    pub cwe_count: i64,
    pub capec_count: i64,
    pub capec_category_count: i64,
    pub capec_view_count: i64,
    pub capec_reference_count: i64,
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
                        description: row.description,
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

/// Database handle backed by one writer connection.
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

    #[allow(clippy::too_many_arguments)]
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

    pub async fn query_package_matches(
        &self,
        ecosystem: &str,
        package: &str,
        version: &str,
        purl: Option<&str>,
    ) -> Result<Vec<EnrichedFinding>, sqlx::Error> {
        let query = PackageQuery {
            ecosystem: ecosystem.to_owned(),
            package: package.to_owned(),
            version: version.to_owned(),
            purl: purl.map(str::to_owned),
        };
        Ok(self
            .query_package_matches_batch(std::slice::from_ref(&query))
            .await?
            .pop()
            .unwrap_or_default())
    }

    /// Returns whether the local OSV corpus has any non-withdrawn advisory for this package
    /// identity, independently of the queried version.
    pub async fn has_osv_package_advisory(
        &self,
        ecosystem: &str,
        package: &str,
        purl: Option<&str>,
    ) -> Result<bool, sqlx::Error> {
        let ecosystem = ecosystem.to_owned();
        let package = normalized_package_name(package);
        let purl = purl.map(str::to_owned);
        self.writer
            .with_connection(|connection| {
                Box::pin(async move {
                    let exists: i64 = sqlx::query_scalar(
                        "SELECT EXISTS(SELECT 1 FROM osv_affected_packages AS package JOIN osv_advisories AS advisory ON advisory.osv_id=package.osv_id WHERE advisory.withdrawn_at IS NULL AND package.ecosystem=? COLLATE NOCASE AND (replace(replace(lower(package.package_name), '_', '-'), '.', '-')=? OR (? IS NOT NULL AND package.purl=?)))",
                    )
                    .bind(ecosystem)
                    .bind(package)
                    .bind(&purl)
                    .bind(&purl)
                    .fetch_one(connection)
                    .await?;
                    Ok(exists != 0)
                })
            })
            .await
    }

    /// Returns local OSV coverage for every query in order, without evaluating versions.
    pub async fn has_osv_package_advisories_batch(
        &self,
        packages: &[PackageQuery],
    ) -> Result<Vec<bool>, sqlx::Error> {
        if packages.is_empty() {
            return Ok(Vec::new());
        }
        let mut packages = packages.to_vec();
        for package in &mut packages {
            package.package = normalized_package_name(&package.package);
        }
        self.writer
            .with_connection(|connection| {
                Box::pin(async move {
                    let input = serde_json::to_string(&packages).map_err(|error| {
                        sqlx::Error::Protocol(format!("failed to encode package queries: {error}"))
                    })?;
                    let rows: Vec<(i64, i64)> = sqlx::query_as(
                        "WITH input AS (SELECT CAST(key AS INTEGER) AS query_index, json_extract(value, '$.ecosystem') AS ecosystem, json_extract(value, '$.package') AS package_name, json_extract(value, '$.purl') AS purl FROM json_each(?)) SELECT input.query_index, EXISTS(SELECT 1 FROM osv_affected_packages AS package JOIN osv_advisories AS advisory ON advisory.osv_id=package.osv_id WHERE advisory.withdrawn_at IS NULL AND package.ecosystem=input.ecosystem COLLATE NOCASE AND (replace(replace(lower(package.package_name), '_', '-'), '.', '-')=input.package_name OR (input.purl IS NOT NULL AND package.purl=input.purl))) FROM input ORDER BY input.query_index",
                    )
                    .bind(input)
                    .fetch_all(connection)
                    .await?;
                    let mut coverage = vec![false; packages.len()];
                    for (index, covered) in rows {
                        if let Ok(index) = usize::try_from(index)
                            && let Some(value) = coverage.get_mut(index)
                        {
                            *value = covered != 0;
                        }
                    }
                    Ok(coverage)
                })
            })
            .await
    }

    /// Matches package/version queries with bounded candidate scans and bounded follow-up reads
    /// for ranges, explicit versions, and CVE aliases.
    pub async fn query_package_matches_batch(
        &self,
        packages: &[PackageQuery],
    ) -> Result<Vec<Vec<EnrichedFinding>>, sqlx::Error> {
        if packages.is_empty() {
            return Ok(Vec::new());
        }
        let mut packages = packages.to_vec();
        for package in &mut packages {
            package.package = normalized_package_name(&package.package);
        }
        self.writer.with_connection(|connection| Box::pin(async move {
            let mut output = vec![Vec::new(); packages.len()];
            for (query_batch_index, package_batch) in
                packages.chunks(PACKAGE_QUERY_BATCH_SIZE).enumerate()
            {
                let input_json = serde_json::to_string(package_batch).map_err(|error| {
                    sqlx::Error::Protocol(format!("failed to encode package queries: {error}"))
                })?;
                let candidates: Vec<(i64, i64, String)> = sqlx::query_as(
                    "WITH input AS (SELECT CAST(key AS INTEGER) AS query_index, json_extract(value, '$.ecosystem') AS ecosystem, json_extract(value, '$.package') AS package_name, json_extract(value, '$.purl') AS purl FROM json_each(?)) SELECT input.query_index, package.id, package.osv_id FROM input JOIN osv_affected_packages AS package ON package.ecosystem=input.ecosystem COLLATE NOCASE AND (replace(replace(lower(package.package_name), '_', '-'), '.', '-')=input.package_name OR (input.purl IS NOT NULL AND package.purl=input.purl)) JOIN osv_advisories AS advisory ON advisory.osv_id=package.osv_id WHERE advisory.withdrawn_at IS NULL ORDER BY input.query_index, package.osv_id, package.id",
                )
                .bind(input_json)
                .fetch_all(&mut *connection)
                .await?;

                let package_ids = candidates
                    .iter()
                    .map(|(_, id, _)| *id)
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>();
                let mut ranges_by_package = BTreeMap::<i64, Vec<OsvRange>>::new();
                let mut versions_by_package = BTreeMap::<i64, BTreeSet<String>>::new();
                for package_id_batch in package_ids.chunks(PACKAGE_ID_BATCH_SIZE) {
                    let package_ids_json = serde_json::to_string(package_id_batch).map_err(|error| {
                        sqlx::Error::Protocol(format!("failed to encode OSV package IDs: {error}"))
                    })?;
                    let events: Vec<(i64, i64, String, String, String)> = sqlx::query_as(
                        "SELECT range.affected_package_id, range.id, range.range_type, event.event_type, event.value FROM osv_ranges AS range JOIN osv_range_events AS event ON event.range_id=range.id WHERE range.affected_package_id IN (SELECT value FROM json_each(?)) ORDER BY range.affected_package_id, range.id, event.id",
                    )
                    .bind(&package_ids_json)
                    .fetch_all(&mut *connection)
                    .await?;
                    let mut current_range = None;
                    for (package_id, range_id, range_type, event_type, value) in events {
                        let ranges = ranges_by_package.entry(package_id).or_default();
                        if current_range != Some((package_id, range_id)) {
                            current_range = Some((package_id, range_id));
                            ranges.push(OsvRange { range_type, events: Vec::new() });
                        }
                        ranges.last_mut().expect("range inserted").events.push((event_type, value));
                    }
                    let version_rows: Vec<(i64, String)> = sqlx::query_as(
                        "SELECT affected_package_id, version FROM osv_versions WHERE affected_package_id IN (SELECT value FROM json_each(?))",
                    )
                    .bind(&package_ids_json)
                    .fetch_all(&mut *connection)
                    .await?;
                    for (package_id, version) in version_rows {
                        versions_by_package.entry(package_id).or_default().insert(version);
                    }
                }

                let osv_ids = candidates
                    .iter()
                    .map(|(_, _, id)| id.clone())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>();
                let mut aliases_by_osv = BTreeMap::<String, Vec<String>>::new();
                for osv_id_batch in osv_ids.chunks(OSV_ID_BATCH_SIZE) {
                    let osv_ids_json = serde_json::to_string(osv_id_batch).map_err(|error| {
                        sqlx::Error::Protocol(format!("failed to encode OSV IDs: {error}"))
                    })?;
                    let alias_rows: Vec<(String, String)> = sqlx::query_as(
                        "SELECT osv_id, alias_id FROM osv_aliases WHERE alias_id LIKE 'CVE-%' AND osv_id IN (SELECT value FROM json_each(?)) ORDER BY osv_id, alias_id",
                    )
                    .bind(osv_ids_json)
                    .fetch_all(&mut *connection)
                    .await?;
                    for (osv_id, alias) in alias_rows {
                        aliases_by_osv.entry(osv_id).or_default().push(alias);
                    }
                }

                let query_offset = query_batch_index * PACKAGE_QUERY_BATCH_SIZE;
                for (query_index, package_id, osv_id) in candidates {
                    let local_index = usize::try_from(query_index).map_err(|_| {
                        sqlx::Error::Protocol("invalid package query index".to_owned())
                    })?;
                    let output_index = query_offset + local_index;
                    let query = packages.get(output_index).ok_or_else(|| {
                        sqlx::Error::Protocol("package query index is out of bounds".to_owned())
                    })?;
                    let matched = if versions_by_package
                        .get(&package_id)
                        .is_some_and(|versions| versions.contains(&query.version))
                    {
                        super::package_eval::VersionMatch {
                            status: "affected".to_owned(),
                            confidence: "high".to_owned(),
                        }
                    } else {
                        evaluate_version(
                            &query.ecosystem,
                            &query.version,
                            ranges_by_package
                                .get(&package_id)
                                .map(Vec::as_slice)
                                .unwrap_or_default(),
                        )
                    };
                    if matched.status == "not_affected" {
                        continue;
                    }
                    let affected = AffectedStatus { status: matched.status, confidence: matched.confidence };
                    let fixed_versions = ranges_by_package
                        .get(&package_id)
                        .into_iter()
                        .flatten()
                        .flat_map(|range| range.events.iter())
                        .filter(|(event_type, _)| event_type == "fixed")
                        .map(|(_, version)| version.clone())
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .collect::<Vec<_>>();
                    output[output_index].push(EnrichedFinding {
                        primary_id: osv_id.clone(), cve_ids: aliases_by_osv.get(&osv_id).cloned().unwrap_or_default(), aliases: Vec::new(), aliases_status: "not_queried".to_owned(), package: query.clone(), affected: affected.clone(), fixed_versions_status: "available".to_owned(), priority_signals: PrioritySignals { known_exploited: false, epss_percentile: None, has_fixed_version: !fixed_versions.is_empty(), affected_confidence: affected.confidence, suggested_priority: "unknown".to_owned(), reasons: Vec::new(), enrichment_status: "not_queried".to_owned() }, fixed_versions, enrichment: FindingEnrichment { kev: None, kev_status: "not_queried".to_owned(), epss: None, epss_status: "not_queried".to_owned() }, evidence: Vec::new(), evidence_status: "not_queried".to_owned()
                    });
                }
            }
            Ok(output)
        })).await
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

    /// Closes the writer before database replacement.
    pub async fn close(self) -> Result<(), sqlx::Error> {
        self.writer.close().await
    }

    pub async fn rebuild_search(&self) -> Result<(), sqlx::Error> {
        self.writer.rebuild_search().await
    }

    pub async fn rebuild_cve_search(&self) -> Result<(), sqlx::Error> {
        self.writer.rebuild_cve_search().await
    }

    /// Refreshes search projections for the CVEs changed by a delta update.
    pub async fn refresh_cve_search_for_ids(
        &self,
        cve_ids: Vec<String>,
    ) -> Result<(), sqlx::Error> {
        self.writer.refresh_cve_search_for_ids(cve_ids).await
    }

    pub async fn rebuild_osv_search(&self) -> Result<(), sqlx::Error> {
        self.writer.rebuild_osv_search().await
    }

    /// Verifies schema plus a fixed number of indexed search-projection sentinels.
    pub async fn check_search_integrity_quick(&self) -> Result<(), sqlx::Error> {
        self.writer.check_search_integrity_quick().await
    }

    /// Verifies schema shape/version without requiring derived search data to be healthy.
    pub async fn check_required_schema(&self) -> Result<(), sqlx::Error> {
        self.writer.check_required_schema().await
    }

    /// Prepares a replacement database for bulk CVE loading.
    pub async fn prepare_cve_bulk_load(&self) -> Result<(), sqlx::Error> {
        self.writer.prepare_cve_bulk_load().await
    }

    /// Builds deferred indexes/search data and restores normal SQLite durability.
    pub async fn finish_cve_bulk_load(&self) -> Result<(), sqlx::Error> {
        self.writer.finish_cve_bulk_load().await
    }

    pub async fn finish_cve_bulk_load_with_index_signal(
        &self,
        index_started: tokio::sync::oneshot::Sender<()>,
    ) -> Result<(), sqlx::Error> {
        self.writer
            .finish_cve_bulk_load_with_index_signal(index_started)
            .await
    }

    pub async fn prepare_osv_bulk_load(&self) -> Result<(), sqlx::Error> {
        self.writer.prepare_osv_bulk_load().await
    }

    pub async fn finish_osv_bulk_load(&self) -> Result<(), sqlx::Error> {
        self.writer.finish_osv_bulk_load().await
    }

    /// Rebuilds identifier edges from normalized OSV relations.
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
        self.writer.check_quick().await
    }

    /// Runs SQLite quick_check and complete search correspondence scans.
    pub async fn check_scan(&self) -> Result<(), sqlx::Error> {
        self.writer.check_scan().await
    }

    /// Runs only SQLite quick_check (plus connection foreign-key enforcement verification).
    /// Replacement validation uses this separately so failures identify the exact stage.
    pub async fn check_scan_sqlite(&self) -> Result<(), sqlx::Error> {
        self.writer.check_sqlite_quick().await
    }

    /// Runs the expensive SQLite file-integrity stage used by `db check --full`.
    pub async fn check_full_sqlite(&self) -> Result<(), sqlx::Error> {
        self.writer.check_integrity().await
    }

    /// Runs the complete foreign-key scan used by `db check --full`.
    pub async fn check_full_foreign_keys(&self) -> Result<(), sqlx::Error> {
        self.writer.check_foreign_key_integrity().await
    }

    /// Runs native FTS and complete CVE projection checks.
    pub async fn check_full_cve_search(&self) -> Result<(), sqlx::Error> {
        self.writer.check_cve_search_full().await
    }

    /// Runs native FTS and complete OSV projection checks.
    pub async fn check_full_osv_search(&self) -> Result<(), sqlx::Error> {
        self.writer.check_osv_search_full().await
    }

    pub const fn schema_version() -> i64 {
        schema::SCHEMA_VERSION
    }

    /// Finds a CVE by its public identifier.
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

    /// Returns the original provider JSON for a CVE.
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

    /// Searches CVE identifiers by prefix.
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
    #[allow(clippy::too_many_arguments)]
    pub async fn search_cves_by_affected(
        &self,
        vendor: Option<String>,
        product: Option<String>,
        exact: bool,
        exclude_wordpress_collection: bool,
        include_rejected: bool,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SqlxCveSummary>, sqlx::Error> {
        let vendor = vendor.map(|value| if exact { value } else { format!("%{value}%") });
        let product_rank = product.clone();
        let product = product.map(|value| if exact { value } else { format!("%{value}%") });
        self.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query_as("SELECT c.cve_id, c.state, c.published_at, c.updated_at, c.title, c.description_en FROM cve AS c JOIN cve_affected AS affected ON affected.cve_db_id=c.id WHERE (? OR c.state=0) AND (? OR affected.collection_url NOT LIKE '%wordpress.org%') AND (? IS NULL OR CASE WHEN ? THEN affected.vendor=? ELSE affected.vendor LIKE ? END) AND (? IS NULL OR CASE WHEN ? THEN (affected.product=? OR affected.package_name=?) ELSE (affected.product LIKE ? OR affected.package_name LIKE ?) END) GROUP BY c.id ORDER BY MIN(CASE WHEN ? IS NULL THEN 0 WHEN affected.product=? OR affected.package_name=? THEN 0 WHEN affected.product LIKE ? || ' %' OR affected.product LIKE '% ' || ? OR affected.product LIKE ? || '-%' OR affected.product LIKE '%-' || ? OR affected.package_name LIKE ? || ' %' OR affected.package_name LIKE '% ' || ? OR affected.package_name LIKE ? || '-%' OR affected.package_name LIKE '%-' || ? THEN 1 ELSE 2 END), c.updated_at DESC, c.cve_id DESC LIMIT ? OFFSET ?")
                .bind(include_rejected)
                .bind(!exclude_wordpress_collection)
                .bind(&vendor).bind(exact).bind(&vendor).bind(&vendor)
                .bind(&product).bind(exact).bind(&product).bind(&product).bind(&product).bind(&product)
                .bind(&product_rank).bind(&product_rank).bind(&product_rank)
                .bind(&product_rank).bind(&product_rank).bind(&product_rank).bind(&product_rank).bind(&product_rank).bind(&product_rank).bind(&product_rank).bind(&product_rank)
                .bind(limit.max(1)).bind(offset.max(0)).fetch_all(connection).await
        })).await
    }

    /// Finds vendor/product candidates without evaluating version expressions.
    ///
    /// CNA expressions such as `< 2.0.0` cannot be compared to installed versions with `LIKE`.
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
        let _version = version;
        self.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query_as("SELECT DISTINCT c.cve_id, c.state, c.published_at, c.updated_at, c.title, c.description_en FROM cve AS c JOIN cve_affected AS affected ON affected.cve_db_id=c.id WHERE (? OR c.state=0) AND (? IS NULL OR affected.vendor LIKE ?) AND (? IS NULL OR affected.product LIKE ? OR affected.package_name LIKE ?) ORDER BY c.updated_at DESC, c.cve_id DESC LIMIT ? OFFSET ?")
                .bind(include_rejected)
                .bind(&vendor).bind(&vendor)
                .bind(&product).bind(&product).bind(&product)
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
        self.search_cves_advanced_with_kev(filters, include_rejected, false, limit, offset)
            .await
    }

    pub(crate) async fn search_cves_advanced_with_kev(
        &self,
        filters: SqlxCveSearch,
        include_rejected: bool,
        kev_only: bool,
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
        let capec_ids = filters
            .capec_ids
            .iter()
            .filter_map(|value| {
                value
                    .trim()
                    .strip_prefix("CAPEC-")
                    .unwrap_or(value.trim())
                    .parse::<i64>()
                    .ok()
            })
            .collect::<Vec<_>>();
        let capec_ids = (!capec_ids.is_empty())
            .then(|| serde_json::to_string(&capec_ids))
            .transpose()
            .map_err(|error| {
                sqlx::Error::Protocol(format!("failed to encode CAPEC IDs: {error}"))
            })?;
        let text = filters.text.as_deref().and_then(fts_query);
        let use_published_index = matches!(
            filters.sort_order,
            CveSummarySortOrder::PublishedAsc | CveSummarySortOrder::PublishedDesc
        ) && if let Some(text) = text.clone() {
            let candidates: i64 = self
                .writer
                .with_connection(|connection| {
                    Box::pin(async move {
                        sqlx::query_scalar(
                            "SELECT COUNT(*) FROM cve_summary_fts WHERE cve_summary_fts MATCH ?",
                        )
                        .bind(text)
                        .fetch_one(connection)
                        .await
                    })
                })
                .await?;
            candidates >= FTS_PUBLISHED_INDEX_MIN_CANDIDATES
        } else {
            false
        };
        self.writer.with_connection(|connection| Box::pin(async move {
            let mut query = QueryBuilder::<Sqlite>::new(if use_published_index {
                "SELECT c.cve_id, c.state, c.published_at, c.updated_at, c.title, c.description_en FROM cve AS c INDEXED BY idx_cve_published_at_cve_id WHERE 1=1"
            } else {
                "SELECT c.cve_id, c.state, c.published_at, c.updated_at, c.title, c.description_en FROM cve AS c WHERE 1=1"
            });
            if !include_rejected { query.push(" AND c.state=0"); }
            if let Some(value) = filters.published_since { query.push(" AND c.published_at >= ").push_bind(value); }
            if let Some(value) = filters.published_until { query.push(" AND c.published_at <= ").push_bind(value); }
            if let Some(value) = filters.updated_since { query.push(" AND c.updated_at >= ").push_bind(value); }
            if let Some(value) = filters.updated_until { query.push(" AND c.updated_at <= ").push_bind(value); }
            if let Some(value) = text {
                query.push(" AND c.cve_id IN (SELECT cve_id FROM cve_summary_fts WHERE cve_summary_fts MATCH ").push_bind(value).push(")");
            }
            if let Some(value) = cwe_ids {
                query.push(" AND EXISTS (SELECT 1 FROM cve_cwe WHERE cve_cwe.cve_db_id=c.id AND cve_cwe.cwe_id IN (SELECT value FROM json_each(").push_bind(value).push(")))");
            }
            if let Some(value) = capec_ids {
                query.push(" AND EXISTS (SELECT 1 FROM cve_cwe JOIN capec_cwe ON capec_cwe.cwe_id=cve_cwe.cwe_id WHERE cve_cwe.cve_db_id=c.id AND capec_cwe.capec_id IN (SELECT value FROM json_each(").push_bind(value).push(")))");
            }
            if kev_only {
                query.push(" AND EXISTS (SELECT 1 FROM kev_entries WHERE kev_entries.cve_id=c.cve_id)");
            }
            let has_affected = filters.vendor_like.is_some() || filters.product_like.is_some() || filters.vendor_exact.is_some() || filters.product_exact.is_some();
            if has_affected {
                query.push(" AND EXISTS (SELECT 1 FROM cve_affected AS affected WHERE affected.cve_db_id=c.id");
                if let Some(value) = filters.vendor_like { query.push(" AND affected.vendor LIKE ").push_bind(value); }
                if let Some(value) = filters.product_like { query.push(" AND affected.product LIKE ").push_bind(value); }
                if let Some(value) = filters.vendor_exact { query.push(" AND affected.vendor=").push_bind(value); }
                if let Some(value) = filters.product_exact { query.push(" AND affected.product=").push_bind(value); }
                query.push(")");
            }
            let has_cvss = filters.cvss.min_score.is_some() || filters.cvss.max_score.is_some() || filters.cvss.severity.is_some() || filters.cvss.version.is_some();
            if has_cvss {
                query.push(" AND EXISTS (SELECT 1 FROM cve_cvss AS cvss WHERE cvss.cve_db_id=c.id");
                if let Some(value) = filters.cvss.min_score { query.push(" AND cvss.base_score >= ").push_bind(value); }
                if let Some(value) = filters.cvss.max_score { query.push(" AND cvss.base_score <= ").push_bind(value); }
                if let Some(value) = filters.cvss.severity { query.push(" AND lower(cvss.base_severity)=lower(").push_bind(value).push(")"); }
                if let Some(value) = filters.cvss.version { query.push(" AND cvss.version=").push_bind(value); }
                query.push(")");
            }
            match filters.sort_order {
                CveSummarySortOrder::PublishedAsc => query.push(" ORDER BY c.published_at ASC, c.cve_id ASC"),
                CveSummarySortOrder::PublishedDesc => query.push(" ORDER BY c.published_at DESC, c.cve_id DESC"),
                CveSummarySortOrder::UpdatedAsc => query.push(" ORDER BY c.updated_at ASC, c.cve_id ASC"),
                CveSummarySortOrder::UpdatedDesc => query.push(" ORDER BY c.updated_at DESC, c.cve_id DESC"),
                CveSummarySortOrder::CveIdAsc => query.push(" ORDER BY c.cve_id ASC"),
                CveSummarySortOrder::CveIdDesc => query.push(" ORDER BY c.cve_id DESC"),
                // Relation rank is only meaningful for identifier-graph searches. Keep the
                // normal CVE list deterministic when no graph ranking is available.
                CveSummarySortOrder::RelationRankAsc => query.push(" ORDER BY c.published_at ASC, c.cve_id ASC"),
                CveSummarySortOrder::RelationRankDesc => query.push(" ORDER BY c.published_at DESC, c.cve_id DESC"),
                CveSummarySortOrder::ScoreAsc => query.push(" ORDER BY (SELECT MAX(base_score) FROM cve_cvss WHERE cve_db_id=c.id) IS NULL ASC, (SELECT MAX(base_score) FROM cve_cvss WHERE cve_db_id=c.id) ASC, c.cve_id ASC"),
                CveSummarySortOrder::ScoreDesc => query.push(" ORDER BY (SELECT MAX(base_score) FROM cve_cvss WHERE cve_db_id=c.id) IS NULL ASC, (SELECT MAX(base_score) FROM cve_cvss WHERE cve_db_id=c.id) DESC, c.cve_id DESC"),
            };
            query.push(" LIMIT ").push_bind(limit.max(1)).push(" OFFSET ").push_bind(offset.max(0));
            query.build_query_as().fetch_all(connection).await
        })).await
    }

    /// Loads full normalized detail in batches per CVE, preserving source ordering in each detail.
    pub async fn cve_detail(&self, cve_id: &str) -> Result<Option<SqlxCveDetail>, sqlx::Error> {
        let cve_id = cve_id.to_owned();
        self.writer.with_connection(|connection| Box::pin(async move {
            let Some(id): Option<i64> = sqlx::query_scalar("SELECT id FROM cve WHERE cve_id=?").bind(&cve_id).fetch_optional(&mut *connection).await? else { return Ok(None); };
            let cvss = sqlx::query_as("SELECT version, base_score, base_severity, vector_string, source FROM cve_cvss WHERE cve_db_id=? ORDER BY id").bind(id).fetch_all(&mut *connection).await?;
            let cwes = sqlx::query_as("SELECT cwe.id, cwe.description FROM cve_cwe JOIN cwe ON cwe.id=cve_cwe.cwe_id WHERE cve_cwe.cve_db_id=? ORDER BY cwe.id").bind(id).fetch_all(&mut *connection).await?;
            let raw_json: String = sqlx::query_scalar("SELECT raw_json FROM cve WHERE id=?").bind(id).fetch_one(&mut *connection).await?;
            let affected_descriptions = cve_affected_descriptions(&raw_json);
            let affected_rows: Vec<AffectedRow> = sqlx::query_as("SELECT id, vendor, product, package_name, raw_json FROM cve_affected WHERE cve_db_id=? ORDER BY id").bind(id).fetch_all(&mut *connection).await?;
            let mut affected = Vec::with_capacity(affected_rows.len());
            for (affected_index, (_affected_id, vendor, product, package_name, raw_json)) in affected_rows.into_iter().enumerate() {
                let versions = serde_json::from_str::<Vec<(Option<String>, Option<String>, Option<String>, Option<String>, Option<String>)>>(&raw_json)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|(version, status, version_type, less_than, less_than_or_equal)| SqlxAffectedVersion { version, status, version_type, less_than, less_than_or_equal })
                    .collect();
                let description = affected_descriptions.get(affected_index).cloned().flatten();
                affected.push(SqlxAffected { vendor, product, package_name, description, versions });
            }
            let references = serde_json::from_str::<Value>(&raw_json)
                .map(|value| cve_references(value.pointer("/containers/cna"), value.pointer("/containers/adp")))
                .unwrap_or_default();
            let epss = sqlx::query_as("SELECT epss, percentile, score_date, model_version FROM epss_current WHERE cve_id=?").bind(&cve_id).fetch_optional(&mut *connection).await?;
            let kev = sqlx::query_as("SELECT vendor_project, product, vulnerability_name, COALESCE(date_added, '') AS date_added, due_date FROM kev_entries WHERE cve_id=?").bind(&cve_id).fetch_optional(&mut *connection).await?;
            let osv_advisories = sqlx::query_as("SELECT advisory.osv_id, COALESCE(advisory.modified_at, '') AS modified_at, advisory.summary, advisory.details, advisory.withdrawn_at FROM osv_aliases AS alias JOIN osv_advisories AS advisory ON advisory.osv_id=alias.osv_id WHERE alias.alias_id=? ORDER BY advisory.modified_at DESC, advisory.osv_id").bind(&cve_id).fetch_all(&mut *connection).await?;
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

    /// Loads normalized details in a fixed number of set-based queries and restores caller order.
    pub async fn cve_details(
        &self,
        cve_ids: &[String],
    ) -> Result<Vec<Option<SqlxCveDetail>>, sqlx::Error> {
        if cve_ids.is_empty() {
            return Ok(Vec::new());
        }
        let requested = cve_ids.to_vec();
        let requested_json = serde_json::to_string(&requested)
            .map_err(|error| sqlx::Error::Protocol(format!("failed to encode CVE IDs: {error}")))?;
        self.writer.with_connection(|connection| Box::pin(async move {
            let parents: Vec<(i64, String, String)> = sqlx::query_as(
                "SELECT id, cve_id, raw_json FROM cve WHERE cve_id IN (SELECT value FROM json_each(?))",
            ).bind(&requested_json).fetch_all(&mut *connection).await?;
            let parent_ids = parents.iter().map(|(id, _, _)| *id).collect::<Vec<_>>();
            let parent_ids_json = serde_json::to_string(&parent_ids)
                .map_err(|error| sqlx::Error::Protocol(format!("failed to encode CVE row IDs: {error}")))?;
            let mut details = BTreeMap::<i64, SqlxCveDetail>::new();
            let mut ids_by_cve = BTreeMap::<String, i64>::new();
            let mut affected_descriptions_by_id = BTreeMap::<i64, Vec<Option<String>>>::new();
            for (id, cve_id, raw_json) in parents {
                let references = serde_json::from_str::<Value>(&raw_json)
                    .map(|value| cve_references(value.pointer("/containers/cna"), value.pointer("/containers/adp")))
                    .unwrap_or_default();
                details.insert(id, SqlxCveDetail { references, ..SqlxCveDetail::default() });
                affected_descriptions_by_id.insert(id, cve_affected_descriptions(&raw_json));
                ids_by_cve.insert(cve_id, id);
            }

            let cvss_rows: Vec<BatchedCvssRow> =
                sqlx::query_as("SELECT cve_db_id, version, base_score, base_severity, vector_string, source FROM cve_cvss WHERE cve_db_id IN (SELECT value FROM json_each(?)) ORDER BY id")
                    .bind(&parent_ids_json).fetch_all(&mut *connection).await?;
            for (id, version, base_score, base_severity, vector_string, source) in cvss_rows {
                if let Some(detail) = details.get_mut(&id) {
                    detail.cvss.push(SqlxCvss { version, base_score, base_severity, vector_string, source });
                }
            }
            let cwe_rows: Vec<(i64, i64, Option<String>)> = sqlx::query_as(
                "SELECT link.cve_db_id, cwe.id, cwe.description FROM cve_cwe link JOIN cwe ON cwe.id=link.cwe_id WHERE link.cve_db_id IN (SELECT value FROM json_each(?)) ORDER BY cwe.id",
            ).bind(&parent_ids_json).fetch_all(&mut *connection).await?;
            for (id, cwe_id, description) in cwe_rows {
                if let Some(detail) = details.get_mut(&id) {
                    detail.cwes.push(SqlxCwe { id: cwe_id, description });
                }
            }
            let affected_rows: Vec<BatchedAffectedRow> =
                sqlx::query_as("SELECT cve_db_id, vendor, product, package_name, raw_json FROM cve_affected WHERE cve_db_id IN (SELECT value FROM json_each(?)) ORDER BY id")
                    .bind(&parent_ids_json).fetch_all(&mut *connection).await?;
            let mut affected_indexes = BTreeMap::<i64, usize>::new();
            for (id, vendor, product, package_name, raw_json) in affected_rows {
                let versions = serde_json::from_str::<Vec<(Option<String>, Option<String>, Option<String>, Option<String>, Option<String>)>>(&raw_json)
                    .unwrap_or_default().into_iter()
                    .map(|(version, status, version_type, less_than, less_than_or_equal)| SqlxAffectedVersion { version, status, version_type, less_than, less_than_or_equal })
                    .collect();
                if let Some(detail) = details.get_mut(&id) {
                    let affected_index = affected_indexes.entry(id).or_default();
                    let description = affected_descriptions_by_id
                        .get(&id)
                        .and_then(|descriptions| descriptions.get(*affected_index))
                        .cloned()
                        .flatten();
                    *affected_index += 1;
                    detail.affected.push(SqlxAffected { vendor, product, package_name, description, versions });
                }
            }
            let epss_rows: Vec<BatchedEpssRow> = sqlx::query_as(
                "SELECT cve_id, epss, percentile, score_date, model_version FROM epss_current WHERE cve_id IN (SELECT value FROM json_each(?))",
            ).bind(&requested_json).fetch_all(&mut *connection).await?;
            for (cve_id, epss, percentile, score_date, model_version) in epss_rows {
                if let Some(id) = ids_by_cve.get(&cve_id) {
                    details.get_mut(id).expect("known parent").epss = Some(SqlxEpss { epss, percentile, score_date, model_version });
                }
            }
            let kev_rows: Vec<BatchedKevRow> = sqlx::query_as(
                "SELECT cve_id, vendor_project, product, vulnerability_name, COALESCE(date_added, ''), due_date FROM kev_entries WHERE cve_id IN (SELECT value FROM json_each(?))",
            ).bind(&requested_json).fetch_all(&mut *connection).await?;
            for (cve_id, vendor_project, product, vulnerability_name, date_added, due_date) in kev_rows {
                if let Some(id) = ids_by_cve.get(&cve_id) {
                    details.get_mut(id).expect("known parent").kev = Some(SqlxKev { vendor_project, product, vulnerability_name, date_added, due_date });
                }
            }
            let osv_rows: Vec<BatchedOsvRow> = sqlx::query_as(
                "SELECT alias.alias_id, advisory.osv_id, COALESCE(advisory.modified_at, ''), advisory.summary, advisory.details, advisory.withdrawn_at FROM osv_aliases alias JOIN osv_advisories advisory ON advisory.osv_id=alias.osv_id WHERE alias.alias_id IN (SELECT value FROM json_each(?)) ORDER BY advisory.modified_at DESC, advisory.osv_id",
            ).bind(&requested_json).fetch_all(&mut *connection).await?;
            for (cve_id, osv_id, modified_at, summary, osv_details, withdrawn_at) in osv_rows {
                if let Some(id) = ids_by_cve.get(&cve_id) {
                    details.get_mut(id).expect("known parent").osv_advisories.push(SqlxOsvSummary { osv_id, modified_at, summary, details: osv_details, withdrawn_at });
                }
            }
            Ok(requested.into_iter().map(|cve_id| {
                ids_by_cve.get(&cve_id).and_then(|id| details.get(id)).cloned()
            }).collect())
        })).await
    }

    pub async fn database_status(&self) -> Result<SqlxDatabaseStatus, sqlx::Error> {
        self.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query_as("SELECT (SELECT COUNT(*) FROM cve) AS cve_count, (SELECT COUNT(*) FROM osv_advisories) AS osv_count, (SELECT COUNT(*) FROM cwe) AS cwe_count, (SELECT COUNT(*) FROM capec) AS capec_count, (SELECT COUNT(*) FROM capec_category) AS capec_category_count, (SELECT COUNT(*) FROM capec_view) AS capec_view_count, (SELECT COUNT(*) FROM capec_external_reference) AS capec_reference_count, (SELECT COUNT(*) FROM cve_affected) AS affected_count, (SELECT COUNT(*) FROM cve_cvss) AS cvss_count, (SELECT MAX(updated_at) FROM cve) AS latest_cve_updated_at")
                .fetch_one(connection).await
        })).await
    }

    /// Returns the newest CVE update timestamp without scanning unrelated table counts.
    /// The TUI uses this lightweight value for its status line on startup and after update.
    pub async fn latest_cve_updated_at(&self) -> Result<Option<String>, sqlx::Error> {
        self.writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query_scalar(
                        "SELECT updated_at FROM cve ORDER BY updated_at DESC, cve_id DESC LIMIT 1",
                    )
                    .fetch_optional(connection)
                    .await
                })
            })
            .await
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

    /// Returns the cursor from the last successfully committed OSV synchronization.
    pub async fn osv_sync_cursor(&self) -> Result<Option<String>, sqlx::Error> {
        self.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query_scalar("SELECT last_cursor FROM source_sync_state WHERE source='OSV' AND status='success'")
                .fetch_optional(connection).await.map(Option::flatten)
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

    /// Resolves alias-equivalent identifiers transitively.
    ///
    /// Upstream and related edges do not establish vulnerability identity.
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

    /// Returns graph edges connected to a public identifier.
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
        let package_name = normalized_package_name(package_name);
        let version = version.to_owned();
        let purl = purl.map(str::to_owned);
        self.writer.with_connection(|connection| Box::pin(async move {
            let packages: Vec<(i64, String)> = sqlx::query_as("SELECT package.id, package.osv_id FROM osv_affected_packages AS package JOIN osv_advisories AS advisory ON advisory.osv_id=package.osv_id WHERE advisory.withdrawn_at IS NULL AND package.ecosystem=? COLLATE NOCASE AND (replace(replace(lower(package.package_name), '_', '-'), '.', '-')=? OR (? IS NOT NULL AND package.purl=?)) ORDER BY package.osv_id")
                .bind(&ecosystem).bind(&package_name).bind(&purl).bind(&purl).fetch_all(&mut *connection).await?;
            let package_ids_json = serde_json::to_string(&packages.iter().map(|(id, _)| id).collect::<Vec<_>>())
                .map_err(|error| sqlx::Error::Protocol(format!("failed to encode OSV package IDs: {error}")))?;
            let osv_ids_json = serde_json::to_string(&packages.iter().map(|(_, id)| id).collect::<BTreeSet<_>>())
                .map_err(|error| sqlx::Error::Protocol(format!("failed to encode OSV IDs: {error}")))?;
            let events: Vec<(i64, i64, String, String, String)> = sqlx::query_as("SELECT range.affected_package_id, range.id, range.range_type, event.event_type, event.value FROM osv_ranges AS range JOIN osv_range_events AS event ON event.range_id=range.id WHERE range.affected_package_id IN (SELECT value FROM json_each(?)) ORDER BY range.affected_package_id, range.id, event.id")
                .bind(&package_ids_json).fetch_all(&mut *connection).await?;
            let mut ranges_by_package = BTreeMap::<i64, Vec<OsvRange>>::new();
            let mut current_range = None;
            for (package_id, range_id, range_type, event_type, value) in events {
                let ranges = ranges_by_package.entry(package_id).or_default();
                if current_range != Some((package_id, range_id)) {
                    current_range = Some((package_id, range_id));
                    ranges.push(OsvRange { range_type, events: Vec::new() });
                }
                ranges.last_mut().expect("range was inserted").events.push((event_type, value));
            }
            let explicit_versions: BTreeSet<i64> = sqlx::query_scalar("SELECT affected_package_id FROM osv_versions WHERE version=? AND affected_package_id IN (SELECT value FROM json_each(?))")
                .bind(&version).bind(&package_ids_json).fetch_all(&mut *connection).await?.into_iter().collect();
            let alias_rows: Vec<(String, String)> = sqlx::query_as("SELECT osv_id, alias_id FROM osv_aliases WHERE alias_id LIKE 'CVE-%' AND osv_id IN (SELECT value FROM json_each(?)) ORDER BY osv_id, alias_id")
                .bind(&osv_ids_json).fetch_all(&mut *connection).await?;
            let mut aliases_by_osv = BTreeMap::<String, Vec<String>>::new();
            for (osv_id, alias_id) in alias_rows {
                aliases_by_osv.entry(osv_id).or_default().push(alias_id);
            }
            let mut findings = Vec::with_capacity(packages.len());
            for (package_id, osv_id) in packages {
                let ranges = ranges_by_package.remove(&package_id).unwrap_or_default();
                let matched = if explicit_versions.contains(&package_id) {
                    super::package_eval::VersionMatch {
                        status: "affected".to_owned(),
                        confidence: "high".to_owned(),
                    }
                } else {
                    evaluate_version(&ecosystem, &version, &ranges)
                };
                let cve_ids = aliases_by_osv.get(&osv_id).cloned().unwrap_or_default();
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

    /// Replaces CWE metadata and `ChildOf` relationships.
    ///
    /// Catalog data replaces placeholder rows created during CVE import.
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
        self.search_osv_paginated(query, limit, 0).await
    }

    pub async fn search_osv_paginated(
        &self,
        query: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SqlxOsvSummary>, sqlx::Error> {
        let Some(query) = fts_query(query) else {
            return Ok(Vec::new());
        };
        self.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query_as("SELECT advisory.osv_id, COALESCE(advisory.modified_at, '') AS modified_at, advisory.summary, advisory.details, advisory.withdrawn_at FROM osv_text_fts JOIN osv_advisories AS advisory ON advisory.osv_id=osv_text_fts.osv_id WHERE osv_text_fts MATCH ? ORDER BY bm25(osv_text_fts), advisory.modified_at DESC, advisory.osv_id LIMIT ? OFFSET ?")
                .bind(query).bind(limit.max(1)).bind(offset.max(0)).fetch_all(connection).await
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
                    sqlx::query_as("SELECT osv_id, COALESCE(modified_at, '') AS modified_at, summary, details, withdrawn_at FROM osv_advisories WHERE osv_id=? COLLATE NOCASE")
                        .bind(osv_id)
                        .fetch_optional(connection)
                        .await
                })
            })
            .await
    }

    /// Returns provider publication/modification timestamps for source-specific filtering.
    pub async fn osv_advisory_dates(
        &self,
        osv_id: &str,
    ) -> Result<Option<(Option<String>, Option<String>)>, sqlx::Error> {
        let osv_id = osv_id.to_owned();
        self.writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query_as(
                        "SELECT published_at, modified_at FROM osv_advisories WHERE osv_id=?",
                    )
                    .bind(osv_id)
                    .fetch_optional(connection)
                    .await
                })
            })
            .await
    }

    /// Returns OSV publication/modification timestamps in caller order using bounded statements.
    pub async fn osv_advisory_dates_batch(
        &self,
        osv_ids: &[String],
    ) -> Result<Vec<Option<(Option<String>, Option<String>)>>, sqlx::Error> {
        if osv_ids.is_empty() {
            return Ok(Vec::new());
        }
        let requested = osv_ids.to_vec();
        self.writer.with_connection(|connection| Box::pin(async move {
            let mut dates = BTreeMap::new();
            for batch in requested.chunks(OSV_DATE_BATCH_SIZE) {
                let requested_json = serde_json::to_string(batch).map_err(|error| {
                    sqlx::Error::Protocol(format!("failed to encode OSV IDs: {error}"))
                })?;
                    let rows: Vec<(String, Option<String>, Option<String>)> = sqlx::query_as(
                        "SELECT advisory.osv_id, advisory.published_at, advisory.modified_at FROM osv_advisories advisory WHERE advisory.osv_id IN (SELECT value FROM json_each(?))",
                    )
                    .bind(requested_json)
                    .fetch_all(&mut *connection)
                    .await?;
                dates.extend(rows.into_iter().map(|(id, published, modified)| {
                    (id, (published, modified))
                }));
            }
            Ok(requested
                .into_iter()
                .map(|id| dates.get(&id).cloned())
                .collect())
        })).await
    }

    /// Starts an OSV synchronization and returns its last completed cursor.
    ///
    /// The cursor advances only after imports, indexes, and checks succeed.
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
        Ok(self
            .import_osv_record_batch(records, true, false)
            .await?
            .examined)
    }

    /// Imports OSV batches while deferring the global FTS rebuild to the ZIP-level caller.
    pub async fn import_osv_records_deferred_search(
        &self,
        records: Vec<OsvRawRecord>,
    ) -> Result<usize, sqlx::Error> {
        Ok(self
            .import_osv_records_deferred_search_with_stats(records)
            .await?
            .examined)
    }

    /// Imports an OSV batch and reports records skipped by the batch hash comparison.
    pub async fn import_osv_records_deferred_search_with_stats(
        &self,
        records: Vec<OsvRawRecord>,
    ) -> Result<OsvImportStats, sqlx::Error> {
        self.import_osv_record_batch(records, false, false).await
    }

    /// Imports an incremental OSV batch and updates FTS only for inserted or changed IDs.
    /// Unchanged hashes produce no normalized or search writes.
    pub async fn import_osv_records_incremental_with_stats(
        &self,
        records: Vec<OsvRawRecord>,
    ) -> Result<OsvImportStats, sqlx::Error> {
        self.import_osv_record_batch(records, true, false).await
    }

    /// Inserts an OSV batch into an empty replacement database. Unlike the update path, this
    /// avoids conflict handling and child-row deletion while bulk-load indexes are absent.
    pub async fn import_osv_records_bulk_init(
        &self,
        records: Vec<OsvRawRecord>,
    ) -> Result<usize, sqlx::Error> {
        Ok(self
            .import_osv_record_batch(records, false, true)
            .await?
            .examined)
    }

    /// Imports one OSV advisory atomically.
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
                    delete_osv_identifier_edges(&mut transaction, &advisory.id).await?;
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
    ) -> Result<OsvImportStats, sqlx::Error> {
        let count = records.len();
        if records.is_empty() {
            return Ok(OsvImportStats::default());
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
                    let mut existing_hashes = BTreeMap::new();
                    if !bulk_init {
                        // Stay below conservative SQLite variable limits while avoiding an
                        // additional lookup for every advisory.
                        for chunk in parsed_records.chunks(500) {
                            let mut query = QueryBuilder::<Sqlite>::new(
                                "SELECT osv_id, content_hash FROM osv_raw_records WHERE osv_id IN (",
                            );
                            let mut separated = query.separated(", ");
                            for record in chunk {
                                separated.push_bind(&record.advisory.id);
                            }
                            separated.push_unseparated(")");
                            let rows: Vec<(String, String)> = query
                                .build_query_as()
                                .fetch_all(&mut *transaction)
                                .await?;
                            existing_hashes.extend(rows);
                        }
                    }
                    let mut stats = OsvImportStats {
                        examined: count,
                        ..OsvImportStats::default()
                    };
                    for record in parsed_records {
                        match existing_hashes.get(&record.advisory.id) {
                            Some(hash) if hash == &record.content_hash => {
                                stats.unchanged += 1;
                                continue;
                            }
                            Some(_) => stats.updated += 1,
                            None => stats.inserted += 1,
                        }
                        Self::write_osv_batch_record(
                            &mut transaction,
                            record,
                            &fetched_at,
                            update_search,
                            bulk_init,
                        )
                        .await?;
                    }
                    transaction.commit().await?;
                    Ok(stats)
                })
            })
            .await
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
        let raw_record_result = sqlx::query(raw_record_sql)
            .bind(&advisory.id)
            .bind(&record.source_path)
            .bind(&record.published_at)
            .bind(&record.modified_at)
            .bind(fetched_at)
            .bind(&record.content_hash)
            .bind(&record.raw_json)
            .execute(&mut **transaction)
            .await?;
        let raw_record_id: i64 = if bulk_init {
            raw_record_result.last_insert_rowid()
        } else {
            sqlx::query_scalar("SELECT id FROM osv_raw_records WHERE osv_id=?")
                .bind(&advisory.id)
                .fetch_one(&mut **transaction)
                .await?
        };
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
            delete_osv_identifier_edges(transaction, &advisory.id).await?;
            for sql in [
                "DELETE FROM osv_aliases WHERE osv_id=?",
                "DELETE FROM osv_references WHERE osv_id=?",
                "DELETE FROM osv_range_events WHERE range_id IN (SELECT id FROM osv_ranges WHERE affected_package_id IN (SELECT id FROM osv_affected_packages WHERE osv_id=?))",
                "DELETE FROM osv_ranges WHERE affected_package_id IN (SELECT id FROM osv_affected_packages WHERE osv_id=?)",
                "DELETE FROM osv_versions WHERE affected_package_id IN (SELECT id FROM osv_affected_packages WHERE osv_id=?)",
                "DELETE FROM osv_affected_packages WHERE osv_id=?",
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
        for references in advisory.references.chunks(250) {
            let mut query = QueryBuilder::<Sqlite>::new(
                "INSERT OR IGNORE INTO osv_references(osv_id, reference_type, url) ",
            );
            query.push_values(references, |mut row, reference| {
                row.push_bind(&advisory.id)
                    .push_bind(&reference.reference_type)
                    .push_bind(&reference.url);
            });
            query.build().execute(&mut **transaction).await?;
        }
        for (affected_order, affected) in advisory.affected.iter().enumerate() {
            let package = affected.package.as_ref();
            let package_result = sqlx::query("INSERT INTO osv_affected_packages (osv_id, affected_order, ecosystem, package_name, purl) VALUES (?, ?, ?, ?, ?)")
                .bind(&advisory.id)
                .bind(i64::try_from(affected_order).unwrap_or(i64::MAX))
                .bind(package.and_then(|value| value.ecosystem.as_deref()))
                .bind(package.and_then(|value| value.name.as_deref()))
                .bind(package.and_then(|value| value.purl.as_deref()))
                .execute(&mut **transaction)
                .await?;
            let package_id = package_result.last_insert_rowid();
            for (range_order, range) in affected.ranges.iter().enumerate() {
                let range_result = sqlx::query("INSERT INTO osv_ranges (affected_package_id, affected_order, range_order, range_type) VALUES (?, ?, ?, ?)")
                    .bind(package_id)
                    .bind(i64::try_from(affected_order).unwrap_or(i64::MAX))
                    .bind(i64::try_from(range_order).unwrap_or(i64::MAX))
                    .bind(range.range_type.as_deref().unwrap_or("ECOSYSTEM"))
                    .execute(&mut **transaction)
                    .await?;
                let range_id = range_result.last_insert_rowid();
                let mut event_rows = Vec::new();
                let mut event_order = 0_i64;
                for event in &range.events {
                    for (kind, value) in event.event_pairs() {
                        event_rows.push((kind, value, event_order));
                        event_order += 1;
                    }
                }
                for events in event_rows.chunks(200) {
                    let mut query = QueryBuilder::<Sqlite>::new(
                        "INSERT INTO osv_range_events (range_id, event_type, value, event_order) ",
                    );
                    query.push_values(events, |mut row, (kind, value, order)| {
                        row.push_bind(range_id)
                            .push_bind(*kind)
                            .push_bind(*value)
                            .push_bind(*order);
                    });
                    query.build().execute(&mut **transaction).await?;
                }
            }
            for versions in affected.versions.chunks(400) {
                let mut query = QueryBuilder::<Sqlite>::new(
                    "INSERT OR IGNORE INTO osv_versions (affected_package_id, version) ",
                );
                query.push_values(versions, |mut row, version| {
                    row.push_bind(package_id).push_bind(version);
                });
                query.build().execute(&mut **transaction).await?;
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
        self.import_cve_raw_jsons_with_search(records, true, false)
            .await
    }

    /// Imports a batch while deferring global search-index maintenance to the caller.
    pub async fn import_cve_raw_jsons_deferred_search(
        &self,
        records: Vec<String>,
    ) -> Result<usize, sqlx::Error> {
        self.import_cve_raw_jsons_with_search(records, false, false)
            .await
    }

    /// As above, but returns the parent identifiers whose search rows must be refreshed.
    pub async fn import_cve_raw_jsons_deferred_search_with_ids(
        &self,
        records: Vec<String>,
    ) -> Result<(usize, Vec<String>), sqlx::Error> {
        let cve_ids = records
            .iter()
            .map(|raw_json| {
                let value: Value = serde_json::from_str(raw_json)
                    .map_err(|error| sqlx::Error::Protocol(format!("invalid CVE JSON: {error}")))?;
                value
                    .pointer("/cveMetadata/cveId")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
                    .ok_or_else(|| {
                        sqlx::Error::Protocol("CVE record is missing cveMetadata.cveId".to_owned())
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let imported = self
            .import_cve_raw_jsons_with_search(records, false, false)
            .await?;
        Ok((imported, cve_ids))
    }

    /// Imports a full-replacement batch into an empty database without conflict checks or stale
    /// child deletion. Callers must prepare the CVE bulk-load mode before using this path.
    pub async fn import_cve_raw_jsons_bulk_init(
        &self,
        records: Vec<String>,
    ) -> Result<usize, sqlx::Error> {
        self.import_cve_raw_jsons_with_search(records, false, true)
            .await
    }

    async fn import_cve_raw_jsons_with_search(
        &self,
        records: Vec<String>,
        update_search: bool,
        bulk_init: bool,
    ) -> Result<usize, sqlx::Error> {
        let count = records.len();
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
                    let mut records = records.into_iter();
                    loop {
                        let batch = records
                            .by_ref()
                            .take(CVE_NORMALIZE_BATCH_SIZE)
                            .collect::<Vec<_>>();
                        if batch.is_empty() {
                            break;
                        }
                        // Bound materialized JSON DOMs independently of the caller's ZIP chunk.
                        // This mirrors the old 2k database batches while retaining one outer
                        // transaction, so larger chunks improve I/O without multiplying memory.
                        let records = batch
                            .into_par_iter()
                            .map(|raw_json| {
                                let mut bytes = raw_json.as_bytes().to_vec();
                                let value = simd_json::from_slice(&mut bytes)
                                    .map_err(|error| format!("invalid CVE JSON: {error}"))?;
                                let parent = Self::cve_parent_input(raw_json, &value)
                                    .map_err(|error| error.to_string())?;
                                Ok((parent, value))
                            })
                            .collect::<Result<Vec<_>, String>>()
                            .map_err(sqlx::Error::Protocol)?;
                        Self::write_cve_identifiers(&mut transaction, &records, bulk_init).await?;
                        let cve_ids =
                            Self::write_cve_parents(&mut transaction, &records, bulk_init).await?;
                        if !bulk_init {
                            Self::delete_existing_cve_children(&mut transaction, &records).await?;
                        }
                        Self::insert_cve_children(&mut transaction, &records, &cve_ids).await?;
                    }
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
    async fn write_cve_identifiers(
        transaction: &mut sqlx::SqliteConnection,
        records: &[(CveParentInput, Value)],
        insert_only: bool,
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
            if !insert_only {
                builder.push(" ON CONFLICT(identifier) DO UPDATE SET identifier_type='cve', last_seen_at=excluded.last_seen_at");
            }
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

    async fn write_cve_parents(
        transaction: &mut sqlx::SqliteConnection,
        records: &[(CveParentInput, Value)],
        insert_only: bool,
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
            if !insert_only {
                builder.push(" ON CONFLICT(cve_id) DO UPDATE SET state=excluded.state, published_at=excluded.published_at, updated_at=excluded.updated_at, serial=excluded.serial, title=excluded.title, description_en=excluded.description_en, reference_text=excluded.reference_text, raw_json=excluded.raw_json");
            }
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
        Ok(self.import_kev_json_with_status(raw_json, true).await?.0)
    }

    /// Imports KEV data and reports whether the snapshot changed.
    pub async fn import_kev_json_with_status(
        &self,
        raw_json: String,
        force: bool,
    ) -> Result<(usize, bool), sqlx::Error> {
        let catalog = KevCatalog::parse_json(raw_json.as_bytes())
            .map_err(|error| sqlx::Error::Protocol(format!("invalid KEV JSON: {error}")))?;
        catalog
            .validate_schema_shape()
            .map_err(|error| sqlx::Error::Protocol(format!("invalid KEV catalog: {error}")))?;
        let count = catalog.vulnerabilities.len();
        let hash = Md5::digest(raw_json.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        self.writer.with_connection(|connection| Box::pin(async move {
            let unchanged: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kev_raw_records WHERE content_hash=? AND raw_json=?)")
                .bind(&hash)
                .bind(&raw_json)
                .fetch_one(&mut *connection)
                .await?;
            if unchanged && !force {
                return Ok(false);
            }
            let mut transaction = connection.begin().await?;
            sqlx::query("INSERT OR IGNORE INTO db_sources (source, display_name, source_type, default_filename, raw_format) VALUES ('KEV', 'CISA KEV', 'enrichment', 'known_exploited_vulnerabilities.json', 'json')")
                .execute(&mut *transaction).await?;
            let now = chrono::Utc::now().to_rfc3339();
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
            transaction.commit().await?;
            Ok(true)
        })).await.map(|changed| (count, changed))
    }

    /// Atomically replaces the current EPSS snapshot.
    pub async fn import_epss_csv(&self, csv: String) -> Result<usize, sqlx::Error> {
        Ok(self.import_epss_csv_with_status(csv, true).await?.0)
    }

    /// Imports EPSS data and reports whether the snapshot changed.
    pub async fn import_epss_csv_with_status(
        &self,
        csv: String,
        force: bool,
    ) -> Result<(usize, bool), sqlx::Error> {
        let parsed = EpssCurrentCsv::parse(&csv)
            .map_err(|error| sqlx::Error::Protocol(format!("invalid EPSS CSV: {error}")))?;
        let count = parsed.rows.len();
        let hash = Md5::digest(csv.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        self.writer.with_connection(|connection| Box::pin(async move {
            let unchanged: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM epss_raw_records WHERE content_hash=? AND raw_csv=?)")
                .bind(&hash)
                .bind(&csv)
                .fetch_one(&mut *connection)
                .await?;
            if unchanged && !force {
                return Ok(false);
            }
            let mut transaction = connection.begin().await?;
            sqlx::query("CREATE TEMP TABLE IF NOT EXISTS epss_import_stage (cve_id TEXT PRIMARY KEY, epss REAL NOT NULL, percentile REAL NOT NULL, input_order INTEGER NOT NULL) WITHOUT ROWID")
                .execute(&mut *transaction).await?;
            sqlx::query("DELETE FROM epss_import_stage")
                .execute(&mut *transaction).await?;
            // Four bindings per row keep each statement below conservative SQLite limits.
            for (batch_index, rows) in parsed.rows.chunks(200).enumerate() {
                let mut query = QueryBuilder::<Sqlite>::new(
                    "INSERT INTO epss_import_stage (cve_id, epss, percentile, input_order) ",
                );
                query.push_values(rows.iter().enumerate(), |mut row, (offset, value)| {
                    row.push_bind(&value.cve_id)
                        .push_bind(value.epss)
                        .push_bind(value.percentile)
                        .push_bind(i64::try_from(batch_index * 200 + offset).unwrap_or(i64::MAX));
                });
                query.push(" ON CONFLICT(cve_id) DO UPDATE SET epss=excluded.epss, percentile=excluded.percentile, input_order=excluded.input_order WHERE excluded.input_order >= epss_import_stage.input_order");
                query.build().execute(&mut *transaction).await?;
            }
            sqlx::query("INSERT OR IGNORE INTO db_sources (source, display_name, source_type, default_filename, raw_format) VALUES ('EPSS', 'FIRST EPSS', 'enrichment', 'epss_scores-current.csv', 'csv')")
                .execute(&mut *transaction).await?;
            let now = chrono::Utc::now().to_rfc3339();
            sqlx::query("INSERT INTO epss_raw_records (score_date, fetched_at, content_hash, raw_csv) VALUES (?, ?, ?, ?) ON CONFLICT(score_date) DO UPDATE SET fetched_at=excluded.fetched_at, content_hash=excluded.content_hash, raw_csv=excluded.raw_csv")
                .bind(&parsed.score_date).bind(&now).bind(hash).bind(&csv).execute(&mut *transaction).await?;
            let raw_record_id: i64 = sqlx::query_scalar("SELECT id FROM epss_raw_records WHERE score_date=?")
                .bind(&parsed.score_date)
                .fetch_one(&mut *transaction).await?;
            // Replace the snapshot atomically so removed CVEs do not leave stale scores.
            sqlx::query("DELETE FROM epss_current").execute(&mut *transaction).await?;
            sqlx::query("INSERT INTO epss_current (cve_id, raw_record_id, epss, percentile, score_date, model_version, fetched_at) SELECT c.cve_id, ?, s.epss, s.percentile, ?, ?, ? FROM epss_import_stage s JOIN cve c ON c.cve_id=s.cve_id")
                .bind(raw_record_id)
                .bind(&parsed.score_date)
                .bind(&parsed.model_version)
                .bind(&now)
                .execute(&mut *transaction).await?;
            transaction.commit().await?;
            Ok(true)
        })).await.map(|changed| (count, changed))
    }
}

async fn delete_osv_identifier_edges(
    transaction: &mut sqlx::Transaction<'_, Sqlite>,
    osv_id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"DELETE FROM vulnerability_identifier_edges
           WHERE source='OSV' AND (
               from_identifier=? OR (
                   to_identifier=? AND relation_type IN ('alias', 'related')
                   AND from_identifier IN (
                       SELECT to_identifier FROM vulnerability_identifier_edges
                       WHERE from_identifier=? AND source='OSV'
                         AND relation_type IN ('alias', 'related')
                   )
               )
           )"#,
    )
    .bind(osv_id)
    .bind(osv_id)
    .bind(osv_id)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

pub(crate) fn cve_affected_descriptions(raw_json: &str) -> Vec<Option<String>> {
    serde_json::from_str::<Value>(raw_json)
        .ok()
        .and_then(|value| {
            value
                .pointer("/containers/cna/affected")
                .and_then(Value::as_array)
                .cloned()
        })
        .unwrap_or_default()
        .into_iter()
        .map(|affected| {
            affected
                .get("description")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        })
        .collect()
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
/// Rebuilding removes edges left by changed OSV relationships.
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
        assert!(database.check_search_integrity_quick().await.is_err());
        database.initialize().await.unwrap();
        database.check_search_integrity_quick().await.unwrap();
        database.rebuild_search().await.unwrap();
        database.check().await.unwrap();
        database.check_full_sqlite().await.unwrap();
        database.check_full_foreign_keys().await.unwrap();
        database.check_full_cve_search().await.unwrap();
        database.check_full_osv_search().await.unwrap();
        assert_eq!(SqlxDatabase::schema_version(), 10);
    }

    #[tokio::test]
    async fn repeated_initialization_is_idempotent() {
        let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        database.initialize().await.unwrap();
        database.initialize().await.unwrap();
        database.check().await.unwrap();
    }

    #[tokio::test]
    async fn initialization_rejects_an_incompatible_existing_schema_without_stamping_it() {
        let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        database
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::raw_sql(
                        "CREATE TABLE schema_meta(version INTEGER NOT NULL); INSERT INTO schema_meta VALUES(6); CREATE TABLE cve(id INTEGER PRIMARY KEY);",
                    )
                    .execute(connection)
                    .await?;
                    Ok(())
                })
            })
            .await
            .unwrap();

        assert!(database.initialize().await.is_err());
        let version: i64 = database
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query_scalar("SELECT version FROM schema_meta")
                        .fetch_one(connection)
                        .await
                })
            })
            .await
            .unwrap();
        assert_eq!(version, 6);
    }

    #[tokio::test]
    async fn quick_check_detects_disabled_foreign_keys() {
        let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        database.initialize().await.unwrap();
        database
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query("PRAGMA foreign_keys=OFF")
                        .execute(connection)
                        .await?;
                    Ok(())
                })
            })
            .await
            .unwrap();
        assert!(
            database
                .check()
                .await
                .unwrap_err()
                .to_string()
                .contains("disabled")
        );
    }

    #[tokio::test]
    async fn quick_check_detects_and_rebuild_repairs_missing_fts_rows() {
        let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        database.initialize().await.unwrap();
        database
            .import_cve_raw_jsons_bulk_init(vec![
                r#"{"cveMetadata":{"cveId":"CVE-2099-9901","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-01T00:00:00Z"},"containers":{"cna":{"title":"integrity fixture"}}}"#.to_owned(),
            ])
            .await
            .unwrap();
        database.rebuild_search().await.unwrap();
        database
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query("DELETE FROM cve_summary_fts WHERE cve_id='CVE-2099-9901'")
                        .execute(connection)
                        .await?;
                    Ok(())
                })
            })
            .await
            .unwrap();
        assert!(database.check().await.is_err());
        database.rebuild_search().await.unwrap();
        database.check().await.unwrap();
    }

    #[tokio::test]
    async fn quick_check_detects_extra_osv_fts_rows() {
        let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        database.initialize().await.unwrap();
        database
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query(
                        "INSERT INTO osv_text_fts(osv_id, summary) VALUES('OSV-EXTRA', 'extra')",
                    )
                    .execute(connection)
                    .await?;
                    Ok(())
                })
            })
            .await
            .unwrap();
        assert!(database.check().await.is_err());
    }

    #[tokio::test]
    async fn schema_check_detects_missing_required_index() {
        let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        database.initialize().await.unwrap();
        database
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query("DROP INDEX idx_cve_updated_at_cve_id")
                        .execute(connection)
                        .await?;
                    Ok(())
                })
            })
            .await
            .unwrap();
        assert!(database.check_search_integrity_quick().await.is_err());
        assert!(database.initialize().await.is_err());
    }

    #[tokio::test]
    async fn current_version_does_not_hide_an_incompatible_table_shape() {
        let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        database.initialize().await.unwrap();
        database
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query("ALTER TABLE cve DROP COLUMN serial")
                        .execute(connection)
                        .await?;
                    Ok(())
                })
            })
            .await
            .unwrap();
        let error = database
            .check_search_integrity_quick()
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("cve.serial"));
        assert!(database.initialize().await.is_err());
    }

    #[tokio::test]
    async fn schema_check_rejects_wrong_index_columns() {
        let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        database.initialize().await.unwrap();
        database
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query("DROP INDEX idx_osv_ranges_package")
                        .execute(&mut *connection)
                        .await?;
                    sqlx::query("CREATE INDEX idx_osv_ranges_package ON osv_ranges(range_type)")
                        .execute(connection)
                        .await?;
                    Ok(())
                })
            })
            .await
            .unwrap();
        assert!(
            database
                .check_required_schema()
                .await
                .unwrap_err()
                .to_string()
                .contains("wrong columns")
        );
    }

    #[tokio::test]
    async fn schema_check_rejects_missing_foreign_key() {
        let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        database.initialize().await.unwrap();
        database.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query("DROP TABLE osv_aliases").execute(&mut *connection).await?;
            sqlx::query("CREATE TABLE osv_aliases (osv_id TEXT NOT NULL, alias_id TEXT NOT NULL, PRIMARY KEY(osv_id, alias_id))").execute(&mut *connection).await?;
            sqlx::query("CREATE INDEX idx_osv_aliases_alias ON osv_aliases(alias_id)").execute(connection).await?;
            Ok(())
        })).await.unwrap();
        assert!(
            database
                .check_required_schema()
                .await
                .unwrap_err()
                .to_string()
                .contains("foreign key")
        );
    }

    #[tokio::test]
    async fn schema_check_rejects_normal_table_in_place_of_fts() {
        let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        database.initialize().await.unwrap();
        database.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query("DROP TABLE osv_text_fts").execute(&mut *connection).await?;
            sqlx::query("CREATE TABLE osv_text_fts (osv_id TEXT, summary TEXT, details TEXT, aliases TEXT, packages TEXT)").execute(connection).await?;
            Ok(())
        })).await.unwrap();
        assert!(
            database
                .check_required_schema()
                .await
                .unwrap_err()
                .to_string()
                .contains("FTS5")
        );
    }

    #[tokio::test]
    async fn schema_check_rejects_missing_unique_constraint() {
        let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        database.initialize().await.unwrap();
        database.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query("DROP TABLE osv_versions").execute(&mut *connection).await?;
            sqlx::query("CREATE TABLE osv_versions (affected_package_id INTEGER NOT NULL REFERENCES osv_affected_packages(id) ON DELETE CASCADE, version TEXT NOT NULL)").execute(connection).await?;
            Ok(())
        })).await.unwrap();
        assert!(
            database
                .check_required_schema()
                .await
                .unwrap_err()
                .to_string()
                .contains("UNIQUE")
        );
    }

    #[tokio::test]
    async fn bulk_cve_load_defers_search_and_restores_indexes_and_pragmas() {
        let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        database.initialize().await.unwrap();
        database.prepare_cve_bulk_load().await.unwrap();
        database
            .import_cve_raw_jsons_bulk_init(vec![
                r#"{"cveMetadata":{"cveId":"CVE-2099-9001","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-01T00:00:00Z"},"containers":{"cna":{"title":"Deferred bulk search fixture"}}}"#.to_owned(),
            ])
            .await
            .unwrap();
        assert!(
            database
                .import_cve_raw_jsons_bulk_init(vec![
                    r#"{"cveMetadata":{"cveId":"CVE-2099-9001","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-01T00:00:00Z"},"containers":{"cna":{"title":"duplicate"}}}"#.to_owned(),
                ])
                .await
                .is_err()
        );

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
                    let index_exists = sqlx::query_scalar("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_cve_updated_at_cve_id'")
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
            matches[0].details.as_deref(),
            Some("Withdrawn records remain in the alias graph.")
        );
        let found = database
            .find_osv_summary("GHSA-TEST-0001")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.osv_id, "GHSA-TEST-0001");
        assert_eq!(found.details, matches[0].details);
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
                r#"{"cveMetadata":{"cveId":"CVE-2099-7101","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-01T00:00:00Z"},"containers":{"cna":{"title":"First overview fixture","affected":[{"vendor":"Acme","product":"widget","description":"Widget deployment is affected."}],"metrics":[{"cvssV3_1":{"version":"3.1","baseScore":9.8,"baseSeverity":"CRITICAL"}}],"problemTypes":[{"descriptions":[{"cweId":"CWE-79","description":"XSS"}]}]}}}"#.to_owned(),
                r#"{"cveMetadata":{"cveId":"CVE-2099-7102","state":"PUBLISHED","datePublished":"2099-01-02T00:00:00Z","dateUpdated":"2099-01-02T00:00:00Z"},"containers":{"cna":{"title":"Second overview fixture","affected":[{"vendor":"Example","product":"service","description":"Service deployment is affected."}],"metrics":[{"cvssV4_0":{"version":"4.0","baseScore":7.2,"baseSeverity":"HIGH"}}],"problemTypes":[{"descriptions":[{"cweId":"CWE-89","description":"SQL injection"}]}]}}}"#.to_owned(),
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
        assert!(rows.iter().all(|row| {
            row.detail.affected[0]
                .description
                .as_deref()
                .is_some_and(|description| description.ends_with("deployment is affected."))
        }));
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
            .join("../collector/src/cwec_v4.20.xml");
        let catalog = qanvuli_models::cwe::read_cwe_catalog_xml(path).unwrap();
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
    async fn osv_child_batches_cross_conservative_sqlite_bind_limits() {
        let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        database.initialize().await.unwrap();
        let versions = (0..1_001)
            .map(|index| format!("1.0.{index}"))
            .collect::<Vec<_>>();
        let references = (0..301)
            .map(|index| {
                serde_json::json!({
                    "type": "WEB",
                    "url": format!("https://example.invalid/{index}")
                })
            })
            .collect::<Vec<_>>();
        let events = (0..301)
            .map(|index| serde_json::json!({"introduced": format!("1.0.{index}")}))
            .collect::<Vec<_>>();
        let raw_json = serde_json::json!({
            "schema_version": "1.8.0",
            "id": "OSV-2099-large-children",
            "modified": "2099-01-01T00:00:00Z",
            "references": references,
            "affected": [{
                "package": {"ecosystem": "Go", "name": "example.invalid/large"},
                "ranges": [{"type": "SEMVER", "events": events}],
                "versions": versions
            }]
        })
        .to_string();
        database.prepare_osv_bulk_load().await.unwrap();
        database
            .import_osv_records_bulk_init(vec![OsvRawRecord {
                source_path: None,
                raw_json,
            }])
            .await
            .unwrap();
        database.finish_osv_bulk_load().await.unwrap();
        let counts: (i64, i64, i64) = database.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query_as("SELECT (SELECT COUNT(*) FROM osv_references), (SELECT COUNT(*) FROM osv_range_events), (SELECT COUNT(*) FROM osv_versions)")
                .fetch_one(connection).await
        })).await.unwrap();
        assert_eq!(counts, (301, 301, 1_001));
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
        database.import_osv_records_deferred_search(vec![OsvRawRecord {
            source_path: None,
            raw_json: r#"{"schema_version":"1.8.0","id":"GHSA-2099-edge","modified":"2099-01-01T00:00:00Z","aliases":["CVE-2099-old"]}"#.to_owned(),
        }]).await.unwrap();
        database.import_osv_records_deferred_search(vec![OsvRawRecord {
            source_path: None,
            raw_json: r#"{"schema_version":"1.8.0","id":"GHSA-2099-edge","modified":"2099-01-02T00:00:00Z","aliases":["CVE-2099-new"]}"#.to_owned(),
        }]).await.unwrap();
        let edges: Vec<String> = database.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query_scalar("SELECT to_identifier FROM vulnerability_identifier_edges WHERE source='OSV' AND from_identifier='GHSA-2099-edge' ORDER BY to_identifier")
                .fetch_all(connection).await
        })).await.unwrap();
        assert_eq!(edges, vec!["CVE-2099-new".to_owned()]);
        let stale_reverse_edges: i64 = database.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query_scalar("SELECT COUNT(*) FROM vulnerability_identifier_edges WHERE source='OSV' AND from_identifier='CVE-2099-old' AND to_identifier='GHSA-2099-edge'")
                .fetch_one(connection).await
        })).await.unwrap();
        assert_eq!(stale_reverse_edges, 0);
    }

    #[tokio::test]
    async fn unchanged_osv_batch_does_not_rewrite_normalized_rows() {
        let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        database.initialize().await.unwrap();
        let record = OsvRawRecord {
            source_path: Some("Go/GO-2099-unchanged.json".to_owned()),
            raw_json: r#"{"schema_version":"1.8.0","id":"GO-2099-unchanged","modified":"2099-01-01T00:00:00Z","aliases":["CVE-2099-1"],"affected":[{"package":{"ecosystem":"Go","name":"example.invalid/package"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}],"versions":["1.0.0"]}]}"#.to_owned(),
        };
        database
            .import_osv_records_deferred_search_with_stats(vec![record.clone()])
            .await
            .unwrap();
        let changes_before: i64 = database
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query_scalar("SELECT total_changes()")
                        .fetch_one(connection)
                        .await
                })
            })
            .await
            .unwrap();
        let stats = database
            .import_osv_records_deferred_search_with_stats(vec![record])
            .await
            .unwrap();
        let changes_after: i64 = database
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query_scalar("SELECT total_changes()")
                        .fetch_one(connection)
                        .await
                })
            })
            .await
            .unwrap();
        assert_eq!(
            stats,
            OsvImportStats {
                examined: 1,
                inserted: 0,
                updated: 0,
                unchanged: 1
            }
        );
        assert_eq!(changes_after, changes_before);
    }

    #[tokio::test]
    async fn incremental_osv_search_updates_only_changed_projection_and_matches_rebuild() {
        let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        database.initialize().await.unwrap();
        let unchanged = OsvRawRecord {
            source_path: None,
            raw_json: r#"{"id":"GO-2099-unchanged","modified":"2099-01-01T00:00:00Z","summary":"untouched"}"#.to_owned(),
        };
        let original = OsvRawRecord {
            source_path: None,
            raw_json: r#"{"id":"GO-2099-changed","modified":"2099-01-01T00:00:00Z","aliases":["CVE-2099-old"],"affected":[{"package":{"ecosystem":"Go","name":"old.example/pkg","purl":"pkg:golang/old.example/pkg"}}]}"#.to_owned(),
        };
        database
            .import_osv_records_incremental_with_stats(vec![unchanged.clone(), original])
            .await
            .unwrap();
        let untouched_before: (i64, String) = database
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query_as(
                        "SELECT rowid, summary FROM osv_text_fts WHERE osv_id='GO-2099-unchanged'",
                    )
                    .fetch_one(connection)
                    .await
                })
            })
            .await
            .unwrap();
        let changed = OsvRawRecord {
            source_path: None,
            raw_json: r#"{"id":"GO-2099-changed","modified":"2099-01-02T00:00:00Z","aliases":["CVE-2099-new"],"affected":[{"package":{"ecosystem":"Go","name":"new.example/pkg","purl":"pkg:golang/new.example/pkg"}}]}"#.to_owned(),
        };
        let stats = database
            .import_osv_records_incremental_with_stats(vec![unchanged, changed])
            .await
            .unwrap();
        assert_eq!(stats.updated, 1);
        assert_eq!(stats.unchanged, 1);

        let untouched_after: (i64, String) = database
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query_as(
                        "SELECT rowid, summary FROM osv_text_fts WHERE osv_id='GO-2099-unchanged'",
                    )
                    .fetch_one(connection)
                    .await
                })
            })
            .await
            .unwrap();
        assert_eq!(untouched_after, untouched_before);
        let incremental_rows: Vec<(String, String, String)> = database
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query_as(
                        "SELECT osv_id, aliases, packages FROM osv_text_fts ORDER BY osv_id",
                    )
                    .fetch_all(connection)
                    .await
                })
            })
            .await
            .unwrap();
        assert!(incremental_rows.iter().any(|(id, aliases, packages)| {
            id == "GO-2099-changed"
                && aliases == "CVE-2099-new"
                && packages.contains("new.example/pkg")
                && packages.contains("pkg:golang/new.example/pkg")
                && !aliases.contains("old")
                && !packages.contains("old.example")
        }));
        // An updated FTS document is deleted and reinserted, so its FTS rowid no longer
        // matches the advisory table's insertion order. The routine health check must not
        // mistake that normal condition for a projection mismatch.
        database.check_search_integrity_quick().await.unwrap();
        database.rebuild_osv_search().await.unwrap();
        let rebuilt_rows: Vec<(String, String, String)> = database
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query_as(
                        "SELECT osv_id, aliases, packages FROM osv_text_fts ORDER BY osv_id",
                    )
                    .fetch_all(connection)
                    .await
                })
            })
            .await
            .unwrap();
        assert_eq!(incremental_rows, rebuilt_rows);
    }

    #[tokio::test]
    async fn incremental_cve_search_refresh_matches_full_rebuild() {
        let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        database.initialize().await.unwrap();
        database
            .import_cve_raw_jsons(vec![
                r#"{"cveMetadata":{"cveId":"CVE-2099-1001","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-01T00:00:00Z"},"containers":{"cna":{"title":"unchanged"}}}"#.to_owned(),
                r#"{"cveMetadata":{"cveId":"CVE-2099-1002","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-01T00:00:00Z"},"containers":{"cna":{"title":"old title"}}}"#.to_owned(),
            ])
            .await
            .unwrap();
        let (_, changed_ids) = database
            .import_cve_raw_jsons_deferred_search_with_ids(vec![
                r#"{"cveMetadata":{"cveId":"CVE-2099-1002","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-02T00:00:00Z"},"containers":{"cna":{"title":"new title"}}}"#.to_owned(),
            ])
            .await
            .unwrap();
        database
            .refresh_cve_search_for_ids(changed_ids)
            .await
            .unwrap();
        database.check_full_cve_search().await.unwrap();
        let aligned_rows: i64 = database
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query_scalar(
                        "SELECT COUNT(*) FROM cve_summary_index projection JOIN cve_summary_fts fts ON fts.rowid=projection.cve_db_id AND fts.cve_id=projection.cve_id",
                    )
                    .fetch_one(connection)
                    .await
                })
            })
            .await
            .unwrap();
        assert_eq!(aligned_rows, 2);
        let incremental_rows: Vec<(String, String)> = database
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query_as("SELECT cve_id, title FROM cve_summary_index ORDER BY cve_id")
                        .fetch_all(connection)
                        .await
                })
            })
            .await
            .unwrap();
        assert!(
            incremental_rows
                .iter()
                .any(|(id, title)| id == "CVE-2099-1002" && title == "new title")
        );
        database.rebuild_cve_search().await.unwrap();
        let rebuilt_rows: Vec<(String, String)> = database
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query_as("SELECT cve_id, title FROM cve_summary_index ORDER BY cve_id")
                        .fetch_all(connection)
                        .await
                })
            })
            .await
            .unwrap();
        assert_eq!(incremental_rows, rebuilt_rows);
    }

    /// Reproducible local micro-benchmark for the incremental OSV update hot path.
    /// Run with: cargo test -p qanvuli-db benchmark_unchanged_osv_batch -- --ignored --nocapture
    #[tokio::test]
    #[ignore = "performance benchmark"]
    async fn benchmark_unchanged_osv_batch() {
        let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        database.initialize().await.unwrap();
        let records = (0..5_000)
            .map(|index| OsvRawRecord {
                source_path: Some(format!("Go/GO-2099-{index}.json")),
                raw_json: format!(
                    r#"{{"schema_version":"1.8.0","id":"GO-2099-{index}","modified":"2099-01-01T00:00:00Z","aliases":["CVE-2099-{index}"],"references":[{{"type":"WEB","url":"https://example.invalid/{index}"}}],"affected":[{{"package":{{"ecosystem":"Go","name":"example.invalid/package/{index}"}},"ranges":[{{"type":"SEMVER","events":[{{"introduced":"0"}},{{"fixed":"2.0.0"}}]}}],"versions":["1.0.0","1.1.0"]}}]}}"#
                ),
            })
            .collect::<Vec<_>>();
        database
            .import_osv_records_deferred_search(records.clone())
            .await
            .unwrap();
        let changes_before: i64 = database
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query_scalar("SELECT total_changes()")
                        .fetch_one(connection)
                        .await
                })
            })
            .await
            .unwrap();
        let started = std::time::Instant::now();
        database
            .import_osv_records_deferred_search(records)
            .await
            .unwrap();
        let elapsed = started.elapsed();
        let changes_after: i64 = database
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query_scalar("SELECT total_changes()")
                        .fetch_one(connection)
                        .await
                })
            })
            .await
            .unwrap();
        eprintln!(
            "unchanged OSV: records=5000 elapsed={elapsed:?} sqlite_changes={}",
            changes_after - changes_before
        );
    }

    /// Reproducible full-init benchmark including deferred index/search construction.
    #[tokio::test]
    #[ignore = "performance benchmark"]
    async fn benchmark_osv_full_init() {
        let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        database.initialize().await.unwrap();
        let records = (0..5_000)
            .map(|index| OsvRawRecord {
                source_path: Some(format!("Go/GO-2099-{index}.json")),
                raw_json: format!(
                    r#"{{"schema_version":"1.8.0","id":"GO-2099-{index}","modified":"2099-01-01T00:00:00Z","aliases":["CVE-2099-{index}"],"references":[{{"type":"WEB","url":"https://example.invalid/{index}"}}],"affected":[{{"package":{{"ecosystem":"Go","name":"example.invalid/package/{index}"}},"ranges":[{{"type":"SEMVER","events":[{{"introduced":"0"}},{{"fixed":"2.0.0"}}]}}],"versions":["1.0.0","1.1.0"]}}]}}"#
                ),
            })
            .collect::<Vec<_>>();
        database.prepare_osv_bulk_load().await.unwrap();
        let write_started = std::time::Instant::now();
        database
            .import_osv_records_bulk_init(records)
            .await
            .unwrap();
        let write_elapsed = write_started.elapsed();
        let index_started = std::time::Instant::now();
        database.finish_osv_bulk_load().await.unwrap();
        let index_elapsed = index_started.elapsed();
        eprintln!(
            "full OSV: records=5000 write={write_elapsed:?} index={index_elapsed:?} total={:?}",
            write_elapsed + index_elapsed
        );
    }

    /// Measures connection, strong schema validation, first lookup, and warmed repeated lookup
    /// against QANVULI_BENCH_DB_URL or the workspace's db.sqlite.
    #[tokio::test]
    #[ignore = "requires a realistic local database"]
    async fn benchmark_schema_and_lookup_latency() {
        let url = std::env::var("QANVULI_BENCH_DB_URL").unwrap_or_else(|_| {
            let current = std::env::current_dir().unwrap();
            let path = current
                .ancestors()
                .map(|directory| directory.join("db.sqlite"))
                .find(|candidate| candidate.exists())
                .expect("set QANVULI_BENCH_DB_URL or place db.sqlite in a parent directory");
            format!(
                "sqlite:///{}?mode=rw",
                path.display().to_string().replace('\\', "/")
            )
        });
        let started = std::time::Instant::now();
        let database = SqlxDatabase::connect(&url).await.unwrap();
        let connection_elapsed = started.elapsed();
        let cve_id: String = database
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query_scalar("SELECT cve_id FROM cve ORDER BY cve_id LIMIT 1")
                        .fetch_one(connection)
                        .await
                })
            })
            .await
            .unwrap();
        let started = std::time::Instant::now();
        database.check_required_schema().await.unwrap();
        let schema_elapsed = started.elapsed();
        let started = std::time::Instant::now();
        assert!(database.find_cve_summary(&cve_id).await.unwrap().is_some());
        let first_lookup_elapsed = started.elapsed();
        let started = std::time::Instant::now();
        for _ in 0..100 {
            assert!(database.find_cve_summary(&cve_id).await.unwrap().is_some());
        }
        let repeated_elapsed = started.elapsed();
        eprintln!(
            "schema/search benchmark: cve_id={cve_id} connection={connection_elapsed:?} schema={schema_elapsed:?} first_lookup={first_lookup_elapsed:?} repeated_100={repeated_elapsed:?} repeated_average={:?}",
            repeated_elapsed / 100
        );
        database.close().await.unwrap();
    }

    /// Reproducible incremental FTS benchmark for zero, one, and one hundred changes.
    #[tokio::test]
    #[ignore = "performance benchmark"]
    async fn benchmark_incremental_osv_change_counts() {
        let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        database.initialize().await.unwrap();
        let records = (0..100)
            .map(|index| OsvRawRecord {
                source_path: None,
                raw_json: format!(
                    r#"{{"id":"GO-2099-{index:04}","modified":"2099-01-01T00:00:00Z","summary":"original {index}","aliases":["CVE-2099-{index:04}"],"affected":[{{"package":{{"ecosystem":"Go","name":"example.invalid/pkg/{index}","purl":"pkg:golang/example.invalid/pkg/{index}@1.0.0"}}}}]}}"#
                ),
            })
            .collect::<Vec<_>>();
        database
            .import_osv_records_incremental_with_stats(records.clone())
            .await
            .unwrap();
        for changed_count in [0_usize, 1, 100] {
            let input = records
                .iter()
                .enumerate()
                .map(|(index, record)| {
                    if index < changed_count {
                        let modified_date = if changed_count == 100 {
                            "2099-01-03"
                        } else {
                            "2099-01-02"
                        };
                        OsvRawRecord {
                            source_path: None,
                            raw_json: record
                                .raw_json
                                .replace("2099-01-01", modified_date)
                                .replace("original", "changed"),
                        }
                    } else {
                        record.clone()
                    }
                })
                .collect();
            let writes_before: i64 = database
                .writer
                .with_connection(|connection| {
                    Box::pin(async move {
                        sqlx::query_scalar("SELECT total_changes()")
                            .fetch_one(connection)
                            .await
                    })
                })
                .await
                .unwrap();
            let started = std::time::Instant::now();
            let stats = database
                .import_osv_records_incremental_with_stats(input)
                .await
                .unwrap();
            let elapsed = started.elapsed();
            let writes_after: i64 = database
                .writer
                .with_connection(|connection| {
                    Box::pin(async move {
                        sqlx::query_scalar("SELECT total_changes()")
                            .fetch_one(connection)
                            .await
                    })
                })
                .await
                .unwrap();
            eprintln!(
                "incremental OSV: requested_changes={changed_count} actual_changes={} elapsed={elapsed:?} sqlite_row_changes={}",
                stats.changed(),
                writes_after - writes_before
            );
        }
        for changed_count in [1_usize, 100] {
            let baseline = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
            baseline.initialize().await.unwrap();
            baseline
                .import_osv_records_deferred_search(records.clone())
                .await
                .unwrap();
            baseline.rebuild_osv_search().await.unwrap();
            let input = records
                .iter()
                .enumerate()
                .map(|(index, record)| {
                    if index < changed_count {
                        OsvRawRecord {
                            source_path: None,
                            raw_json: record
                                .raw_json
                                .replace("2099-01-01", "2099-01-04")
                                .replace("original", "baseline-changed"),
                        }
                    } else {
                        record.clone()
                    }
                })
                .collect();
            let writes_before: i64 = baseline
                .writer
                .with_connection(|connection| {
                    Box::pin(async move {
                        sqlx::query_scalar("SELECT total_changes()")
                            .fetch_one(connection)
                            .await
                    })
                })
                .await
                .unwrap();
            let started = std::time::Instant::now();
            baseline
                .import_osv_records_deferred_search(input)
                .await
                .unwrap();
            baseline.rebuild_osv_search().await.unwrap();
            let elapsed = started.elapsed();
            let writes_after: i64 = baseline
                .writer
                .with_connection(|connection| {
                    Box::pin(async move {
                        sqlx::query_scalar("SELECT total_changes()")
                            .fetch_one(connection)
                            .await
                    })
                })
                .await
                .unwrap();
            eprintln!(
                "baseline global OSV FTS rebuild: requested_changes={changed_count} elapsed={elapsed:?} sqlite_row_changes={}",
                writes_after - writes_before
            );
            baseline.close().await.unwrap();
        }
    }

    #[tokio::test]
    async fn imports_cve_with_stable_fts_rowid() {
        let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        database.initialize().await.unwrap();
        database.import_cve_raw_json(r#"{"cveMetadata":{"cveId":"CVE-2099-1","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-01T00:00:00Z"},"containers":{"cna":{"title":"Example CVE","affected":[{"vendor":"Acme","product":"widget","description":"Affected widget description.","versions":[{"version":"1.0","status":"affected","versionType":"semver","lessThan":"2.0","lessThanOrEqual":"1.9"}]}],"metrics":[{"cvssV3_1":{"version":"3.1","baseScore":9.8,"baseSeverity":"CRITICAL","vectorString":"CVSS:3.1/AV:N"}}],"problemTypes":[{"descriptions":[{"cweId":"CWE-79","description":"XSS"}]}]}}}"#.to_owned()).await.unwrap();
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
            detail.affected[0].description.as_deref(),
            Some("Affected widget description.")
        );
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
                .cve_details(&[
                    "missing".to_owned(),
                    "CVE-2099-1".to_owned(),
                    "CVE-2099-1".to_owned(),
                ])
                .await
                .unwrap(),
            vec![None, Some(detail.clone()), Some(detail)]
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
    async fn combined_search_joins_cwe_affected_and_cvss_filters_with_and() {
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
    async fn advanced_search_honors_default_published_desc_sorting() {
        let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        database.initialize().await.unwrap();
        database
            .import_cve_raw_jsons(vec![
                r#"{"cveMetadata":{"cveId":"CVE-2099-newer-published","state":"PUBLISHED","datePublished":"2099-02-01T00:00:00Z","dateUpdated":"2099-01-01T00:00:00Z"},"containers":{"cna":{"title":"newer published"}}}"#.to_owned(),
                r#"{"cveMetadata":{"cveId":"CVE-2099-newer-updated","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-03-01T00:00:00Z"},"containers":{"cna":{"title":"newer updated"}}}"#.to_owned(),
            ])
            .await
            .unwrap();
        let published = database
            .search_cves_advanced(SqlxCveSearch::default(), false, 10, 0)
            .await
            .unwrap();
        assert_eq!(published[0].cve_id, "CVE-2099-newer-published");
        let updated = database
            .search_cves_advanced(
                SqlxCveSearch {
                    sort_order: CveSummarySortOrder::UpdatedDesc,
                    ..SqlxCveSearch::default()
                },
                false,
                10,
                0,
            )
            .await
            .unwrap();
        assert_eq!(updated[0].cve_id, "CVE-2099-newer-updated");
    }

    #[tokio::test]
    async fn kev_filter_is_applied_before_search_pagination() {
        let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        database.initialize().await.unwrap();
        database.import_cve_raw_json(r#"{"cveMetadata":{"cveId":"CVE-2099-0001","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-02T00:00:00Z"},"containers":{"cna":{"title":"Windows KEV vulnerability"}}}"#.to_owned()).await.unwrap();
        database.import_cve_raw_json(r#"{"cveMetadata":{"cveId":"CVE-2099-0002","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-03T00:00:00Z"},"containers":{"cna":{"title":"Windows non-KEV vulnerability"}}}"#.to_owned()).await.unwrap();
        database
            .import_kev_json(include_str!("../../../fixtures/kev/kev-test.json").to_owned())
            .await
            .unwrap();

        let options = crate::CveAdvancedSearch {
            query: Some("windows".to_owned()),
            query_mode: Some(crate::CveAdvancedQueryMode::FreeText),
            kev_only: true,
            ..Default::default()
        };
        let rows = database
            .search_cve_summaries_advanced(&options, 1, 0)
            .await
            .unwrap();
        assert_eq!(
            rows.iter()
                .map(|row| row.cve_id.as_str())
                .collect::<Vec<_>>(),
            vec!["CVE-2099-0001"]
        );
        assert_eq!(
            database
                .count_cve_summaries_advanced(&options)
                .await
                .unwrap(),
            1
        );
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
        let (_, changed) = database
            .import_epss_csv_with_status(
                include_str!("../../../fixtures/epss/epss-test.csv").to_owned(),
                false,
            )
            .await
            .unwrap();
        assert!(!changed);
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
    async fn epss_snapshot_is_deduplicated_replaced_and_atomic() {
        let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        database.initialize().await.unwrap();
        for id in ["CVE-2099-0001", "CVE-2099-0002"] {
            database.import_cve_raw_json(format!(r#"{{"cveMetadata":{{"cveId":"{id}","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-01T00:00:00Z"}},"containers":{{"cna":{{"title":"EPSS fixture"}}}}}}"#)).await.unwrap();
        }
        database.import_epss_csv("#model_version:v1,score_date:2099-01-01\ncve,epss,percentile\nCVE-2099-0001,0.1,0.2\nCVE-2099-0002,0.3,0.4\nCVE-2099-missing,0.5,0.6\nCVE-2099-0001,0.7,0.8\n".to_owned()).await.unwrap();
        let first: Vec<(String, f64)> = database
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query_as("SELECT cve_id, epss FROM epss_current ORDER BY cve_id")
                        .fetch_all(connection)
                        .await
                })
            })
            .await
            .unwrap();
        assert_eq!(
            first,
            vec![
                ("CVE-2099-0001".to_owned(), 0.7),
                ("CVE-2099-0002".to_owned(), 0.3)
            ]
        );

        database.import_epss_csv("#model_version:v2,score_date:2099-01-02\ncve,epss,percentile\nCVE-2099-0002,0.9,0.95\n".to_owned()).await.unwrap();
        let replaced: Vec<(String, f64)> = database
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query_as("SELECT cve_id, epss FROM epss_current ORDER BY cve_id")
                        .fetch_all(connection)
                        .await
                })
            })
            .await
            .unwrap();
        assert_eq!(replaced, vec![("CVE-2099-0002".to_owned(), 0.9)]);

        let failing_csv =
            "#model_version:v3,score_date:2099-01-04\ncve,epss,percentile\nCVE-2099-0001,0.2,0.3\n"
                .to_owned();
        let conflicting_hash = Md5::digest(failing_csv.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        database.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query("INSERT INTO epss_raw_records(score_date,fetched_at,content_hash,raw_csv) VALUES ('2099-01-03','2099-01-03T00:00:00Z',?,'conflict')")
                .bind(conflicting_hash).execute(connection).await.map(|_| ())
        })).await.unwrap();
        assert!(database.import_epss_csv(failing_csv).await.is_err());
        let after_error: Vec<(String, f64)> = database
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query_as("SELECT cve_id, epss FROM epss_current ORDER BY cve_id")
                        .fetch_all(connection)
                        .await
                })
            })
            .await
            .unwrap();
        assert_eq!(after_error, replaced);
    }

    /// Reproducible local micro-benchmark for a realistic EPSS current snapshot.
    /// Run with: cargo test -p qanvuli-db benchmark_epss_snapshot -- --ignored --nocapture
    #[tokio::test]
    #[ignore = "performance benchmark"]
    async fn benchmark_epss_snapshot() {
        const ROWS: usize = 50_000;
        let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        database.initialize().await.unwrap();
        database
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    let mut transaction = connection.begin().await?;
                    for start in (0..ROWS).step_by(100) {
                        let mut query = QueryBuilder::<Sqlite>::new(
                    "INSERT INTO cve(cve_id,state,published_at,updated_at,title,serial,reference_text,raw_json) ",
                        );
                        query.push_values(start..(start + 100).min(ROWS), |mut row, index| {
                            row.push_bind(format!("CVE-2099-{index:05}"))
                                .push_bind(0_i64)
                                .push_bind("2099-01-01T00:00:00Z")
                                .push_bind("2099-01-01T00:00:00Z")
                        .push_bind("")
                        .push_bind(i64::try_from(index).unwrap())
                        .push_bind("")
                        .push_bind("{}");
                        });
                        query.build().execute(&mut *transaction).await?;
                    }
                    transaction.commit().await
                })
            })
            .await
            .unwrap();
        let mut csv =
            String::from("#model_version:v2099.01.01,score_date:2099-01-01\ncve,epss,percentile\n");
        for index in 0..ROWS {
            use std::fmt::Write as _;
            writeln!(&mut csv, "CVE-2099-{index:05},0.123,0.456").unwrap();
        }
        let started = std::time::Instant::now();
        let imported = database.import_epss_csv(csv).await.unwrap();
        eprintln!("EPSS: records={imported} elapsed={:?}", started.elapsed());
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
    async fn package_query_evaluates_npm_and_pypi_ranges_and_normalizes_names() {
        let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        database.initialize().await.unwrap();
        database
            .import_osv_record(OsvRawRecord {
                source_path: None,
                raw_json: r#"{"schema_version":"1.8.0","id":"GHSA-2099-npm","modified":"2099-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"jquery"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]}]}"#.to_owned(),
            })
            .await
            .unwrap();
        database
            .import_osv_record(OsvRawRecord {
                source_path: None,
                raw_json: r#"{"schema_version":"1.8.0","id":"PYSEC-2099-name","modified":"2099-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"PyPI","name":"pillow-heif"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.0.post1"}]}]}]}"#.to_owned(),
            })
            .await
            .unwrap();

        let npm = database
            .query_package_matches("npm", "jquery", "1.10.2", None)
            .await
            .unwrap();
        assert_eq!(npm.len(), 1);
        assert_eq!(npm[0].affected.status, "affected");

        let pypi = database
            .query_package_matches("PyPI", "pillow_heif", "1.0", None)
            .await
            .unwrap();
        assert_eq!(pypi.len(), 1);
        assert_eq!(pypi[0].affected.status, "affected");
        assert!(
            database
                .has_osv_package_advisory("PyPI", "pillow_heif", None)
                .await
                .unwrap()
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
    async fn package_matching_preserves_order_across_query_batch_boundaries() {
        let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        database.initialize().await.unwrap();
        database
            .import_osv_record(OsvRawRecord {
                source_path: None,
                raw_json: r#"{"schema_version":"1.8.0","id":"GHSA-2099-batched-package","modified":"2099-01-01T00:00:00Z","aliases":["CVE-2099-9999"],"affected":[{"package":{"ecosystem":"crates.io","name":"example"},"versions":["1.0.0"],"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]}]}"#.to_owned(),
            })
            .await
            .unwrap();
        let queries = (0..=PACKAGE_QUERY_BATCH_SIZE)
            .map(|_| PackageQuery {
                ecosystem: "crates.io".to_owned(),
                package: "example".to_owned(),
                version: "1.0.0".to_owned(),
                purl: None,
            })
            .collect::<Vec<_>>();
        let findings = database
            .query_package_matches_batch(&queries)
            .await
            .unwrap();
        let coverage = database
            .has_osv_package_advisories_batch(&queries)
            .await
            .unwrap();
        assert_eq!(findings.len(), PACKAGE_QUERY_BATCH_SIZE + 1);
        assert_eq!(coverage, vec![true; PACKAGE_QUERY_BATCH_SIZE + 1]);
        assert!(findings.iter().all(|rows| {
            rows.len() == 1
                && rows[0].primary_id == "GHSA-2099-batched-package"
                && rows[0].cve_ids == ["CVE-2099-9999"]
                && rows[0].fixed_versions == ["2.0.0"]
        }));
    }

    #[tokio::test]
    async fn osv_date_batch_preserves_order_across_id_batch_boundaries() {
        let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        database.initialize().await.unwrap();
        let ids = (0..=OSV_DATE_BATCH_SIZE)
            .map(|index| format!("OSV-MISSING-{index}"))
            .collect::<Vec<_>>();
        let dates = database.osv_advisory_dates_batch(&ids).await.unwrap();
        assert_eq!(dates.len(), OSV_DATE_BATCH_SIZE + 1);
        assert!(dates.iter().all(Option::is_none));
    }

    #[tokio::test]
    async fn cve_detail_batch_preserves_order_across_id_batch_boundaries() {
        let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        database.initialize().await.unwrap();
        let ids = (0..=2_000)
            .map(|index| format!("CVE-2099-{index:04}"))
            .collect::<Vec<_>>();
        let details = database
            .cve_summaries_with_details_batch(&ids, CveStateScope::PublishedOnly)
            .await
            .unwrap();
        assert_eq!(details.len(), 2_001);
        assert!(details.iter().all(Option::is_none));
    }

    #[tokio::test]
    async fn imports_kev_through_integer_cve_foreign_keys_idempotently() {
        let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        database.initialize().await.unwrap();
        database.import_cve_raw_json(r#"{"cveMetadata":{"cveId":"CVE-2099-0001","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-01T00:00:00Z"},"containers":{"cna":{"title":"Example CVE"}}}"#.to_owned()).await.unwrap();
        let fixture = include_str!("../../../fixtures/kev/kev-test.json").to_owned();
        assert_eq!(database.import_kev_json(fixture.clone()).await.unwrap(), 1);
        assert_eq!(
            database
                .import_kev_json_with_status(fixture, false)
                .await
                .unwrap(),
            (1, false)
        );
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
