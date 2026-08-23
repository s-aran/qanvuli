//! SQLite database implementation.

use super::{
    maintenance::rebuild_cve_search,
    package_eval::{
        CveVersionChange, CveVersionRange, OsvRange, ecosystem_identity_key,
        evaluate_cve_version_ranges, evaluate_version, normalize_package_name,
        package_identity_from_purl, package_identity_purl, parse_package_purl, versions_equivalent,
    },
    schema,
    search::fts_query,
    timestamps::{canonical_cve_utc, canonical_utc},
    writer::SqliteWriter,
};
use crate::{
    AffectedStatus, CveAffectedDetail, CveAffectedVersionDetail, CveCvssDetail, CveCweDetail,
    CveDetail, CveStateScope, CveSummary, CveSummarySortOrder, CveSummaryWithDetail,
    EnrichedFinding, FindingEnrichment, OsvRawRecord, PackageQuery, PrioritySignals, SsvcInfo,
    SsvcSearch,
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

mod cve;
mod maintenance;
mod osv;
mod package;
mod ssvc;

#[cfg(test)]
mod tests;

/// Maximum number of caller package queries encoded in one SQLite JSON input.
const PACKAGE_QUERY_BATCH_SIZE: usize = 200;
/// Maximum number of affected-package IDs used by one range/version statement.
const PACKAGE_ID_BATCH_SIZE: usize = 2_000;
/// Maximum number of OSV IDs used by one alias statement.
const OSV_ID_BATCH_SIZE: usize = 2_000;
/// Maximum number of OSV IDs used by one advisory-date statement.
const OSV_DATE_BATCH_SIZE: usize = 2_000;
/// Natural CVE ordering compares the four-digit year and variable-width sequence numerically.
/// The full identifier remains the final key for malformed or otherwise tied identifiers.
const CVE_ID_ASC_KEYS: &str = "CAST(substr(c.cve_id, 5, 4) AS INTEGER) ASC, CAST(substr(c.cve_id, 10) AS INTEGER) ASC, c.cve_id ASC";
const CVE_ID_DESC_KEYS: &str = "CAST(substr(c.cve_id, 5, 4) AS INTEGER) DESC, CAST(substr(c.cve_id, 10) AS INTEGER) DESC, c.cve_id DESC";

fn prefixed_numeric_id(value: &str, prefix: &str) -> Option<i64> {
    let value = value.trim();
    let suffix = if value
        .get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
    {
        value.get(prefix.len()..)?
    } else {
        value
    };
    suffix
        .strip_prefix('-')
        .unwrap_or(suffix)
        .parse::<i64>()
        .ok()
        .filter(|id| *id > 0)
}
/// Builds SQLite-side package normalization for already-imported rows.
/// Repeating `replace('--', '-')` 16 times collapses separator runs up to
/// 65,536 characters, well beyond practical package-name limits.
pub(super) fn sql_normalized_package_name(name: &str, ecosystem: &str) -> String {
    let mut pypi = format!("replace(replace(lower({name}), '_', '-'), '.', '-')");
    for _ in 0..16 {
        pypi = format!("replace({pypi}, '--', '-')");
    }
    let pub_name =
        format!("replace(replace(replace(lower({name}), '-', '_'), '.', '_'), ' ', '_')");
    format!(
        "CASE lower({ecosystem}) WHEN 'pypi' THEN {pypi} WHEN 'nuget' THEN lower({name}) WHEN 'github actions' THEN lower({name}) WHEN 'pub' THEN {pub_name} ELSE {name} END"
    )
}

fn sql_ecosystem_matches(left: &str, right: &str) -> String {
    // Ecosystem names are ASCII case-insensitive, but an OSV ecosystem suffix
    // can contain a Maven repository URL whose path is case-sensitive.  Build
    // the same key as `ecosystem_identity_key`: lowercase only the base name.
    let left_key = format!(
        "CASE WHEN instr({left}, ':')=0 THEN lower({left}) ELSE lower(substr({left}, 1, instr({left}, ':')-1)) || ':' || substr({left}, instr({left}, ':')+1) END"
    );
    format!("({left_key}={right} COLLATE BINARY)")
}

fn canonical_stored_ecosystem(ecosystem: &str) -> String {
    let key = ecosystem_identity_key(ecosystem);
    if key == "maven" {
        "Maven".to_owned()
    } else if let Some(repository) = key.strip_prefix("maven:") {
        format!("Maven:{repository}")
    } else {
        ecosystem.to_owned()
    }
}

fn canonical_imported_package_ecosystem(
    source_ecosystem: Option<&str>,
    purl_ecosystem: Option<&str>,
) -> Option<String> {
    match source_ecosystem {
        Some(source) => {
            let source_key = ecosystem_identity_key(source);
            let purl_key = purl_ecosystem.map(ecosystem_identity_key);
            // OSV uses a scoped Maven ecosystem for non-Central repositories,
            // while purl carries the same scope as `repository_url`. Prefer
            // that more specific locator when the feed's ecosystem is the
            // otherwise-unscoped Maven value.
            if source_key == "maven"
                && purl_key
                    .as_deref()
                    .is_some_and(|key| key.starts_with("maven:"))
            {
                purl_ecosystem.map(canonical_stored_ecosystem)
            } else {
                Some(canonical_stored_ecosystem(source))
            }
        }
        None => purl_ecosystem.map(canonical_stored_ecosystem),
    }
}

fn purl_base_identity(purl: &str) -> &str {
    let qualifier = purl.find('?').unwrap_or(purl.len());
    let subpath = purl.find('#').unwrap_or(purl.len());
    &purl[..qualifier.min(subpath)]
}

fn package_queries_json(packages: &[PackageQuery]) -> Result<String, sqlx::Error> {
    let input = packages
        .iter()
        .map(|package| {
            serde_json::json!({
                "ecosystem": package.ecosystem,
                "ecosystem_key": ecosystem_identity_key(&package.ecosystem),
                "package": package.package,
                "version": package.version,
                "purl": package.purl,
                "purl_base": package.purl.as_deref().map(purl_base_identity),
            })
        })
        .collect::<Vec<_>>();
    serde_json::to_string(&input).map_err(|error| {
        sqlx::Error::Protocol(format!("failed to encode package queries: {error}"))
    })
}

fn validate_package_query_identity(
    ecosystem: &str,
    package: &str,
    purl: Option<&str>,
) -> Result<(), sqlx::Error> {
    let Some(purl) = purl else {
        return Ok(());
    };
    let Some((purl_ecosystem, purl_package)) = package_identity_from_purl(purl) else {
        return Err(sqlx::Error::Protocol(
            "purl is malformed or uses an unsupported package type".to_owned(),
        ));
    };
    let ecosystems_match =
        ecosystem_identity_key(ecosystem) == ecosystem_identity_key(&purl_ecosystem);
    if !ecosystems_match
        || normalize_package_name(ecosystem, package)
            != normalize_package_name(&purl_ecosystem, &purl_package)
    {
        return Err(sqlx::Error::Protocol(format!(
            "package identity `{ecosystem}:{package}` conflicts with purl `{purl}`"
        )));
    }
    Ok(())
}

fn consolidate_package_findings(findings: Vec<EnrichedFinding>) -> Vec<EnrichedFinding> {
    let mut indexes = BTreeMap::<(String, String), usize>::new();
    let mut consolidated: Vec<EnrichedFinding> = Vec::new();
    for finding in findings {
        let key = (finding.source.clone(), finding.primary_id.clone());
        let Some(index) = indexes.get(&key).copied() else {
            indexes.insert(key, consolidated.len());
            consolidated.push(finding);
            continue;
        };
        let existing = &mut consolidated[index];
        if package_status_rank(&finding.affected.status)
            > package_status_rank(&existing.affected.status)
        {
            existing.affected = finding.affected.clone();
            existing.priority_signals.affected_confidence = finding.affected.confidence.clone();
        }
        for cve_id in finding.cve_ids {
            if !existing.cve_ids.contains(&cve_id) {
                existing.cve_ids.push(cve_id);
            }
        }
        for alias in finding.aliases {
            if !existing.aliases.contains(&alias) {
                existing.aliases.push(alias);
            }
        }
        for fixed_version in finding.fixed_versions {
            if !existing.fixed_versions.contains(&fixed_version) {
                existing.fixed_versions.push(fixed_version);
            }
        }
        existing.priority_signals.has_fixed_version |= finding.priority_signals.has_fixed_version;
        existing.priority_signals.known_exploited |= finding.priority_signals.known_exploited;
        existing.priority_signals.epss_percentile = match (
            existing.priority_signals.epss_percentile,
            finding.priority_signals.epss_percentile,
        ) {
            (Some(left), Some(right)) => Some(left.max(right)),
            (left, right) => left.or(right),
        };
        existing.evidence.extend(finding.evidence);
    }
    consolidated
}

fn package_status_rank(status: &str) -> u8 {
    match status {
        "affected" => 3,
        "unknown" => 2,
        "unsupported_version_scheme" => 1,
        _ => 0,
    }
}
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
    Option<String>,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
);
type CvePackageCandidate = (
    i64,
    String,
    Option<String>,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
);
#[derive(Clone, Debug, Default, serde::Serialize)]
pub(crate) struct CveStoredVersion {
    pub(crate) version: Option<String>,
    pub(crate) status: Option<String>,
    pub(crate) version_type: Option<String>,
    pub(crate) less_than: Option<String>,
    pub(crate) less_than_or_equal: Option<String>,
    pub(crate) changes: Vec<CveStoredVersionChange>,
}

#[derive(Clone, Debug, Default, serde::Serialize)]
pub(crate) struct CveStoredVersionChange {
    pub(crate) at: String,
    pub(crate) status: String,
}

/// Reads both the current object representation and the legacy five-element
/// tuple representation already present in existing databases.
pub(crate) fn cve_stored_versions(raw_json: &str) -> Result<Vec<CveStoredVersion>, String> {
    let values = serde_json::from_str::<Vec<Value>>(raw_json).map_err(|error| error.to_string())?;
    values
        .into_iter()
        .map(|value| {
            if let Some(object) = value.as_object() {
                let changes = object
                    .get("changes")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(|change| {
                        Some(CveStoredVersionChange {
                            at: change.get("at")?.as_str()?.to_owned(),
                            status: change.get("status")?.as_str()?.to_owned(),
                        })
                    })
                    .collect();
                return Ok(CveStoredVersion {
                    version: object
                        .get("version")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned),
                    status: object
                        .get("status")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned),
                    version_type: object
                        .get("version_type")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned),
                    less_than: object
                        .get("less_than")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned),
                    less_than_or_equal: object
                        .get("less_than_or_equal")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned),
                    changes,
                });
            }
            let Some(values) = value.as_array() else {
                return Err("affected version is neither an object nor a tuple".to_owned());
            };
            if values.len() < 5 {
                return Err("affected version tuple has fewer than five fields".to_owned());
            }
            let string_at = |index: usize| {
                values
                    .get(index)
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
            };
            Ok(CveStoredVersion {
                version: string_at(0),
                status: string_at(1),
                version_type: string_at(2),
                less_than: string_at(3),
                less_than_or_equal: string_at(4),
                changes: Vec::new(),
            })
        })
        .collect()
}
const CVE_NORMALIZE_BATCH_SIZE: usize = 2_000;

#[derive(Clone, Copy, Eq, PartialEq)]
enum CvePackageIdentity {
    /// The CNA supplied a package name and its collection identifies the queried ecosystem.
    Confirmed,
    /// Product-only CVE records cannot distinguish a library from a same-named product.
    Ambiguous,
    /// The collection positively identifies a different package ecosystem or product catalog.
    Excluded,
}

fn collection_url_host(collection_url: &str) -> Option<&str> {
    let collection_url = collection_url.trim();
    let (scheme, remainder) = collection_url.split_once("://")?;
    let mut scheme_chars = scheme.chars();
    if !scheme_chars.next()?.is_ascii_alphabetic()
        || !scheme_chars.all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '+' | '-' | '.')
        })
    {
        return None;
    }

    let authority_end = remainder.find(['/', '?', '#']).unwrap_or(remainder.len());
    let authority = &remainder[..authority_end];
    let host_and_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    if host_and_port.is_empty() || host_and_port.starts_with('[') {
        return None;
    }

    let host = if let Some((host, port)) = host_and_port.rsplit_once(':') {
        if host.contains(':') || port.parse::<u16>().is_err() {
            return None;
        }
        host
    } else {
        host_and_port
    };
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty()
        || !host.split('.').all(|label| {
            !label.is_empty()
                && label
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '-')
        })
    {
        return None;
    }
    Some(host)
}

fn host_matches_domain(host: &str, domain: &str) -> bool {
    host.eq_ignore_ascii_case(domain)
        || host
            .get(..host.len().saturating_sub(domain.len()))
            .is_some_and(|prefix| {
                prefix.len() > 1
                    && prefix.ends_with('.')
                    && host[prefix.len()..].eq_ignore_ascii_case(domain)
            })
}

fn cve_package_identity(
    ecosystem: &str,
    _package_name: Option<&str>,
    _product: Option<&str>,
    collection_url: Option<&str>,
) -> CvePackageIdentity {
    let Some(collection_url) = collection_url else {
        // `packageName` is more useful than product, but is not a purl and
        // does not itself state an ecosystem.  Retain it for review without
        // presenting it as a verified package vulnerability.
        return CvePackageIdentity::Ambiguous;
    };
    let Some(collection_host) = collection_url_host(collection_url) else {
        return CvePackageIdentity::Excluded;
    };
    let ecosystem_base = ecosystem
        .split_once(':')
        .map_or(ecosystem, |(base, _)| base);
    let ecosystem_matches = match ecosystem_base.to_ascii_lowercase().as_str() {
        "pypi" => host_matches_domain(collection_host, "pypi.org"),
        "npm" => {
            host_matches_domain(collection_host, "npmjs.com")
                || host_matches_domain(collection_host, "registry.npmjs.org")
        }
        "crates.io" => host_matches_domain(collection_host, "crates.io"),
        "maven" => {
            host_matches_domain(collection_host, "maven.apache.org")
                || host_matches_domain(collection_host, "repo.maven.apache.org")
        }
        "rubygems" => host_matches_domain(collection_host, "rubygems.org"),
        "packagist" => host_matches_domain(collection_host, "packagist.org"),
        "nuget" => host_matches_domain(collection_host, "nuget.org"),
        _ => false,
    };
    if ecosystem_matches {
        CvePackageIdentity::Confirmed
    } else {
        // A collection is affirmative identity evidence. Do not reinterpret a
        // WordPress/theme marketplace record as a package merely because its
        // product has the same name.
        CvePackageIdentity::Excluded
    }
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
    pub ssvc: Vec<SsvcInfo>,
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
    pub cve_id_prefix: Option<String>,
    pub cwe_ids: Vec<String>,
    pub capec_ids: Vec<String>,
    pub vendor_like: Option<String>,
    pub product_like: Option<String>,
    pub vendor_exact: Option<String>,
    pub product_exact: Option<String>,
    pub cvss: SqlxCvssSearch,
    pub ssvc: SsvcSearch,
    pub published_since: Option<String>,
    pub published_until: Option<String>,
    pub updated_since: Option<String>,
    pub updated_until: Option<String>,
    pub sort_order: CveSummarySortOrder,
}

/// Parameters for the name-based CVE fallback used by package searches.
#[derive(Clone, Debug)]
pub struct SqlxAffectedComponentSearch {
    pub vendor: Option<String>,
    pub component: String,
    pub published_since: Option<String>,
    pub updated_since: Option<String>,
    pub state_scope: CveStateScope,
    pub limit: u64,
    pub offset: u64,
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
    pub published_at: Option<String>,
    pub modified_at: String,
    pub summary: Option<String>,
    pub details: Option<String>,
    pub withdrawn_at: Option<String>,
    pub package_summary: Option<String>,
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
    pub last_attempt_at: Option<String>,
    pub last_success_at: Option<String>,
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
                ssvc: detail.ssvc,
            },
        }
    }
}

/// Database handle backed by one writer connection.
#[derive(Clone, Debug)]
pub struct SqlxDatabase {
    pub(crate) writer: SqliteWriter,
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
