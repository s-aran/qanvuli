//! High-level vulnerability queries.

use super::sqlx_database::{
    SqlxCveSearch, SqlxCveSummary, SqlxCvssSearch, SqlxDatabase, SqlxOsvSummary,
    cve_affected_descriptions, cve_stored_versions, sql_normalized_package_name,
};
use crate::{
    AffectedPackageSummary, CveAdvancedQueryMode, CveAdvancedSearch, CveAffectedDetail,
    CveAffectedVersionDetail, CveCvssDetail, CveCweDetail, CveDatabaseStatus, CveDetail,
    CveReference, CveRiskSummary, CveStateScope, CveSummary, CveSummaryWithDetail, CweEntry,
    DatabaseStatus, DbSource, EnrichedCve, EnrichedCveSummary, EnrichedFinding,
    EnrichmentDatabaseStatus, EnrichmentStatusSummary, EpssInfo, Evidence, IdentifierEdgeEvidence,
    KevInfo, OsvSummary, SourceSyncState,
};
use qanvuli_models::{RawCveStatusRecord, parse_json_with_raw};
use sqlx::Row;
use std::collections::{HashMap, HashSet};

mod cve;
mod enrichment;
mod osv;

/// Maximum number of CVE IDs expanded into one detail-loading operation.
const CVE_ID_BATCH_SIZE: usize = 2_000;

type CompatCweRow = (i32, Option<String>, Option<String>, Option<i32>);
type CompatCvssRow = (
    i64,
    String,
    Option<f64>,
    Option<String>,
    Option<String>,
    Option<String>,
);
type CompatAffectedRow = (
    i64,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    String,
);

#[derive(Clone, Copy)]
enum OsvPackageFilter<'a> {
    Any,
    Exact(&'a str),
    Contains(&'a str),
}

#[derive(Clone, Copy)]
struct OsvScopedFilters<'a> {
    query: Option<&'a str>,
    families: &'a [String],
    ecosystems: Option<&'a [String]>,
    package: OsvPackageFilter<'a>,
}

fn include_rejected(scope: CveStateScope) -> bool {
    scope == CveStateScope::IncludeRejected
}

fn advanced_cve_filters(options: &CveAdvancedSearch) -> SqlxCveSearch {
    let mut filters = SqlxCveSearch {
        published_since: options.published_from.clone(),
        published_until: options.published_to.clone(),
        cwe_ids: options.cwe.iter().cloned().collect(),
        vendor_like: options.vendor.as_ref().map(|v| format!("%{v}%")),
        product_like: options.product.as_ref().map(|v| format!("%{v}%")),
        vendor_exact: options.vendor_exact.clone(),
        product_exact: options.product_exact.clone(),
        sort_order: options.sort_order,
        ..Default::default()
    };
    match options.query_mode.unwrap_or(CveAdvancedQueryMode::FreeText) {
        CveAdvancedQueryMode::FreeText => filters.text = options.query.clone(),
        CveAdvancedQueryMode::Product => {
            filters.product_like = options.query.as_ref().map(|v| format!("%{v}%"))
        }
        CveAdvancedQueryMode::Vendor => {
            filters.vendor_like = options.query.as_ref().map(|v| format!("%{v}%"))
        }
        CveAdvancedQueryMode::Cwe => filters.cwe_ids.extend(options.query.iter().cloned()),
        CveAdvancedQueryMode::Cve => filters.cve_id_prefix = options.query.clone(),
    }
    filters
}

fn cwe_number(value: &str) -> Option<i32> {
    let value = value.trim();
    let upper = value.to_ascii_uppercase();
    value
        .strip_prefix("CWE-")
        .or_else(|| value.strip_prefix("CWE"))
        .or_else(|| upper.strip_prefix("CWE-"))
        .or_else(|| upper.strip_prefix("CWE"))
        .unwrap_or(value)
        .parse::<i32>()
        .ok()
        .filter(|id| *id > 0)
}

fn cwe_entries_with_relation_counts(rows: Vec<CompatCweRow>) -> Vec<CweEntry> {
    let mut sibling_groups = HashMap::<Option<i32>, usize>::new();
    let mut child_counts = HashMap::<i32, usize>::new();
    for (_, _, _, parent_id) in &rows {
        *sibling_groups.entry(*parent_id).or_default() += 1;
        if let Some(parent_id) = parent_id {
            *child_counts.entry(*parent_id).or_default() += 1;
        }
    }
    rows.into_iter()
        .map(|(id, description, status, parent_id)| CweEntry {
            id,
            description,
            status,
            parent_id,
            parent_count: usize::from(parent_id.is_some()),
            sibling_count: sibling_groups
                .get(&parent_id)
                .copied()
                .unwrap_or_default()
                .saturating_sub(1),
            child_count: child_counts.get(&id).copied().unwrap_or_default(),
            capec_ids: Vec::new(),
        })
        .collect()
}

fn cwe_entries_tree_order(entries: Vec<CweEntry>, limit: usize) -> Vec<CweEntry> {
    let ids = entries.iter().map(|entry| entry.id).collect::<HashSet<_>>();
    let mut children = HashMap::<i32, Vec<i32>>::new();
    for entry in &entries {
        if let Some(parent_id) = entry.parent_id
            && ids.contains(&parent_id)
        {
            children.entry(parent_id).or_default().push(entry.id);
        }
    }
    for child_ids in children.values_mut() {
        child_ids.sort_unstable();
    }
    let by_id = entries
        .into_iter()
        .map(|entry| (entry.id, entry))
        .collect::<HashMap<_, _>>();
    let mut roots = by_id
        .values()
        .filter(|entry| {
            entry
                .parent_id
                .is_none_or(|parent_id| !by_id.contains_key(&parent_id))
        })
        .map(|entry| entry.id)
        .collect::<Vec<_>>();
    roots.sort_unstable();
    let mut ordered_ids = Vec::with_capacity(by_id.len());
    let mut seen = HashSet::new();
    for root_id in roots {
        push_cwe_tree_id(root_id, &children, &mut seen, &mut ordered_ids);
    }
    let mut remaining = by_id.keys().copied().collect::<Vec<_>>();
    remaining.sort_unstable();
    for id in remaining {
        push_cwe_tree_id(id, &children, &mut seen, &mut ordered_ids);
    }
    ordered_ids
        .into_iter()
        .take(limit)
        .filter_map(|id| by_id.get(&id).cloned())
        .collect()
}

fn push_cwe_tree_id(
    id: i32,
    children: &HashMap<i32, Vec<i32>>,
    seen: &mut HashSet<i32>,
    ordered_ids: &mut Vec<i32>,
) {
    if !seen.insert(id) {
        return;
    }
    ordered_ids.push(id);
    if let Some(child_ids) = children.get(&id) {
        for child_id in child_ids {
            push_cwe_tree_id(*child_id, children, seen, ordered_ids);
        }
    }
}

fn summary(row: super::sqlx_database::SqlxCveSummary) -> CveSummary {
    row.into()
}

fn osv_summary(row: SqlxOsvSummary) -> OsvSummary {
    OsvSummary {
        osv_id: row.osv_id,
        schema_version: None,
        published_at: row.published_at,
        modified_at: Some(row.modified_at),
        withdrawn_at: row.withdrawn_at,
        summary: row.summary,
        details: row.details,
        package_summary: row.package_summary,
    }
}

fn risk_summary(row: &sqlx::sqlite::SqliteRow) -> Result<CveRiskSummary, sqlx::Error> {
    Ok(CveRiskSummary {
        cve_id: row.try_get("cve_id")?,
        title: row.try_get("title")?,
        published_at: row.try_get("published_at")?,
        updated_at: row.try_get("updated_at")?,
        state: row.try_get("state")?,
        kev_listed: row.try_get::<i64, _>("kev_listed")? != 0,
        kev_date_added: row.try_get("kev_date_added")?,
        kev_due_date: row.try_get("kev_due_date")?,
        kev_known_ransomware_campaign_use: row.try_get("kev_known_ransomware_campaign_use")?,
        epss: row.try_get("epss")?,
        epss_percentile: row.try_get("epss_percentile")?,
        epss_score_date: row.try_get("epss_score_date")?,
        epss_model_version: row.try_get("epss_model_version")?,
        max_cvss_score: row.try_get("max_cvss_score")?,
        max_cvss_severity: row.try_get("max_cvss_severity")?,
        max_cvss_version: row.try_get("max_cvss_version")?,
    })
}
