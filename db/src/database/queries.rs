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
        published_at: None,
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

impl SqlxDatabase {
    pub async fn find_cve_raw_json_by_id(
        &self,
        cve_id: &str,
    ) -> Result<Option<serde_json::Value>, sqlx::Error> {
        self.cve_raw_json(cve_id)
            .await?
            .map(|raw| {
                serde_json::from_str(&raw).map_err(|error| {
                    sqlx::Error::Protocol(format!("invalid stored CVE JSON: {error}"))
                })
            })
            .transpose()
    }

    pub async fn find_osv_raw_json_by_id(
        &self,
        osv_id: &str,
    ) -> Result<Option<serde_json::Value>, sqlx::Error> {
        let osv_id = osv_id.to_owned();
        let raw: Option<String> = self
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query_scalar(
                        "SELECT raw_json FROM osv_raw_records WHERE osv_id=? COLLATE NOCASE",
                    )
                    .bind(osv_id)
                    .fetch_optional(connection)
                    .await
                })
            })
            .await?;
        raw.map(|raw| {
            serde_json::from_str(&raw)
                .map_err(|error| sqlx::Error::Protocol(format!("invalid stored OSV JSON: {error}")))
        })
        .transpose()
    }

    pub async fn find_cve_model_by_id(
        &self,
        cve_id: &str,
    ) -> Result<Option<RawCveStatusRecord>, sqlx::Error> {
        self.cve_raw_json(cve_id)
            .await?
            .map(|raw| {
                parse_json_with_raw(raw).map_err(|error| {
                    sqlx::Error::Protocol(format!("invalid stored CVE JSON: {error}"))
                })
            })
            .transpose()
    }

    pub async fn find_cve_summary_with_detail(
        &self,
        cve_id: &str,
    ) -> Result<Option<CveSummaryWithDetail>, sqlx::Error> {
        Ok(self.cve_summary_with_detail(cve_id).await?.map(Into::into))
    }

    /// Loads CVE summaries and normalized details in bounded set-based queries.
    pub async fn cve_summaries_with_details_batch(
        &self,
        cve_ids: &[String],
        state_scope: CveStateScope,
    ) -> Result<Vec<Option<CveSummaryWithDetail>>, sqlx::Error> {
        if cve_ids.is_empty() {
            return Ok(Vec::new());
        }
        let requested = cve_ids.to_vec();
        let include_rejected = include_rejected(state_scope);
        let mut by_id = HashMap::new();
        for batch in requested.chunks(CVE_ID_BATCH_SIZE) {
            let requested_json = serde_json::to_string(batch)
                .map_err(|error| sqlx::Error::Protocol(error.to_string()))?;
            let summaries: Vec<CveSummary> = self
                .writer
                .with_connection(|connection| {
                    Box::pin(async move {
                        let rows: Vec<SqlxCveSummary> = sqlx::query_as(
                            "SELECT c.cve_id, c.state, c.published_at, c.updated_at, c.title, c.description_en FROM cve c WHERE c.cve_id IN (SELECT value FROM json_each(?)) AND (? OR c.state=0)",
                        )
                        .bind(requested_json)
                        .bind(include_rejected)
                        .fetch_all(connection)
                        .await?;
                        Ok(rows.into_iter().map(CveSummary::from).collect())
                    })
                })
                .await?;
            for row in self.attach_cve_overview_details(summaries).await? {
                by_id.insert(row.summary.cve_id.clone(), row);
            }
        }
        Ok(requested
            .into_iter()
            .map(|id| by_id.get(&id).cloned())
            .collect())
    }

    pub async fn attach_cve_overview_details(
        &self,
        rows: Vec<CveSummary>,
    ) -> Result<Vec<CveSummaryWithDetail>, sqlx::Error> {
        if rows.is_empty() {
            return Ok(Vec::new());
        }
        let cve_ids_json = serde_json::to_string(
            &rows
                .iter()
                .map(|row| row.cve_id.as_str())
                .collect::<Vec<_>>(),
        )
        .map_err(|error| sqlx::Error::Protocol(error.to_string()))?;
        let mut details = self
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    let id_rows: Vec<(i64, String, String)> = sqlx::query_as(
                        "SELECT c.id, c.cve_id, c.raw_json FROM cve c JOIN json_each(?) requested ON requested.value=c.cve_id",
                    )
                    .bind(cve_ids_json)
                    .fetch_all(&mut *connection)
                    .await?;
                    let db_ids_json = serde_json::to_string(
                        &id_rows.iter().map(|(id, _, _)| *id).collect::<Vec<_>>(),
                    )
                    .map_err(|error| sqlx::Error::Protocol(error.to_string()))?;
                    let cve_id_by_db_id = id_rows
                        .iter()
                        .map(|(id, cve_id, _)| (*id, cve_id.clone()))
                        .collect::<HashMap<_, _>>();
                    let affected_descriptions_by_db_id = id_rows
                        .iter()
                        .map(|(id, _, raw_json)| (*id, cve_affected_descriptions(raw_json)))
                        .collect::<HashMap<_, _>>();
                    let mut details = id_rows
                        .into_iter()
                        .map(|(_, cve_id, _)| (cve_id, CveDetail::default()))
                        .collect::<HashMap<_, _>>();

                    let cwes: Vec<(i64, i32, Option<String>)> = sqlx::query_as(
                        "SELECT link.cve_db_id, cwe.id, cwe.description FROM cve_cwe link JOIN cwe ON cwe.id=link.cwe_id WHERE link.cve_db_id IN (SELECT value FROM json_each(?)) ORDER BY link.cve_db_id, cwe.id",
                    )
                    .bind(&db_ids_json)
                    .fetch_all(&mut *connection)
                    .await?;
                    for (db_id, id, description) in cwes {
                        if let Some(cve_id) = cve_id_by_db_id.get(&db_id)
                            && let Some(detail) = details.get_mut(cve_id)
                        {
                            detail.cwes.push(CveCweDetail { id, description });
                        }
                    }

                    let cvss: Vec<CompatCvssRow> = sqlx::query_as(
                        "SELECT cve_db_id, version, base_score, base_severity, vector_string, source FROM cve_cvss WHERE cve_db_id IN (SELECT value FROM json_each(?)) ORDER BY cve_db_id, base_score DESC, version",
                    )
                    .bind(&db_ids_json)
                    .fetch_all(&mut *connection)
                    .await?;
                    for (db_id, version, base_score, base_severity, vector_string, source) in cvss {
                        if let Some(cve_id) = cve_id_by_db_id.get(&db_id)
                            && let Some(detail) = details.get_mut(cve_id)
                        {
                            detail.cvss.push(CveCvssDetail {
                                version,
                                base_score,
                                base_severity,
                                vector_string,
                                source,
                            });
                        }
                    }

                    let affected: Vec<CompatAffectedRow> = sqlx::query_as(
                        "SELECT cve_db_id, vendor, product, package_name, collection_url, default_status, raw_json FROM cve_affected WHERE cve_db_id IN (SELECT value FROM json_each(?)) ORDER BY cve_db_id, id",
                    )
                    .bind(db_ids_json)
                    .fetch_all(&mut *connection)
                    .await?;
                    let mut affected_indexes = HashMap::<i64, usize>::new();
                    for (db_id, vendor, product, package_name, collection_url, default_status, raw_json) in affected {
                        if let Some(cve_id) = cve_id_by_db_id.get(&db_id)
                            && let Some(detail) = details.get_mut(cve_id)
                        {
                            let affected_index = affected_indexes.entry(db_id).or_default();
                            let description = affected_descriptions_by_db_id
                                .get(&db_id)
                                .and_then(|descriptions| descriptions.get(*affected_index))
                                .cloned()
                                .flatten();
                            *affected_index += 1;
                            let versions = cve_stored_versions(&raw_json)
                                .unwrap_or_else(|error| {
                                    tracing::warn!(cve_id = %cve_id, %error, "failed to parse cve_affected.raw_json");
                                    Vec::new()
                                })
                                .into_iter()
                                .map(|version| CveAffectedVersionDetail {
                                    version: version.version,
                                    status: version.status,
                                    version_type: version.version_type,
                                    less_than: version.less_than,
                                    less_than_or_equal: version.less_than_or_equal,
                                })
                                .collect();
                            detail.affected.push(CveAffectedDetail {
                                vendor,
                                product,
                                package_name,
                                description,
                                collection_url,
                                default_status,
                                versions,
                            });
                        }
                    }
                    Ok(details)
                })
            })
            .await?;
        Ok(rows
            .into_iter()
            .map(|summary| CveSummaryWithDetail {
                detail: details.remove(&summary.cve_id).unwrap_or_default(),
                summary,
            })
            .collect())
    }

    pub async fn search_cve_summaries_free_text_with_state_scope(
        &self,
        query: &str,
        scope: CveStateScope,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, sqlx::Error> {
        let Some(query) = super::search::fts_query(query) else {
            return Ok(Vec::new());
        };
        let include_rejected = include_rejected(scope);
        self.writer.with_connection(|connection| Box::pin(async move {
            let rows = sqlx::query_as("SELECT c.cve_id, c.state, c.published_at, c.updated_at, c.title, c.description_en FROM cve_summary_fts f JOIN cve c ON c.cve_id=f.cve_id WHERE cve_summary_fts MATCH ? AND (? OR c.state=0) ORDER BY bm25(cve_summary_fts), c.published_at DESC, c.cve_id LIMIT ? OFFSET ?")
                .bind(query).bind(include_rejected).bind(limit as i64).bind(offset as i64)
                .fetch_all(connection).await?;
            Ok(rows.into_iter().map(summary).collect())
        })).await
    }

    pub async fn cve_summaries_by_ids_with_state_scope(
        &self,
        ids: &[String],
        scope: CveStateScope,
    ) -> Result<Vec<CveSummary>, sqlx::Error> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let ids_json =
            serde_json::to_string(ids).map_err(|error| sqlx::Error::Protocol(error.to_string()))?;
        let include_rejected = include_rejected(scope);
        self.writer
            .with_connection(|connection| {
                Box::pin(async move {
                    let rows = sqlx::query_as(
                        "SELECT c.cve_id, c.state, c.published_at, c.updated_at, c.title, c.description_en \
                         FROM json_each(?) AS requested \
                         JOIN cve AS c ON c.cve_id=requested.value \
                         WHERE (? OR c.state=0) \
                         ORDER BY CAST(requested.key AS INTEGER)",
                    )
                    .bind(ids_json)
                    .bind(include_rejected)
                    .fetch_all(connection)
                    .await?;
                    Ok(rows.into_iter().map(summary).collect())
                })
            })
            .await
    }

    pub async fn cve_summaries_by_ids_sorted(
        &self,
        ids: &[String],
        scope: CveStateScope,
        sort_order: crate::CveSummarySortOrder,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, sqlx::Error> {
        Ok(self
            .cves_by_ids_sorted(ids, scope, sort_order, limit, offset)
            .await?
            .into_iter()
            .map(summary)
            .collect())
    }

    pub async fn search_cve_summaries_by_cwe_with_state_scope(
        &self,
        cwe_ids: &[String],
        scope: CveStateScope,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, sqlx::Error> {
        Ok(self
            .search_cves_by_cwes(
                cwe_ids,
                include_rejected(scope),
                limit as i64,
                offset as i64,
            )
            .await?
            .into_iter()
            .map(summary)
            .collect())
    }

    pub async fn search_cve_summaries_by_vendor_product_with_state_scope(
        &self,
        vendor: Option<&str>,
        product: Option<&str>,
        scope: CveStateScope,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, sqlx::Error> {
        Ok(self
            .search_cves_by_affected(
                vendor.map(str::to_owned),
                product.map(str::to_owned),
                false,
                false,
                include_rejected(scope),
                limit as i64,
                offset as i64,
            )
            .await?
            .into_iter()
            .map(summary)
            .collect())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn search_cve_summaries_by_vendor_product_exact_with_state_scope(
        &self,
        vendor: Option<&str>,
        product: Option<&str>,
        vendor_exact: Option<&str>,
        product_exact: Option<&str>,
        exclude_wordpress_collection: bool,
        scope: CveStateScope,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, sqlx::Error> {
        let vendor = vendor_exact.or(vendor).map(str::to_owned);
        let product = product_exact.or(product).map(str::to_owned);
        let exact = vendor_exact.is_some() || product_exact.is_some();
        Ok(self
            .search_cves_by_affected(
                vendor,
                product,
                exact,
                exclude_wordpress_collection,
                include_rejected(scope),
                limit as i64,
                offset as i64,
            )
            .await?
            .into_iter()
            .map(summary)
            .collect())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn search_cve_summaries_by_cvss_with_state_scope(
        &self,
        min_score: Option<f64>,
        max_score: Option<f64>,
        severity: Option<&str>,
        version: Option<&str>,
        scope: CveStateScope,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, sqlx::Error> {
        Ok(self
            .search_cves_by_cvss(
                SqlxCvssSearch {
                    min_score,
                    max_score,
                    severity: severity.map(str::to_owned),
                    version: version.map(str::to_owned),
                },
                include_rejected(scope),
                limit as i64,
                offset as i64,
            )
            .await?
            .into_iter()
            .map(summary)
            .collect())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn search_cve_summaries_by_product_cvss_exact_with_state_scope(
        &self,
        vendor: Option<&str>,
        product: Option<&str>,
        vendor_exact: Option<&str>,
        product_exact: Option<&str>,
        min_score: Option<f64>,
        max_score: Option<f64>,
        severity: Option<&str>,
        version: Option<&str>,
        scope: CveStateScope,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, sqlx::Error> {
        let filters = SqlxCveSearch {
            vendor_like: vendor.map(|v| format!("%{v}%")),
            product_like: product.map(|v| format!("%{v}%")),
            vendor_exact: vendor_exact.map(str::to_owned),
            product_exact: product_exact.map(str::to_owned),
            cvss: SqlxCvssSearch {
                min_score,
                max_score,
                severity: severity.map(str::to_owned),
                version: version.map(str::to_owned),
            },
            sort_order: crate::CveSummarySortOrder::ScoreDesc,
            ..Default::default()
        };
        Ok(self
            .search_cves_advanced(
                filters,
                include_rejected(scope),
                limit as i64,
                offset as i64,
            )
            .await?
            .into_iter()
            .map(summary)
            .collect())
    }

    pub async fn search_cve_summaries_by_date_with_state_scope(
        &self,
        published_since: Option<&str>,
        updated_since: Option<&str>,
        scope: CveStateScope,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, sqlx::Error> {
        Ok(self
            .search_cves_by_dates(
                published_since.map(str::to_owned),
                updated_since.map(str::to_owned),
                include_rejected(scope),
                limit as i64,
                offset as i64,
            )
            .await?
            .into_iter()
            .map(summary)
            .collect())
    }

    pub async fn search_cve_summaries_by_cve_id_prefix_with_state_scope(
        &self,
        prefix: &str,
        scope: CveStateScope,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, sqlx::Error> {
        Ok(self
            .search_cves_by_id_prefix(prefix, include_rejected(scope), limit as i64, offset as i64)
            .await?
            .into_iter()
            .map(summary)
            .collect())
    }

    pub async fn search_cve_summaries_advanced(
        &self,
        options: &CveAdvancedSearch,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, sqlx::Error> {
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
            CveAdvancedQueryMode::Cve => {
                filters.cve_id_prefix = options.query.clone();
            }
        }
        let rows = self
            .search_cves_advanced_with_kev(
                filters,
                include_rejected(options.state_scope),
                options.kev_only,
                limit as i64,
                offset as i64,
            )
            .await?;
        Ok(rows.into_iter().map(summary).collect())
    }

    pub async fn count_cve_summaries_advanced(
        &self,
        options: &CveAdvancedSearch,
    ) -> Result<u64, sqlx::Error> {
        Ok(self
            .search_cve_summaries_advanced(options, u64::MAX / 2, 0)
            .await?
            .len() as u64)
    }

    pub async fn count_cve_summaries_free_text_with_state_scope(
        &self,
        query: &str,
        scope: CveStateScope,
    ) -> Result<u64, sqlx::Error> {
        let Some(query) = super::search::fts_query(query) else {
            return Ok(0);
        };
        let include = include_rejected(scope);
        self.writer.with_connection(|c| Box::pin(async move { let n:i64=sqlx::query_scalar("SELECT COUNT(*) FROM cve_summary_fts f JOIN cve c ON c.cve_id=f.cve_id WHERE cve_summary_fts MATCH ? AND (? OR c.state=0)").bind(query).bind(include).fetch_one(c).await?; Ok(n as u64) })).await
    }

    pub async fn count_cve_summaries_by_vendor_product_with_state_scope(
        &self,
        vendor: Option<&str>,
        product: Option<&str>,
        scope: CveStateScope,
    ) -> Result<u64, sqlx::Error> {
        let vendor = vendor.map(|v| format!("%{v}%"));
        let product = product.map(|v| format!("%{v}%"));
        let include = include_rejected(scope);
        self.writer.with_connection(|c| Box::pin(async move { let n:i64=sqlx::query_scalar("SELECT COUNT(DISTINCT c.id) FROM cve c JOIN cve_affected a ON a.cve_db_id=c.id WHERE (? OR c.state=0) AND (? IS NULL OR a.vendor LIKE ?) AND (? IS NULL OR a.product LIKE ? OR a.package_name LIKE ?)").bind(include).bind(&vendor).bind(&vendor).bind(&product).bind(&product).bind(&product).fetch_one(c).await?; Ok(n as u64) })).await
    }

    pub async fn count_cve_summaries_by_cwe_with_state_scope(
        &self,
        ids: &[String],
        scope: CveStateScope,
    ) -> Result<u64, sqlx::Error> {
        let ids: Vec<i64> = ids
            .iter()
            .filter_map(|id| {
                id.trim()
                    .strip_prefix("CWE-")
                    .unwrap_or(id.trim())
                    .parse()
                    .ok()
            })
            .collect();
        if ids.is_empty() {
            return Ok(0);
        }
        let json = serde_json::to_string(&ids).map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
        let include = include_rejected(scope);
        self.writer.with_connection(|c| Box::pin(async move { let n:i64=sqlx::query_scalar("SELECT COUNT(DISTINCT c.id) FROM cve c JOIN cve_cwe w ON w.cve_db_id=c.id WHERE w.cwe_id IN (SELECT value FROM json_each(?)) AND (? OR c.state=0)").bind(json).bind(include).fetch_one(c).await?; Ok(n as u64) })).await
    }

    pub async fn count_cve_summaries_by_cve_id_prefix_with_state_scope(
        &self,
        prefix: &str,
        scope: CveStateScope,
    ) -> Result<u64, sqlx::Error> {
        let prefix = format!("{}%", prefix.trim());
        let include = include_rejected(scope);
        self.writer
            .with_connection(|c| {
                Box::pin(async move {
                    let n: i64 = sqlx::query_scalar(
                        "SELECT COUNT(*) FROM cve WHERE cve_id LIKE ? AND (? OR state=0)",
                    )
                    .bind(prefix)
                    .bind(include)
                    .fetch_one(c)
                    .await?;
                    Ok(n as u64)
                })
            })
            .await
    }

    pub async fn find_cve_references(
        &self,
        cve_id: &str,
    ) -> Result<Vec<CveReference>, sqlx::Error> {
        let Some(detail) = self.cve_detail(cve_id).await? else {
            return Ok(Vec::new());
        };
        Ok(detail
            .references
            .into_iter()
            .map(|row| CveReference {
                url: Some(row.url),
                name: row.name,
                tags: serde_json::from_str(&row.tags_json).unwrap_or_default(),
            })
            .collect())
    }

    pub async fn search_osv_summaries_free_text(
        &self,
        query: &str,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<OsvSummary>, sqlx::Error> {
        self.search_osv_summaries_free_text_sorted(
            query,
            crate::CveSummarySortOrder::RelationRankAsc,
            limit,
            offset,
        )
        .await
    }

    pub async fn search_osv_summaries_free_text_sorted(
        &self,
        query: &str,
        sort_order: crate::CveSummarySortOrder,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<OsvSummary>, sqlx::Error> {
        let rows = self
            .search_osv_paginated_sorted(query, sort_order, limit as i64, offset as i64)
            .await?;
        Ok(rows.into_iter().map(osv_summary).collect())
    }

    pub async fn osv_summaries_by_ids_sorted(
        &self,
        ids: &[String],
        sort_order: crate::CveSummarySortOrder,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<OsvSummary>, sqlx::Error> {
        Ok(self
            .osvs_by_ids_sorted(ids, sort_order, limit, offset)
            .await?
            .into_iter()
            .map(osv_summary)
            .collect())
    }

    pub async fn search_osv_summaries_by_package(
        &self,
        query: &str,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<OsvSummary>, sqlx::Error> {
        self.search_osv_summaries_scoped_by_exact_package(None, &[], None, query, limit, offset)
            .await
    }

    pub async fn find_enriched_osv(&self, osv_id: &str) -> Result<Option<OsvSummary>, sqlx::Error> {
        Ok(self.find_osv_summary(osv_id).await?.map(osv_summary))
    }

    pub async fn get_enriched_osv_many(
        &self,
        ids: &[String],
    ) -> Result<Vec<OsvSummary>, sqlx::Error> {
        let mut rows = Vec::new();
        for id in ids {
            if let Some(row) = self.find_enriched_osv(id).await? {
                rows.push(row);
            }
        }
        Ok(rows)
    }

    /// Resolves a page of OSV advisories to CVEs that exist in the local CVE table.
    ///
    /// The `osv_aliases` primary key starts with `osv_id`, so this remains one indexed
    /// lookup for the whole page instead of an identifier-graph query per result.
    pub async fn cve_aliases_for_osv_ids(
        &self,
        ids: &[String],
        scope: CveStateScope,
    ) -> Result<HashMap<String, Vec<String>>, sqlx::Error> {
        if ids.is_empty() {
            return Ok(HashMap::new());
        }
        let ids_json =
            serde_json::to_string(ids).map_err(|error| sqlx::Error::Protocol(error.to_string()))?;
        let include_rejected = include_rejected(scope);
        self.writer
            .with_connection(|connection| {
                Box::pin(async move {
                    let rows: Vec<(String, String)> = sqlx::query_as(
                        "SELECT alias.osv_id, cve.cve_id \
                         FROM osv_aliases AS alias \
                         JOIN cve ON cve.cve_id=alias.alias_id \
                         WHERE alias.osv_id IN (SELECT value FROM json_each(?)) \
                           AND (? OR cve.state=0) \
                         ORDER BY alias.osv_id, cve.cve_id",
                    )
                    .bind(ids_json)
                    .bind(include_rejected)
                    .fetch_all(connection)
                    .await?;
                    let mut aliases = HashMap::<String, Vec<String>>::new();
                    for (osv_id, cve_id) in rows {
                        aliases.entry(osv_id).or_default().push(cve_id);
                    }
                    Ok(aliases)
                })
            })
            .await
    }

    /// Loads complete OSV summaries for a page of CVEs in one indexed query.
    pub async fn osv_summaries_for_cve_ids(
        &self,
        ids: &[String],
    ) -> Result<HashMap<String, Vec<OsvSummary>>, sqlx::Error> {
        if ids.is_empty() {
            return Ok(HashMap::new());
        }
        let ids_json =
            serde_json::to_string(ids).map_err(|error| sqlx::Error::Protocol(error.to_string()))?;
        self.writer
            .with_connection(|connection| {
                Box::pin(async move {
                    let rows = sqlx::query(
                        "SELECT alias.alias_id AS cve_id, advisory.osv_id, \
                                advisory.schema_version, advisory.published_at, \
                                advisory.modified_at, advisory.withdrawn_at, \
                                advisory.summary, advisory.details, \
                                (SELECT group_concat(COALESCE(package.ecosystem, '') || ':' || COALESCE(package.package_name, ''), ', ') \
                                 FROM osv_affected_packages AS package \
                                 WHERE package.osv_id=advisory.osv_id) AS package_summary \
                         FROM osv_aliases AS alias \
                         JOIN osv_advisories AS advisory ON advisory.osv_id=alias.osv_id \
                         WHERE alias.alias_id IN (SELECT value FROM json_each(?)) \
                         ORDER BY alias.alias_id, advisory.modified_at DESC, advisory.osv_id",
                    )
                    .bind(ids_json)
                    .fetch_all(connection)
                    .await?;
                    let mut advisories = HashMap::<String, Vec<OsvSummary>>::new();
                    for row in rows {
                        advisories
                            .entry(row.try_get("cve_id")?)
                            .or_default()
                            .push(OsvSummary {
                                osv_id: row.try_get("osv_id")?,
                                schema_version: row.try_get("schema_version")?,
                                published_at: row.try_get("published_at")?,
                                modified_at: row.try_get("modified_at")?,
                                withdrawn_at: row.try_get("withdrawn_at")?,
                                summary: row.try_get("summary")?,
                                details: row.try_get("details")?,
                                package_summary: row.try_get("package_summary")?,
                            });
                    }
                    Ok(advisories)
                })
            })
            .await
    }

    pub async fn osv_advisory_families(&self) -> Result<Vec<String>, sqlx::Error> {
        self.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query_scalar("SELECT DISTINCT CASE WHEN instr(osv_id, '-')>0 THEN substr(osv_id, 1, instr(osv_id, '-')-1) ELSE osv_id END FROM osv_advisories ORDER BY 1")
                .fetch_all(connection).await
        })).await
    }

    pub async fn search_osv_summaries_scoped(
        &self,
        query: Option<&str>,
        families: &[String],
        ecosystems: Option<&[String]>,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<OsvSummary>, sqlx::Error> {
        self.search_osv_summaries_scoped_sorted(
            query,
            families,
            ecosystems,
            crate::CveSummarySortOrder::UpdatedDesc,
            limit,
            offset,
        )
        .await
    }

    pub async fn search_osv_summaries_scoped_sorted(
        &self,
        query: Option<&str>,
        families: &[String],
        ecosystems: Option<&[String]>,
        sort_order: crate::CveSummarySortOrder,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<OsvSummary>, sqlx::Error> {
        self.search_osv_scoped_inner(
            OsvScopedFilters {
                query,
                families,
                ecosystems,
                package: OsvPackageFilter::Any,
            },
            sort_order,
            limit,
            offset,
        )
        .await
    }

    pub async fn search_osv_summaries_scoped_by_exact_package(
        &self,
        query: Option<&str>,
        families: &[String],
        ecosystems: Option<&[String]>,
        package: &str,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<OsvSummary>, sqlx::Error> {
        self.search_osv_summaries_scoped_by_exact_package_sorted(
            query,
            families,
            ecosystems,
            package,
            crate::CveSummarySortOrder::UpdatedDesc,
            limit,
            offset,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn search_osv_summaries_scoped_by_exact_package_sorted(
        &self,
        query: Option<&str>,
        families: &[String],
        ecosystems: Option<&[String]>,
        package: &str,
        sort_order: crate::CveSummarySortOrder,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<OsvSummary>, sqlx::Error> {
        self.search_osv_scoped_inner(
            OsvScopedFilters {
                query,
                families,
                ecosystems,
                package: OsvPackageFilter::Exact(package),
            },
            sort_order,
            limit,
            offset,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn search_osv_summaries_scoped_by_package_sorted(
        &self,
        families: &[String],
        ecosystems: Option<&[String]>,
        package: &str,
        sort_order: crate::CveSummarySortOrder,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<OsvSummary>, sqlx::Error> {
        self.search_osv_scoped_inner(
            OsvScopedFilters {
                query: None,
                families,
                ecosystems,
                package: OsvPackageFilter::Contains(package),
            },
            sort_order,
            limit,
            offset,
        )
        .await
    }

    async fn search_osv_scoped_inner(
        &self,
        filters: OsvScopedFilters<'_>,
        sort_order: crate::CveSummarySortOrder,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<OsvSummary>, sqlx::Error> {
        let query = filters.query.map(|q| format!("%{q}%"));
        let (package, package_like) = match filters.package {
            OsvPackageFilter::Any => (None, None),
            OsvPackageFilter::Exact(value) => (Some(value.to_owned()), None),
            OsvPackageFilter::Contains(value) => (None, Some(format!("%{value}%"))),
        };
        let families = filters.families.to_vec();
        let ecosystems = filters.ecosystems.unwrap_or_default().to_vec();
        self.writer.with_connection(|connection| Box::pin(async move {
            let families_json = serde_json::to_string(&families).unwrap_or_default();
            let ecosystems_json = serde_json::to_string(&ecosystems).unwrap_or_default();
            let stored_package = sql_normalized_package_name("p.package_name", "p.ecosystem");
            let input_package = sql_normalized_package_name("input.package_name", "p.ecosystem");
            let order_by = match sort_order {
                crate::CveSummarySortOrder::PublishedAsc => "a.published_at IS NULL ASC, a.published_at ASC, a.osv_id ASC",
                crate::CveSummarySortOrder::PublishedDesc => "a.published_at IS NULL ASC, a.published_at DESC, a.osv_id DESC",
                crate::CveSummarySortOrder::UpdatedAsc => "a.modified_at ASC, a.osv_id ASC",
                crate::CveSummarySortOrder::UpdatedDesc => "a.modified_at DESC, a.osv_id DESC",
                crate::CveSummarySortOrder::CveIdAsc | crate::CveSummarySortOrder::ScoreAsc => "a.osv_id ASC",
                crate::CveSummarySortOrder::CveIdDesc | crate::CveSummarySortOrder::ScoreDesc => "a.osv_id DESC",
                crate::CveSummarySortOrder::RelationRankAsc => "a.published_at ASC, a.osv_id ASC",
                crate::CveSummarySortOrder::RelationRankDesc => "a.published_at DESC, a.osv_id DESC",
            };
            let statement = format!("WITH input(package_name, package_like) AS (VALUES (?, ?)) SELECT DISTINCT a.osv_id, COALESCE(a.modified_at, '') AS modified_at, a.summary, a.details, a.withdrawn_at, (SELECT group_concat(COALESCE(package.ecosystem, '') || ':' || COALESCE(package.package_name, ''), ', ') FROM osv_affected_packages AS package WHERE package.osv_id=a.osv_id) AS package_summary FROM input CROSS JOIN osv_advisories a LEFT JOIN osv_affected_packages p ON p.osv_id=a.osv_id WHERE (? IS NULL OR a.osv_id LIKE ? OR a.summary LIKE ? OR a.details LIKE ? OR p.ecosystem LIKE ? OR p.package_name LIKE ? OR p.purl LIKE ?) AND (json_array_length(?)=0 OR EXISTS(SELECT 1 FROM json_each(?) f WHERE a.osv_id LIKE f.value || '-%')) AND (json_array_length(?)=0 OR p.ecosystem IN (SELECT value FROM json_each(?))) AND (input.package_name IS NULL OR {stored_package}={input_package} COLLATE BINARY) AND (input.package_like IS NULL OR p.package_name LIKE input.package_like OR p.purl LIKE input.package_like) ORDER BY {order_by} LIMIT ? OFFSET ?");
            let rows: Vec<SqlxOsvSummary> = sqlx::query_as(sqlx::AssertSqlSafe(statement))
                .bind(&package)
                .bind(&package_like)
                .bind(&query).bind(&query).bind(&query).bind(&query).bind(&query).bind(&query).bind(&query)
                .bind(&families_json).bind(&families_json).bind(&ecosystems_json).bind(&ecosystems_json)
                .bind(limit as i64).bind(offset as i64)
                .fetch_all(connection).await?;
            Ok(rows.into_iter().map(osv_summary).collect())
        })).await
    }

    pub async fn count_osv_summaries_scoped(
        &self,
        query: Option<&str>,
        families: &[String],
        ecosystems: Option<&[String]>,
    ) -> Result<u64, sqlx::Error> {
        self.count_osv_scoped_inner(OsvScopedFilters {
            query,
            families,
            ecosystems,
            package: OsvPackageFilter::Any,
        })
        .await
    }

    pub async fn count_osv_summaries_scoped_by_exact_package(
        &self,
        query: Option<&str>,
        families: &[String],
        ecosystems: Option<&[String]>,
        package: &str,
    ) -> Result<u64, sqlx::Error> {
        self.count_osv_scoped_inner(OsvScopedFilters {
            query,
            families,
            ecosystems,
            package: OsvPackageFilter::Exact(package),
        })
        .await
    }

    pub async fn count_osv_summaries_free_text(&self, query: &str) -> Result<u64, sqlx::Error> {
        let Some(query) = super::search::fts_query(query) else {
            return Ok(0);
        };
        self.writer
            .with_connection(|c| {
                Box::pin(async move {
                    let n: i64 = sqlx::query_scalar(
                        "SELECT COUNT(*) FROM osv_text_fts WHERE osv_text_fts MATCH ?",
                    )
                    .bind(query)
                    .fetch_one(c)
                    .await?;
                    Ok(n as u64)
                })
            })
            .await
    }

    pub async fn count_osv_summaries_by_package(&self, query: &str) -> Result<u64, sqlx::Error> {
        self.count_osv_scoped_inner(OsvScopedFilters {
            query: None,
            families: &[],
            ecosystems: None,
            package: OsvPackageFilter::Exact(query),
        })
        .await
    }

    pub async fn count_osv_summaries_scoped_by_package(
        &self,
        families: &[String],
        ecosystems: Option<&[String]>,
        package: &str,
    ) -> Result<u64, sqlx::Error> {
        self.count_osv_scoped_inner(OsvScopedFilters {
            query: None,
            families,
            ecosystems,
            package: OsvPackageFilter::Contains(package),
        })
        .await
    }

    async fn count_osv_scoped_inner(
        &self,
        filters: OsvScopedFilters<'_>,
    ) -> Result<u64, sqlx::Error> {
        let query = filters.query.map(|q| format!("%{q}%"));
        let families = serde_json::to_string(filters.families)
            .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
        let ecosystems = serde_json::to_string(filters.ecosystems.unwrap_or_default())
            .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
        let (package, package_like) = match filters.package {
            OsvPackageFilter::Any => (None, None),
            OsvPackageFilter::Exact(value) => (Some(value.to_owned()), None),
            OsvPackageFilter::Contains(value) => (None, Some(format!("%{value}%"))),
        };
        self.writer.with_connection(|c| Box::pin(async move {
            let stored_package = sql_normalized_package_name("p.package_name", "p.ecosystem");
            let input_package = sql_normalized_package_name("input.package_name", "p.ecosystem");
            let statement = format!("WITH input(package_name, package_like) AS (VALUES (?, ?)) SELECT COUNT(DISTINCT a.osv_id) FROM input CROSS JOIN osv_advisories a LEFT JOIN osv_affected_packages p ON p.osv_id=a.osv_id WHERE (? IS NULL OR a.osv_id LIKE ? OR a.summary LIKE ? OR a.details LIKE ? OR p.ecosystem LIKE ? OR p.package_name LIKE ? OR p.purl LIKE ?) AND (json_array_length(?)=0 OR EXISTS(SELECT 1 FROM json_each(?) f WHERE a.osv_id LIKE f.value || '-%')) AND (json_array_length(?)=0 OR p.ecosystem IN (SELECT value FROM json_each(?))) AND (input.package_name IS NULL OR {stored_package}={input_package} COLLATE BINARY) AND (input.package_like IS NULL OR p.package_name LIKE input.package_like OR p.purl LIKE input.package_like)");
            let n: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(statement))
                .bind(&package)
                .bind(&package_like)
                .bind(&query).bind(&query).bind(&query).bind(&query).bind(&query).bind(&query).bind(&query)
                .bind(&families).bind(&families).bind(&ecosystems).bind(&ecosystems)
                .fetch_one(c).await?;
            Ok(n as u64)
        })).await
    }

    pub async fn find_cwe_entry(&self, id: i32) -> Result<Option<CweEntry>, sqlx::Error> {
        let row: Option<CompatCweRow> = self
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query_as("SELECT id, description, status, parent_id FROM cwe WHERE id=?")
                        .bind(id)
                        .fetch_optional(connection)
                        .await
                })
            })
            .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let mut entry = cwe_entries_with_relation_counts(vec![row]).remove(0);
        entry.capec_ids = self
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query_scalar(
                        "SELECT capec_id FROM capec_cwe WHERE cwe_id=? ORDER BY capec_id",
                    )
                    .bind(id)
                    .fetch_all(connection)
                    .await
                })
            })
            .await?;
        Ok(Some(entry))
    }

    pub async fn search_cwe_entries(
        &self,
        query: &str,
        limit: u64,
        statuses: &[String],
    ) -> Result<Vec<CweEntry>, sqlx::Error> {
        self.search_cwe_entries_filtered(query, limit, statuses, None)
            .await
    }

    pub async fn search_cwe_entries_filtered(
        &self,
        query: &str,
        limit: u64,
        statuses: &[String],
        capec_id: Option<i32>,
    ) -> Result<Vec<CweEntry>, sqlx::Error> {
        let query = query.trim();
        if statuses.is_empty() {
            return Ok(Vec::new());
        }
        let status_json = serde_json::to_string(statuses)
            .map_err(|error| sqlx::Error::Protocol(error.to_string()))?;
        let all_statuses = statuses.len() >= 6;
        let pattern = format!("%{query}%");
        let id = cwe_number(query);
        let query = query.to_owned();
        let rows: Vec<CompatCweRow> = self
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query_as(
                        "SELECT id, description, status, parent_id FROM cwe WHERE (? OR status IN (SELECT value FROM json_each(?))) AND (?='' OR description LIKE ? OR id=?) AND (? IS NULL OR EXISTS(SELECT 1 FROM capec_cwe link WHERE link.cwe_id=cwe.id AND link.capec_id=?)) ORDER BY id",
                    )
                    .bind(all_statuses)
                    .bind(status_json)
                    .bind(query)
                    .bind(pattern)
                    .bind(id)
                    .bind(capec_id)
                    .bind(capec_id)
                    .fetch_all(connection)
                    .await
                })
            })
            .await?;
        let mut entries = cwe_entries_tree_order(
            cwe_entries_with_relation_counts(rows),
            limit.max(1) as usize,
        );
        if !entries.is_empty() {
            let ids = entries.iter().map(|entry| entry.id).collect::<Vec<_>>();
            let ids_json = serde_json::to_string(&ids)
                .map_err(|error| sqlx::Error::Protocol(error.to_string()))?;
            let links: Vec<(i32, i32)> = self
                .writer
                .with_connection(|connection| {
                    Box::pin(async move {
                        sqlx::query_as("SELECT cwe_id,capec_id FROM capec_cwe WHERE cwe_id IN (SELECT value FROM json_each(?)) ORDER BY capec_id")
                            .bind(ids_json)
                            .fetch_all(connection)
                            .await
                    })
                })
                .await?;
            let mut by_cwe = HashMap::<i32, Vec<i32>>::new();
            for (cwe_id, capec_id) in links {
                by_cwe.entry(cwe_id).or_default().push(capec_id);
            }
            for entry in &mut entries {
                entry.capec_ids = by_cwe.remove(&entry.id).unwrap_or_default();
            }
        }
        Ok(entries)
    }

    pub async fn enriched_cve_summaries(
        &self,
        ids: &[String],
    ) -> Result<Vec<EnrichedCveSummary>, sqlx::Error> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let ids_json =
            serde_json::to_string(ids).map_err(|error| sqlx::Error::Protocol(error.to_string()))?;
        self.writer.with_connection(|connection| Box::pin(async move {
            let rows = sqlx::query(
                r#"SELECT j.value AS cve_id,
                   COALESCE((SELECT group_concat(alias_id, ', ') FROM osv_aliases WHERE alias_id=j.value), '') AS aliases,
                   COALESCE((SELECT group_concat(osv_id, ', ') FROM osv_aliases WHERE alias_id=j.value), '') AS osv_ids,
                   COALESCE((SELECT group_concat(COALESCE(a.summary, a.osv_id), ' | ') FROM osv_aliases x JOIN osv_advisories a ON a.osv_id=x.osv_id WHERE x.alias_id=j.value), '') AS osv_summaries,
                   COALESCE((SELECT group_concat(COALESCE(p.ecosystem, '') || ':' || COALESCE(p.package_name, ''), ', ') FROM osv_aliases x JOIN osv_affected_packages p ON p.osv_id=x.osv_id WHERE x.alias_id=j.value), '') AS affected_packages,
                   EXISTS(SELECT 1 FROM kev_entries k WHERE k.cve_id=j.value) AS kev_listed,
                   k.date_added AS kev_date_added, k.due_date AS kev_due_date, k.known_ransomware_campaign_use AS kev_known_ransomware_campaign_use,
                   e.epss, e.percentile AS epss_percentile, e.score_date AS epss_score_date, e.model_version AS epss_model_version
                   FROM json_each(?) j
                   LEFT JOIN kev_entries k ON k.cve_id=j.value
                   LEFT JOIN epss_current e ON e.cve_id=j.value
                   ORDER BY CAST(j.key AS INTEGER)"#
            ).bind(ids_json).fetch_all(connection).await?;
            rows.into_iter().map(|row| Ok(EnrichedCveSummary {
                cve_id: row.try_get("cve_id")?, aliases: row.try_get("aliases")?,
                osv_ids: row.try_get("osv_ids")?, osv_summaries: row.try_get("osv_summaries")?,
                affected_packages: row.try_get("affected_packages")?,
                kev_listed: row.try_get::<i64, _>("kev_listed")? != 0,
                kev_date_added: row.try_get("kev_date_added")?, kev_due_date: row.try_get("kev_due_date")?,
                kev_known_ransomware_campaign_use: row.try_get("kev_known_ransomware_campaign_use")?,
                epss: row.try_get("epss")?, epss_percentile: row.try_get("epss_percentile")?,
                epss_score_date: row.try_get("epss_score_date")?, epss_model_version: row.try_get("epss_model_version")?,
            })).collect()
        })).await
    }

    pub async fn database_status_enriched(&self) -> Result<DatabaseStatus, sqlx::Error> {
        self.writer.with_connection(|connection| Box::pin(async move {
            let row = sqlx::query("SELECT (SELECT COUNT(*) FROM cve) cve_count, (SELECT COUNT(*) FROM cve WHERE state=0) published_count, (SELECT COUNT(*) FROM cve WHERE state=1) rejected_count, (SELECT COUNT(*) FROM cwe) cwe_count, (SELECT COUNT(*) FROM cve_affected) affected_count, (SELECT COUNT(*) FROM cve_cvss) cvss_count, (SELECT MAX(updated_at) FROM cve) latest_cve_updated_at, (SELECT zip_datetime FROM cve_zip_file ORDER BY zip_datetime DESC LIMIT 1) latest_zip_datetime, (SELECT zip_filename FROM cve_zip_file ORDER BY zip_datetime DESC LIMIT 1) latest_zip_filename, (SELECT COUNT(*) FROM osv_advisories) osv_record_count, (SELECT COUNT(*) FROM kev_entries) kev_entry_count, (SELECT COUNT(*) FROM epss_current) epss_current_count, (SELECT COUNT(*) FROM vulnerability_identifiers) identifier_node_count, (SELECT COUNT(*) FROM vulnerability_identifier_edges) identifier_edge_count").fetch_one(&mut *connection).await?;
            let source_rows = sqlx::query("SELECT source, display_name, source_type, default_filename, raw_format FROM db_sources ORDER BY source").fetch_all(&mut *connection).await?;
            let sources = source_rows.into_iter().map(|r| Ok(DbSource { source:r.try_get("source")?, display_name:r.try_get("display_name")?, source_type:r.try_get("source_type")?, default_filename:r.try_get("default_filename")?, raw_format:r.try_get("raw_format")? })).collect::<Result<Vec<_>, sqlx::Error>>()?;
            Ok(DatabaseStatus {
                cve: CveDatabaseStatus { cve_count:row.try_get("cve_count")?, published_count:row.try_get("published_count")?, rejected_count:row.try_get("rejected_count")?, cwe_count:row.try_get("cwe_count")?, affected_count:row.try_get("affected_count")?, cvss_count:row.try_get("cvss_count")?, latest_cve_updated_at:row.try_get("latest_cve_updated_at")?, latest_zip_datetime:row.try_get("latest_zip_datetime")?, latest_zip_filename:row.try_get("latest_zip_filename")? },
                sources,
                enrichment: EnrichmentDatabaseStatus { osv_record_count:row.try_get("osv_record_count")?, kev_entry_count:row.try_get("kev_entry_count")?, epss_current_count:row.try_get("epss_current_count")?, identifier_node_count:row.try_get("identifier_node_count")?, identifier_edge_count:row.try_get("identifier_edge_count")? },
            })
        })).await
    }

    pub async fn related_edges(
        &self,
        id: &str,
    ) -> Result<Vec<IdentifierEdgeEvidence>, sqlx::Error> {
        let id = id.to_owned();
        self.writer.with_connection(|connection| Box::pin(async move {
            let rows = sqlx::query("SELECT from_identifier,to_identifier,relation_type,source,confidence,evidence_json,created_at FROM vulnerability_identifier_edges WHERE from_identifier=? OR to_identifier=? ORDER BY relation_type,from_identifier,to_identifier")
                .bind(&id).bind(&id).fetch_all(connection).await?;
            rows.into_iter().map(|r| Ok(IdentifierEdgeEvidence { from_identifier:r.try_get("from_identifier")?, to_identifier:r.try_get("to_identifier")?, relation_type:r.try_get("relation_type")?, source:r.try_get("source")?, confidence:r.try_get("confidence")?, evidence_json:r.try_get("evidence_json")?, created_at:r.try_get("created_at")? })).collect()
        })).await
    }

    pub async fn get_enriched_cve(&self, cve_id: &str) -> Result<EnrichedCve, sqlx::Error> {
        let cve = self.find_cve_summary_with_detail(cve_id).await?;
        let severity = cve
            .as_ref()
            .map(|row| row.detail.cvss.clone())
            .unwrap_or_default();
        let cwe = cve
            .as_ref()
            .map(|row| {
                row.detail
                    .cwes
                    .iter()
                    .map(|item| format!("CWE-{}", item.id))
                    .collect()
            })
            .unwrap_or_default();
        let id = cve_id.to_owned();
        let (aliases, advisories, packages, kev, epss, source_sync) = self.writer.with_connection(|connection| Box::pin(async move {
            let aliases: Vec<String> = sqlx::query_scalar("SELECT DISTINCT osv_id FROM osv_aliases WHERE alias_id=? ORDER BY osv_id").bind(&id).fetch_all(&mut *connection).await?;
            let advisory_rows = sqlx::query("SELECT a.osv_id,a.schema_version,a.published_at,a.modified_at,a.withdrawn_at,a.summary,a.details,(SELECT group_concat(COALESCE(p.ecosystem,'') || ':' || COALESCE(p.package_name,''), ', ') FROM osv_affected_packages p WHERE p.osv_id=a.osv_id) package_summary FROM osv_aliases x JOIN osv_advisories a ON a.osv_id=x.osv_id WHERE x.alias_id=? ORDER BY a.modified_at DESC,a.osv_id").bind(&id).fetch_all(&mut *connection).await?;
            let advisories = advisory_rows.into_iter().map(|r| Ok(OsvSummary { osv_id:r.try_get("osv_id")?, schema_version:r.try_get("schema_version")?, published_at:r.try_get("published_at")?, modified_at:r.try_get("modified_at")?, withdrawn_at:r.try_get("withdrawn_at")?, summary:r.try_get("summary")?, details:r.try_get("details")?, package_summary:r.try_get("package_summary")? })).collect::<Result<Vec<_>,sqlx::Error>>()?;
            let package_rows=sqlx::query("SELECT p.osv_id,p.ecosystem,p.package_name,p.purl,COALESCE((SELECT group_concat(v.version, ', ') FROM osv_versions v WHERE v.affected_package_id=p.id),'') fixed_versions FROM osv_aliases x JOIN osv_affected_packages p ON p.osv_id=x.osv_id WHERE x.alias_id=? ORDER BY p.osv_id,p.affected_order").bind(&id).fetch_all(&mut *connection).await?;
            let packages=package_rows.into_iter().map(|r| Ok(AffectedPackageSummary { osv_id:r.try_get("osv_id")?, ecosystem:r.try_get("ecosystem")?, package_name:r.try_get("package_name")?, purl:r.try_get("purl")?, fixed_versions:r.try_get("fixed_versions")? })).collect::<Result<Vec<_>,sqlx::Error>>()?;
            let kev_row=sqlx::query("SELECT cve_id,vendor_project,product,vulnerability_name,date_added,short_description,required_action,due_date,known_ransomware_campaign_use,notes,fetched_at FROM kev_entries WHERE cve_id=?").bind(&id).fetch_optional(&mut *connection).await?;
            let kev=kev_row.map(|r| -> Result<KevInfo, sqlx::Error> { Ok(KevInfo { cve_id:r.try_get("cve_id")?, vendor_project:r.try_get("vendor_project")?, product:r.try_get("product")?, vulnerability_name:r.try_get("vulnerability_name")?, date_added:r.try_get("date_added")?, short_description:r.try_get("short_description")?, required_action:r.try_get("required_action")?, due_date:r.try_get("due_date")?, known_ransomware_campaign_use:r.try_get("known_ransomware_campaign_use")?, notes:r.try_get("notes")?, fetched_at:r.try_get("fetched_at")? }) }).transpose()?;
            let epss_row=sqlx::query("SELECT cve_id,epss,percentile,score_date,model_version,fetched_at FROM epss_current WHERE cve_id=?").bind(&id).fetch_optional(&mut *connection).await?;
            let epss=epss_row.map(|r| -> Result<EpssInfo, sqlx::Error> { Ok(EpssInfo { cve_id:r.try_get("cve_id")?, epss:r.try_get("epss")?, percentile:r.try_get("percentile")?, score_date:r.try_get("score_date")?, model_version:r.try_get("model_version")?, fetched_at:r.try_get("fetched_at")? }) }).transpose()?;
            let sync_rows=sqlx::query("SELECT source,last_attempt_at,last_success_at,status,error_message,last_cursor,content_hash,schema_version,record_count FROM source_sync_state ORDER BY source").fetch_all(&mut *connection).await?;
            let source_sync=sync_rows.into_iter().map(|r| Ok(SourceSyncState { source:r.try_get("source")?, last_attempt_at:r.try_get("last_attempt_at")?, last_success_at:r.try_get("last_success_at")?, status:r.try_get("status")?, error_message:r.try_get("error_message")?, last_cursor:r.try_get("last_cursor")?, content_hash:r.try_get("content_hash")?, schema_version:r.try_get("schema_version")?, record_count:r.try_get("record_count")? })).collect::<Result<Vec<_>,sqlx::Error>>()?;
            Ok((aliases,advisories,packages,kev,epss,source_sync))
        })).await?;
        let evidence = self
            .related_edges(cve_id)
            .await?
            .into_iter()
            .map(|edge| Evidence {
                kind: edge.relation_type,
                source: edge.source,
                from: Some(edge.from_identifier),
                to: Some(edge.to_identifier),
                cve_id: Some(cve_id.to_owned()),
                osv_id: None,
                detail: Some(edge.evidence_json),
            })
            .collect();
        Ok(EnrichedCve {
            cve_id: cve_id.to_owned(),
            cve,
            aliases,
            osv_advisories: advisories,
            affected_packages: packages,
            kev,
            epss,
            severity,
            cwe,
            evidence,
            database_status: EnrichmentStatusSummary { source_sync },
        })
    }

    pub async fn query_package_enriched_with_evidence(
        &self,
        ecosystem: &str,
        package: &str,
        version: &str,
        purl: Option<&str>,
        include_evidence: bool,
    ) -> Result<Vec<EnrichedFinding>, sqlx::Error> {
        let mut rows = self
            .query_package_matches(ecosystem, package, version, purl)
            .await?;
        if include_evidence {
            for row in &mut rows {
                row.evidence.push(Evidence {
                    kind: "package_version_evaluation".to_owned(),
                    source: row.source.clone(),
                    from: Some(format!(
                        "{}:{}@{}",
                        row.package.ecosystem, row.package.package, row.package.version
                    )),
                    to: Some(row.primary_id.clone()),
                    cve_id: row.cve_ids.first().cloned(),
                    osv_id: (row.source == "osv").then(|| row.primary_id.clone()),
                    detail: Some(
                        serde_json::json!({
                            "status": &row.affected.status,
                            "confidence": &row.affected.confidence,
                            "purl": &row.package.purl,
                            "fixed_versions": &row.fixed_versions,
                        })
                        .to_string(),
                    ),
                });
                row.evidence_status = "available".to_owned();
            }
        } else {
            for row in &mut rows {
                row.evidence.clear();
            }
        }
        Ok(rows)
    }

    pub async fn cve_risk_summaries(
        &self,
        ids: &[String],
    ) -> Result<Vec<CveRiskSummary>, sqlx::Error> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let ids_json =
            serde_json::to_string(ids).map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
        self.writer.with_connection(|connection| Box::pin(async move {
            let rows = sqlx::query("SELECT c.cve_id,c.title,c.published_at,c.updated_at,c.state, k.cve_id IS NOT NULL kev_listed,k.date_added kev_date_added,k.due_date kev_due_date,k.known_ransomware_campaign_use kev_known_ransomware_campaign_use,e.epss,e.percentile epss_percentile,e.score_date epss_score_date,e.model_version epss_model_version,(SELECT MAX(v.base_score) FROM cve_cvss v WHERE v.cve_db_id=c.id) max_cvss_score,(SELECT v.base_severity FROM cve_cvss v WHERE v.cve_db_id=c.id ORDER BY v.base_score DESC LIMIT 1) max_cvss_severity,(SELECT v.version FROM cve_cvss v WHERE v.cve_db_id=c.id ORDER BY v.base_score DESC LIMIT 1) max_cvss_version FROM json_each(?) j JOIN cve c ON c.cve_id=j.value LEFT JOIN kev_entries k ON k.cve_id=c.cve_id LEFT JOIN epss_current e ON e.cve_id=c.cve_id ORDER BY CAST(j.key AS INTEGER)").bind(ids_json).fetch_all(connection).await?;
            rows.iter().map(risk_summary).collect()
        })).await
    }

    pub async fn search_cve_risk_by_epss(
        &self,
        min_score: Option<f64>,
        min_percentile: Option<f64>,
        scope: CveStateScope,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveRiskSummary>, sqlx::Error> {
        let include = include_rejected(scope);
        self.writer.with_connection(|connection| Box::pin(async move {
            let rows = sqlx::query("SELECT c.cve_id,c.title,c.published_at,c.updated_at,c.state,k.cve_id IS NOT NULL kev_listed,k.date_added kev_date_added,k.due_date kev_due_date,k.known_ransomware_campaign_use kev_known_ransomware_campaign_use,e.epss,e.percentile epss_percentile,e.score_date epss_score_date,e.model_version epss_model_version,(SELECT MAX(v.base_score) FROM cve_cvss v WHERE v.cve_db_id=c.id) max_cvss_score,(SELECT v.base_severity FROM cve_cvss v WHERE v.cve_db_id=c.id ORDER BY v.base_score DESC LIMIT 1) max_cvss_severity,(SELECT v.version FROM cve_cvss v WHERE v.cve_db_id=c.id ORDER BY v.base_score DESC LIMIT 1) max_cvss_version FROM epss_current e JOIN cve c ON c.cve_id=e.cve_id LEFT JOIN kev_entries k ON k.cve_id=c.cve_id WHERE (? OR c.state=0) AND (? IS NULL OR e.epss>=?) AND (? IS NULL OR e.percentile>=?) ORDER BY e.epss DESC,e.percentile DESC,c.cve_id LIMIT ? OFFSET ?")
                .bind(include).bind(min_score).bind(min_score).bind(min_percentile).bind(min_percentile).bind(limit as i64).bind(offset as i64).fetch_all(connection).await?;
            rows.iter().map(risk_summary).collect()
        })).await
    }

    pub async fn kev_entries_count(&self) -> Result<u64, sqlx::Error> {
        self.writer
            .with_connection(|c| {
                Box::pin(async move {
                    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM kev_entries")
                        .fetch_one(c)
                        .await?;
                    Ok(n as u64)
                })
            })
            .await
    }

    pub async fn search_cve_summaries_by_reference_text(
        &self,
        query: &str,
        scope: CveStateScope,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, sqlx::Error> {
        Ok(self
            .search_cves_by_reference_text(
                query,
                include_rejected(scope),
                limit as i64,
                offset as i64,
            )
            .await?
            .into_iter()
            .map(summary)
            .collect())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn search_cve_summaries_by_date_range(
        &self,
        published_from: Option<&str>,
        published_to: Option<&str>,
        updated_from: Option<&str>,
        updated_to: Option<&str>,
        scope: CveStateScope,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, sqlx::Error> {
        let filters = SqlxCveSearch {
            published_since: published_from.map(str::to_owned),
            published_until: published_to.map(str::to_owned),
            updated_since: updated_from.map(str::to_owned),
            updated_until: updated_to.map(str::to_owned),
            ..Default::default()
        };
        Ok(self
            .search_cves_advanced(
                filters,
                include_rejected(scope),
                limit as i64,
                offset as i64,
            )
            .await?
            .into_iter()
            .map(summary)
            .collect())
    }

    pub async fn list_recent_updates(
        &self,
        since: Option<&str>,
        scope: CveStateScope,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, sqlx::Error> {
        Ok(self
            .search_cves_by_dates(
                None,
                since.map(str::to_owned),
                include_rejected(scope),
                limit as i64,
                offset as i64,
            )
            .await?
            .into_iter()
            .map(summary)
            .collect())
    }
}
