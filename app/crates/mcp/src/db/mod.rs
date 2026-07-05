#![allow(clippy::too_many_arguments)]

use crate::{common::error::mcp_error, response};
use qanvuli_app_commands::common::{
    OsvImportSelection, apply_delta_updates, sync_all_enrichment_sources_after_update,
};
use qanvuli_db::{CveDatabase, CveStateScope, CveSummary};
use qanvuli_models::RawCveStatusRecord;
use rmcp::{ErrorData as McpError, model::CallToolResult};
use simd_json::json;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::OnceCell;

#[derive(Clone)]
pub(crate) struct DbProvider {
    db_url: String,
    db: Arc<OnceCell<CveDatabase>>,
}

impl DbProvider {
    pub(crate) fn new(db_url: String) -> Self {
        Self {
            db_url,
            db: Arc::new(OnceCell::new()),
        }
    }

    pub(crate) async fn get(&self) -> Result<&CveDatabase, McpError> {
        self.db
            .get_or_try_init(|| async {
                CveDatabase::connect(&self.db_url).await.map_err(|err| {
                    mcp_error(format!(
                        "failed to connect database `{}`: {err}",
                        self.db_url
                    ))
                })
            })
            .await
    }
}

pub(crate) async fn paged_search_result(
    db: &CveDatabase,
    mut cves: Vec<CveSummary>,
    requested_limit: u64,
) -> Result<CallToolResult, McpError> {
    let has_more = cves.len() > requested_limit as usize;
    cves.truncate(requested_limit as usize);
    let cves = db
        .attach_cve_details(cves)
        .await
        .map_err(|err| mcp_error(err.to_string()))?;
    response::tool_result(json!({
        "has_more": has_more,
        "results": response::summaries_with_detail(cves),
    }))
}

pub(crate) async fn search_by_cwe(
    db: &CveDatabase,
    cwe_ids: &[String],
    state_scope: CveStateScope,
    limit: u64,
    offset: u64,
) -> Result<Vec<CveSummary>, McpError> {
    db.search_cve_summaries_by_cwe_with_state_scope(cwe_ids, state_scope, limit, offset)
        .await
        .map_err(|err| mcp_error(err.to_string()))
}

pub(crate) async fn search_by_product(
    db: &CveDatabase,
    vendor: Option<&str>,
    product: Option<&str>,
    vendor_exact: Option<&str>,
    product_exact: Option<&str>,
    state_scope: CveStateScope,
    limit: u64,
    offset: u64,
) -> Result<Vec<CveSummary>, McpError> {
    db.search_cve_summaries_by_vendor_product_exact_with_state_scope(
        vendor,
        product,
        vendor_exact,
        product_exact,
        state_scope,
        limit,
        offset,
    )
    .await
    .map_err(|err| mcp_error(err.to_string()))
}

pub(crate) async fn search_text(
    db: &CveDatabase,
    query: &str,
    state_scope: CveStateScope,
    limit: u64,
    offset: u64,
) -> Result<Vec<CveSummary>, McpError> {
    db.search_cve_summaries_by_text_with_state_scope(query, state_scope, limit, offset)
        .await
        .map_err(|err| mcp_error(err.to_string()))
}

pub(crate) async fn search_by_cvss(
    db: &CveDatabase,
    min_score: Option<f64>,
    max_score: Option<f64>,
    severity: Option<&str>,
    version: Option<&str>,
    state_scope: CveStateScope,
    limit: u64,
    offset: u64,
) -> Result<Vec<CveSummary>, McpError> {
    db.search_cve_summaries_by_cvss_with_state_scope(
        min_score,
        max_score,
        severity,
        version,
        state_scope,
        limit,
        offset,
    )
    .await
    .map_err(|err| mcp_error(err.to_string()))
}

pub(crate) async fn search_product_by_cvss(
    db: &CveDatabase,
    vendor: Option<&str>,
    product: Option<&str>,
    vendor_exact: Option<&str>,
    product_exact: Option<&str>,
    min_score: Option<f64>,
    severity: Option<&str>,
    state_scope: CveStateScope,
    limit: u64,
    offset: u64,
) -> Result<Vec<CveSummary>, McpError> {
    db.search_cve_summaries_by_product_cvss_exact_with_state_scope(
        vendor,
        product,
        vendor_exact,
        product_exact,
        min_score,
        None,
        severity,
        None,
        state_scope,
        limit,
        offset,
    )
    .await
    .map_err(|err| mcp_error(err.to_string()))
}

pub(crate) async fn search_recent(
    db: &CveDatabase,
    published_since: Option<&str>,
    updated_since: Option<&str>,
    state_scope: CveStateScope,
    limit: u64,
    offset: u64,
) -> Result<Vec<CveSummary>, McpError> {
    db.search_cve_summaries_by_date_with_state_scope(
        published_since,
        updated_since,
        state_scope,
        limit,
        offset,
    )
    .await
    .map_err(|err| mcp_error(err.to_string()))
}

pub(crate) async fn find_cve(
    db: &CveDatabase,
    cve_id: &str,
) -> Result<Option<RawCveStatusRecord>, McpError> {
    db.find_cve_model_by_id(cve_id)
        .await
        .map_err(|err| mcp_error(err.to_string()))
}

pub(crate) async fn find_cve_summary(
    db: &CveDatabase,
    cve_id: &str,
) -> Result<CallToolResult, McpError> {
    let cve = db
        .find_cve_summary_with_detail(cve_id)
        .await
        .map_err(|err| mcp_error(err.to_string()))?;
    response::tool_result(json!(cve.map(response::summary_with_detail)))
}

pub(crate) async fn find_cve_references(
    db: &CveDatabase,
    cve_id: &str,
) -> Result<CallToolResult, McpError> {
    let references = db
        .find_cve_references(cve_id)
        .await
        .map_err(|err| mcp_error(err.to_string()))?;
    response::tool_result(json!(references))
}

pub(crate) async fn database_status(db: &CveDatabase) -> Result<CallToolResult, McpError> {
    let mut status = simd_json::serde::to_owned_value(
        db.database_status_enriched()
            .await
            .map_err(|err| mcp_error(err.to_string()))?,
    )
    .map_err(|err| mcp_error(err.to_string()))?;
    status["source_sync"] = simd_json::serde::to_owned_value(
        db.source_sync_states()
            .await
            .map_err(|err| mcp_error(err.to_string()))?,
    )
    .map_err(|err| mcp_error(err.to_string()))?;
    response::tool_result(json!(status))
}

pub(crate) async fn resolve_identifier(
    db: &CveDatabase,
    id: &str,
) -> Result<CallToolResult, McpError> {
    let result = db
        .resolve_identifier(id)
        .await
        .map_err(|err| mcp_error(err.to_string()))?;
    response::tool_result(json!(result))
}

pub(crate) async fn get_related_identifiers(
    db: &CveDatabase,
    id: &str,
) -> Result<CallToolResult, McpError> {
    let result = db
        .related_edges(id)
        .await
        .map_err(|err| mcp_error(err.to_string()))?;
    response::tool_result(json!(result))
}

pub(crate) async fn get_enriched_cve(
    db: &CveDatabase,
    cve_id: &str,
) -> Result<CallToolResult, McpError> {
    let result = db
        .get_enriched_cve(cve_id)
        .await
        .map_err(|err| mcp_error(err.to_string()))?;
    response::tool_result(json!(result))
}

pub(crate) async fn get_enriched_osv(
    db: &CveDatabase,
    osv_id: &str,
) -> Result<CallToolResult, McpError> {
    let result = db
        .get_enriched_osv(osv_id)
        .await
        .map_err(|err| mcp_error(err.to_string()))?;
    response::tool_result(json!(result))
}

pub(crate) async fn query_package_enriched(
    db: &CveDatabase,
    ecosystem: &str,
    package: &str,
    version: &str,
    purl: Option<&str>,
) -> Result<CallToolResult, McpError> {
    let result = db
        .query_package_enriched(ecosystem, package, version, purl)
        .await
        .map_err(|err| mcp_error(err.to_string()))?;
    response::tool_result(json!(result))
}

pub(crate) async fn known_exploited(
    db: &CveDatabase,
    cve_id: Option<&str>,
) -> Result<CallToolResult, McpError> {
    let entries = db
        .kev_entries(cve_id)
        .await
        .map_err(|err| mcp_error(err.to_string()))?;
    response::tool_result(json!({
        "available": true,
        "cve_id": cve_id,
        "known_exploited": if cve_id.is_some() { !entries.is_empty() } else { false },
        "count": entries.len(),
        "entries": entries,
    }))
}

pub(crate) async fn search_references(
    db: &CveDatabase,
    query: &str,
    state_scope: CveStateScope,
    limit: u64,
    offset: u64,
) -> Result<Vec<CveSummary>, McpError> {
    db.search_cve_summaries_by_reference_text(query, state_scope, limit, offset)
        .await
        .map_err(|err| mcp_error(err.to_string()))
}

pub(crate) async fn search_date_range(
    db: &CveDatabase,
    published_from: Option<&str>,
    published_to: Option<&str>,
    updated_from: Option<&str>,
    updated_to: Option<&str>,
    state_scope: CveStateScope,
    limit: u64,
    offset: u64,
) -> Result<Vec<CveSummary>, McpError> {
    db.search_cve_summaries_by_date_range(
        published_from,
        published_to,
        updated_from,
        updated_to,
        state_scope,
        limit,
        offset,
    )
    .await
    .map_err(|err| mcp_error(err.to_string()))
}

pub(crate) async fn search_id_prefix(
    db: &CveDatabase,
    prefix: &str,
    state_scope: CveStateScope,
    limit: u64,
    offset: u64,
) -> Result<Vec<CveSummary>, McpError> {
    db.search_cve_summaries_by_cve_id_prefix_with_state_scope(prefix, state_scope, limit, offset)
        .await
        .map_err(|err| mcp_error(err.to_string()))
}

pub(crate) async fn search_product_version(
    db: &CveDatabase,
    vendor: Option<&str>,
    product: Option<&str>,
    version: Option<&str>,
    state_scope: CveStateScope,
    limit: u64,
    offset: u64,
) -> Result<Vec<CveSummary>, McpError> {
    db.search_cve_summaries_by_vendor_product_version(
        vendor,
        product,
        version,
        state_scope,
        limit,
        offset,
    )
    .await
    .map_err(|err| mcp_error(err.to_string()))
}

pub(crate) async fn search_cwe_catalog(
    db: &CveDatabase,
    query: Option<&str>,
    limit: u64,
    statuses: &[String],
) -> Result<CallToolResult, McpError> {
    let statuses = if statuses.is_empty() {
        vec![
            "Draft".to_owned(),
            "Incomplete".to_owned(),
            "Usable".to_owned(),
            "Stable".to_owned(),
            "Deprecated".to_owned(),
            "Obsolete".to_owned(),
        ]
    } else {
        statuses.to_owned()
    };
    let entries = db
        .search_cwe_entries(query.unwrap_or_default(), limit, &statuses)
        .await
        .map_err(|err| mcp_error(err.to_string()))?;
    response::tool_result(json!(entries))
}

pub(crate) async fn get_cwe(db: &CveDatabase, cwe_id: i32) -> Result<CallToolResult, McpError> {
    let entry = db
        .get_cwe_entry(cwe_id)
        .await
        .map_err(|err| mcp_error(err.to_string()))?;
    response::tool_result(json!(entry))
}

pub(crate) async fn list_recent_updates(
    db: &CveDatabase,
    since: Option<&str>,
    state_scope: CveStateScope,
    limit: u64,
    offset: u64,
) -> Result<Vec<CveSummary>, McpError> {
    db.list_recent_updates(since, state_scope, limit, offset)
        .await
        .map_err(|err| mcp_error(err.to_string()))
}

pub(crate) async fn apply_updates(
    db: &CveDatabase,
    zip: Option<String>,
    max_chunks: Option<usize>,
    osv_all: bool,
    osv_prefixes: &[String],
) -> Result<CallToolResult, McpError> {
    db.initialize_schema()
        .await
        .map_err(|err| mcp_error(format!("failed to initialize schema: {err}")))?;

    let applied = apply_delta_updates(db, zip.map(PathBuf::from), max_chunks)
        .await
        .map_err(mcp_error)?;

    let osv_additions = OsvImportSelection::update_additions(osv_all, osv_prefixes);
    sync_all_enrichment_sources_after_update(db, "mcp update_db", osv_additions.as_ref())
        .await
        .map_err(mcp_error)?;

    let graph = db
        .rebuild_identifier_graph()
        .await
        .map_err(|err| mcp_error(format!("failed to rebuild identifier graph: {err}")))?;

    response::tool_result(json!({
        "updated": true,
        "applied_assets": applied.into_iter().map(|path| path.display().to_string()).collect::<Vec<_>>(),
        "identifier_graph": graph,
    }))
}
