use crate::{common::error::mcp_error, response};
use qanvuli_app_commands::common::apply_delta_updates;
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

pub(crate) async fn search_result(
    db: &CveDatabase,
    cves: Vec<CveSummary>,
) -> Result<CallToolResult, McpError> {
    let cves = db
        .attach_cve_details(cves)
        .await
        .map_err(|err| mcp_error(err.to_string()))?;
    response::tool_result(json!(response::summaries_with_detail(cves)))
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

pub(crate) async fn apply_updates(
    db: &CveDatabase,
    zip: Option<String>,
    max_chunks: Option<usize>,
) -> Result<CallToolResult, McpError> {
    db.initialize_schema()
        .await
        .map_err(|err| mcp_error(format!("failed to initialize schema: {err}")))?;

    let applied = apply_delta_updates(db, zip.map(PathBuf::from), max_chunks)
        .await
        .map_err(mcp_error)?;

    response::tool_result(json!({
        "updated": true,
        "applied_assets": applied.into_iter().map(|path| path.display().to_string()).collect::<Vec<_>>(),
    }))
}
