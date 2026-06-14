use super::common::{IngestMode, ReleaseAssetKind, download_latest_asset, ingest_zip};
use qanvuli_db::{CveDatabase, CveStateScope, CveSummary, cve_state_label};
use qanvuli_models::RawCveStatusRecord;
use rmcp::{
    ErrorData as McpError, ServerHandler, ServiceExt,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{CallToolResult, Content, ServerCapabilities, ServerInfo},
    schemars, tool, tool_handler, tool_router,
    transport::stdio,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::OnceCell;

#[derive(Clone)]
struct CveSearchServer {
    db_url: String,
    db: Arc<OnceCell<CveDatabase>>,
    tool_router: ToolRouter<Self>,
}

impl CveSearchServer {
    fn new(db_url: String) -> Self {
        Self {
            db_url,
            db: Arc::new(OnceCell::new()),
            tool_router: Self::tool_router(),
        }
    }

    async fn db(&self) -> Result<&CveDatabase, McpError> {
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

    fn result(value: Value) -> Result<CallToolResult, McpError> {
        let text = serde_json::to_string_pretty(&value)
            .map_err(|err| mcp_error(format!("failed to encode tool result: {err}")))?;
        Ok(CallToolResult::success(vec![Content::text(text)]))
    }
}

#[tool_router]
impl CveSearchServer {
    #[tool(
        description = "Search CVEs by vulnerability type using CWE IDs such as CWE-79, CWE79, or 79."
    )]
    async fn search_by_cwe(
        &self,
        Parameters(args): Parameters<CweArgs>,
    ) -> Result<CallToolResult, McpError> {
        let db = self.db().await?;
        let limit = limit(args.limit);
        let offset = offset(args.offset);
        let state_scope = state_scope(args.include_rejected);
        let cwe_ids = args.search_values();
        let cves = db
            .search_cve_summaries_by_cwe_with_state_scope(&cwe_ids, state_scope, limit, offset)
            .await
            .map_err(|err| mcp_error(err.to_string()))?;
        Self::result(json!(summaries(cves)))
    }

    #[tool(description = "Search CVEs by affected vendor and/or product name.")]
    async fn search_by_product(
        &self,
        Parameters(args): Parameters<ProductArgs>,
    ) -> Result<CallToolResult, McpError> {
        let db = self.db().await?;
        let cves = db
            .search_cve_summaries_by_vendor_product_with_state_scope(
                args.vendor.as_deref(),
                args.product.as_deref(),
                state_scope(args.include_rejected),
                limit(args.limit),
                offset(args.offset),
            )
            .await
            .map_err(|err| mcp_error(err.to_string()))?;
        Self::result(json!(summaries(cves)))
    }

    #[tool(description = "Search CVEs by CVE ID, title, or English description text.")]
    async fn search_text(
        &self,
        Parameters(args): Parameters<TextArgs>,
    ) -> Result<CallToolResult, McpError> {
        let db = self.db().await?;
        let cves = db
            .search_cve_summaries_by_text_with_state_scope(
                &args.query,
                state_scope(args.include_rejected),
                limit(args.limit),
                offset(args.offset),
            )
            .await
            .map_err(|err| mcp_error(err.to_string()))?;
        Self::result(json!(summaries(cves)))
    }

    #[tool(description = "Search CVEs by CVSS score, severity, and/or CVSS version.")]
    async fn search_by_cvss(
        &self,
        Parameters(args): Parameters<CvssArgs>,
    ) -> Result<CallToolResult, McpError> {
        let db = self.db().await?;
        let cves = db
            .search_cve_summaries_by_cvss_with_state_scope(
                args.min_score,
                args.max_score,
                args.severity.as_deref(),
                args.version.as_deref(),
                state_scope(args.include_rejected),
                limit(args.limit),
                offset(args.offset),
            )
            .await
            .map_err(|err| mcp_error(err.to_string()))?;
        Self::result(json!(summaries(cves)))
    }

    #[tool(description = "Search high-risk CVEs for a specific affected vendor/product.")]
    async fn search_product_by_cvss(
        &self,
        Parameters(args): Parameters<ProductCvssArgs>,
    ) -> Result<CallToolResult, McpError> {
        let db = self.db().await?;
        let cves = db
            .search_cve_summaries_by_product_cvss_with_state_scope(
                args.vendor.as_deref(),
                args.product.as_deref(),
                args.min_score,
                args.severity.as_deref(),
                state_scope(args.include_rejected),
                limit(args.limit),
                offset(args.offset),
            )
            .await
            .map_err(|err| mcp_error(err.to_string()))?;
        Self::result(json!(summaries(cves)))
    }

    #[tool(
        description = "Search recently published and/or recently updated CVEs using ISO-8601 timestamps."
    )]
    async fn search_recent(
        &self,
        Parameters(args): Parameters<DateArgs>,
    ) -> Result<CallToolResult, McpError> {
        let db = self.db().await?;
        let cves = db
            .search_cve_summaries_by_date_with_state_scope(
                args.published_since.as_deref(),
                args.updated_since.as_deref(),
                state_scope(args.include_rejected),
                limit(args.limit),
                offset(args.offset),
            )
            .await
            .map_err(|err| mcp_error(err.to_string()))?;
        Self::result(json!(summaries(cves)))
    }

    #[tool(description = "Fetch one CVE record by CVE ID, including raw JSON.")]
    async fn get_cve(
        &self,
        Parameters(args): Parameters<GetCveArgs>,
    ) -> Result<CallToolResult, McpError> {
        let db = self.db().await?;
        let cve = db
            .find_cve_model_by_id(&args.cve_id)
            .await
            .map_err(|err| mcp_error(err.to_string()))?;
        Self::result(json!(cve.map(full_cve)))
    }

    #[tool(
        description = "Update the CVE database by applying a delta CVE zip. If no zip is provided, the latest delta zip is downloaded from GitHub."
    )]
    async fn update_db(
        &self,
        Parameters(args): Parameters<UpdateDbArgs>,
    ) -> Result<CallToolResult, McpError> {
        let db = self.db().await?;
        db.initialize_schema()
            .await
            .map_err(|err| mcp_error(format!("failed to initialize schema: {err}")))?;

        let asset_path = if let Some(zip) = args.zip {
            PathBuf::from(zip)
        } else {
            download_latest_asset(ReleaseAssetKind::Delta)
                .await
                .map_err(mcp_error)?
        };

        ingest_zip(
            db,
            "delta",
            &asset_path,
            IngestMode::Upsert,
            args.max_chunks,
        )
        .await;

        Self::result(json!({
            "updated": true,
            "asset": asset_path.display().to_string(),
        }))
    }
}

#[tool_handler]
impl ServerHandler for CveSearchServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            instructions: Some("Search and update the local qanvuli CVE database.".into()),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            ..Default::default()
        }
    }
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct CweArgs {
    #[serde(default)]
    cwe_ids: Vec<CweArgValue>,
    cwe_id: Option<CweArgValue>,
    limit: Option<u64>,
    offset: Option<u64>,
    include_rejected: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
enum CweArgValue {
    Number(i32),
    String(String),
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ProductArgs {
    vendor: Option<String>,
    product: Option<String>,
    limit: Option<u64>,
    offset: Option<u64>,
    include_rejected: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct TextArgs {
    query: String,
    limit: Option<u64>,
    offset: Option<u64>,
    include_rejected: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct GetCveArgs {
    cve_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct CvssArgs {
    min_score: Option<f64>,
    max_score: Option<f64>,
    severity: Option<String>,
    version: Option<String>,
    limit: Option<u64>,
    offset: Option<u64>,
    include_rejected: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ProductCvssArgs {
    vendor: Option<String>,
    product: Option<String>,
    min_score: Option<f64>,
    severity: Option<String>,
    limit: Option<u64>,
    offset: Option<u64>,
    include_rejected: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct DateArgs {
    published_since: Option<String>,
    updated_since: Option<String>,
    limit: Option<u64>,
    offset: Option<u64>,
    include_rejected: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct UpdateDbArgs {
    zip: Option<String>,
    max_chunks: Option<usize>,
}

pub fn run(db_url: String) -> Result<(), String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| format!("failed to build tokio runtime: {err}"))?;

    runtime.block_on(async move {
        let service = CveSearchServer::new(db_url)
            .serve(stdio())
            .await
            .map_err(|err| format!("failed to serve MCP over stdio: {err}"))?;
        service
            .waiting()
            .await
            .map_err(|err| format!("MCP server failed: {err}"))?;
        Ok(())
    })
}

impl CweArgs {
    fn search_values(self) -> Vec<String> {
        let mut values = self
            .cwe_ids
            .into_iter()
            .map(CweArgValue::into_search_value)
            .collect::<Vec<_>>();
        if let Some(cwe_id) = self.cwe_id {
            values.push(cwe_id.into_search_value());
        }
        values
    }
}

impl CweArgValue {
    fn into_search_value(self) -> String {
        match self {
            Self::Number(value) => value.to_string(),
            Self::String(value) => value,
        }
    }
}

fn limit(value: Option<u64>) -> u64 {
    value.unwrap_or(10).clamp(1, 25)
}

fn offset(value: Option<u64>) -> u64 {
    value.unwrap_or(0)
}

fn state_scope(include_rejected: Option<bool>) -> CveStateScope {
    if include_rejected.unwrap_or(false) {
        CveStateScope::IncludeRejected
    } else {
        CveStateScope::PublishedOnly
    }
}

fn summaries(cves: Vec<CveSummary>) -> Vec<Value> {
    cves.into_iter().map(summary).collect()
}

fn summary(cve: CveSummary) -> Value {
    json!({
        "cve_id": cve.cve_id,
        "state": cve_state_label(cve.state),
        "published_at": cve.published_at,
        "updated_at": cve.updated_at,
        "title": cve.title,
        "description_preview": cve.description_en.as_deref().map(preview),
    })
}

fn full_cve(cve: RawCveStatusRecord) -> Value {
    cve.into_parts().1
}

fn preview(value: &str) -> String {
    let compact = value.split_whitespace().collect::<Vec<_>>().join(" ");
    let max_chars = 500;

    if compact.chars().count() <= max_chars {
        compact
    } else {
        let mut truncated = compact.chars().take(max_chars).collect::<String>();
        truncated.push_str("...");
        truncated
    }
}

fn mcp_error(message: impl Into<String>) -> McpError {
    McpError::internal_error(message.into(), None)
}
