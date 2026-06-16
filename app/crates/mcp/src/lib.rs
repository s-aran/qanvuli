mod json_schemars;
mod utils;

use crate::{json_schemars::*, utils::*};
use qanvuli_app_commands::common::apply_delta_updates;
use qanvuli_db::{CveDatabase, CveSummary};
use rmcp::{
    ErrorData as McpError, ServerHandler, ServiceExt,
    handler::server::wrapper::Parameters,
    model::{CallToolResult, Content, ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router,
    transport::stdio,
};
use simd_json::{OwnedValue as Value, json};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::OnceCell;

#[derive(Clone)]
struct CveSearchServer {
    db_url: String,
    db: Arc<OnceCell<CveDatabase>>,
}

impl CveSearchServer {
    fn new(db_url: String) -> Self {
        Self {
            db_url,
            db: Arc::new(OnceCell::new()),
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
        let text = simd_json::to_string_pretty(&value)
            .map_err(|err| mcp_error(format!("failed to encode tool result: {err}")))?;
        Ok(CallToolResult::success(vec![Content::text(text)]))
    }

    async fn search_result(
        db: &CveDatabase,
        cves: Vec<CveSummary>,
    ) -> Result<CallToolResult, McpError> {
        let cves = db
            .attach_cve_details(cves)
            .await
            .map_err(|err| mcp_error(err.to_string()))?;
        Self::result(json!(summaries_with_detail(cves)))
    }
}

#[tool_router]
impl CveSearchServer {
    #[tool(
        description = "Search CVEs by vulnerability type using CWE IDs such as CWE-79, CWE79, or 79. Results include complete descriptions but not raw JSON; use get_cve only when raw CVE JSON is required."
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
        Self::search_result(db, cves).await
    }

    #[tool(
        description = "Search CVEs by affected vendor and/or product name. Results include complete descriptions but not raw JSON; use get_cve only when raw CVE JSON is required."
    )]
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
        Self::search_result(db, cves).await
    }

    #[tool(
        description = "Search CVEs by CVE ID, title, or English description text. Results include complete descriptions but not raw JSON; use get_cve only when raw CVE JSON is required."
    )]
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
        Self::search_result(db, cves).await
    }

    #[tool(
        description = "Search CVEs by CVSS score, severity, and/or CVSS version. Results include complete descriptions but not raw JSON; use get_cve only when raw CVE JSON is required."
    )]
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
        Self::search_result(db, cves).await
    }

    #[tool(
        description = "Search high-risk CVEs for a specific affected vendor/product. Results include complete descriptions but not raw JSON; use get_cve only when raw CVE JSON is required."
    )]
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
        Self::search_result(db, cves).await
    }

    #[tool(
        description = "Search recently published and/or recently updated CVEs using ISO-8601 timestamps. Results include complete descriptions but not raw JSON; use get_cve only when raw CVE JSON is required."
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
        Self::search_result(db, cves).await
    }

    #[tool(
        description = "Fetch one CVE record by CVE ID, including raw JSON. This is token-heavy; prefer search_* tools unless raw CVE JSON is explicitly required."
    )]
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

        let applied = apply_delta_updates(db, args.zip.map(PathBuf::from), args.max_chunks)
            .await
            .map_err(mcp_error)?;

        Self::result(json!({
            "updated": true,
            "applied_assets": applied.into_iter().map(|path| path.display().to_string()).collect::<Vec<_>>(),
        }))
    }
}

#[tool_handler]
impl ServerHandler for CveSearchServer {
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::default();
        info.instructions = Some("Search and update the local qanvuli CVE database.".into());
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info
    }
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

fn mcp_error(message: impl Into<String>) -> McpError {
    McpError::internal_error(message.into(), None)
}
