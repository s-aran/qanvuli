use super::CveSearchServer;
use crate::{args::*, common::params::*, db, response};
use rmcp::{
    ErrorData as McpError, ServerHandler,
    handler::server::wrapper::Parameters,
    model::{CallToolResult, ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router,
};
use simd_json::json;

#[tool_router]
impl CveSearchServer {
    #[tool(
        description = "Search CVEs by vulnerability type using CWE IDs such as CWE-79, CWE79, or 79. Results include cve_id, state, published_at, updated_at, title, complete English description, CWE entries, CVSS metrics, and affected vendor/product/version data. Results do not include raw CVE JSON; use get_cve only when raw CVE JSON is explicitly required."
    )]
    pub(crate) async fn search_by_cwe(
        &self,
        Parameters(args): Parameters<CweArgs>,
    ) -> Result<CallToolResult, McpError> {
        let db = self.db.get().await?;
        let include_rejected = args.include_rejected;
        let limit = limit(args.limit);
        let offset = offset(args.offset);
        let cves = db::search_by_cwe(
            db,
            &args.search_values(),
            state_scope(include_rejected),
            limit,
            offset,
        )
        .await?;
        db::search_result(db, cves).await
    }

    #[tool(
        description = "Search CVEs by affected vendor and/or product name. Results include cve_id, state, published_at, updated_at, title, complete English description, CWE entries, CVSS metrics, and affected vendor/product/version data. Results do not include raw CVE JSON; use get_cve only when raw CVE JSON is explicitly required."
    )]
    pub(crate) async fn search_by_product(
        &self,
        Parameters(args): Parameters<ProductArgs>,
    ) -> Result<CallToolResult, McpError> {
        let db = self.db.get().await?;
        let cves = db::search_by_product(
            db,
            args.vendor.as_deref(),
            args.product.as_deref(),
            state_scope(args.include_rejected),
            limit(args.limit),
            offset(args.offset),
        )
        .await?;
        db::search_result(db, cves).await
    }

    #[tool(
        description = "Search CVEs by CVE ID, title, or English description text. Results include cve_id, state, published_at, updated_at, title, complete English description, CWE entries, CVSS metrics, and affected vendor/product/version data. Results do not include raw CVE JSON; use get_cve only when raw CVE JSON is explicitly required."
    )]
    pub(crate) async fn search_text(
        &self,
        Parameters(args): Parameters<TextArgs>,
    ) -> Result<CallToolResult, McpError> {
        let db = self.db.get().await?;
        let cves = db::search_text(
            db,
            &args.query,
            state_scope(args.include_rejected),
            limit(args.limit),
            offset(args.offset),
        )
        .await?;
        db::search_result(db, cves).await
    }

    #[tool(
        description = "Search CVEs by CVSS score, severity, and/or CVSS version. Results include cve_id, state, published_at, updated_at, title, complete English description, CWE entries, CVSS metrics, and affected vendor/product/version data. Results do not include raw CVE JSON; use get_cve only when raw CVE JSON is explicitly required."
    )]
    pub(crate) async fn search_by_cvss(
        &self,
        Parameters(args): Parameters<CvssArgs>,
    ) -> Result<CallToolResult, McpError> {
        let db = self.db.get().await?;
        let cves = db::search_by_cvss(
            db,
            args.min_score,
            args.max_score,
            args.severity.as_deref(),
            args.version.as_deref(),
            state_scope(args.include_rejected),
            limit(args.limit),
            offset(args.offset),
        )
        .await?;
        db::search_result(db, cves).await
    }

    #[tool(
        description = "Search high-risk CVEs for a specific affected vendor/product. Results include cve_id, state, published_at, updated_at, title, complete English description, CWE entries, CVSS metrics, and affected vendor/product/version data. Results do not include raw CVE JSON; use get_cve only when raw CVE JSON is explicitly required."
    )]
    pub(crate) async fn search_product_by_cvss(
        &self,
        Parameters(args): Parameters<ProductCvssArgs>,
    ) -> Result<CallToolResult, McpError> {
        let db = self.db.get().await?;
        let cves = db::search_product_by_cvss(
            db,
            args.vendor.as_deref(),
            args.product.as_deref(),
            args.min_score,
            args.severity.as_deref(),
            state_scope(args.include_rejected),
            limit(args.limit),
            offset(args.offset),
        )
        .await?;
        db::search_result(db, cves).await
    }

    #[tool(
        description = "Search recently published and/or recently updated CVEs using ISO-8601 timestamps. Results include cve_id, state, published_at, updated_at, title, complete English description, CWE entries, CVSS metrics, and affected vendor/product/version data. Results do not include raw CVE JSON; use get_cve only when raw CVE JSON is explicitly required."
    )]
    pub(crate) async fn search_recent(
        &self,
        Parameters(args): Parameters<DateArgs>,
    ) -> Result<CallToolResult, McpError> {
        let db = self.db.get().await?;
        let cves = db::search_recent(
            db,
            args.published_since.as_deref(),
            args.updated_since.as_deref(),
            state_scope(args.include_rejected),
            limit(args.limit),
            offset(args.offset),
        )
        .await?;
        db::search_result(db, cves).await
    }

    #[tool(
        description = "Fetch one exact CVE record by CVE ID. Returns the raw CVE JSON stored in the local database, including cveMetadata and containers, so this is token-heavy. Prefer search_* tools for triage, affected version checks, CVSS, CWE, descriptions, published_at, and updated_at; use get_cve only when raw CVE JSON fields not exposed by search_* are explicitly required."
    )]
    pub(crate) async fn get_cve(
        &self,
        Parameters(args): Parameters<GetCveArgs>,
    ) -> Result<CallToolResult, McpError> {
        let db = self.db.get().await?;
        let cve = db::find_cve(db, &args.cve_id).await?;
        response::tool_result(json!(cve.map(response::full_cve)))
    }

    #[tool(
        description = "Update the local CVE database. With zip, applies that local CVE delta zip. Without zip, downloads and applies the applicable CVE delta archives according to local update history. Returns updated=true and applied_assets, the list of archive paths applied. This mutates the local database and may access GitHub."
    )]
    pub(crate) async fn update_db(
        &self,
        Parameters(args): Parameters<UpdateDbArgs>,
    ) -> Result<CallToolResult, McpError> {
        let db = self.db.get().await?;
        db::apply_updates(db, args.zip, args.max_chunks).await
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
