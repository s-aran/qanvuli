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
        description = "Search CVEs by CWE ID. Set full_description=true to replace previews with complete English descriptions."
    )]
    pub(crate) async fn search_by_cwe(
        &self,
        Parameters(args): Parameters<CweArgs>,
    ) -> Result<CallToolResult, McpError> {
        let db = self.db.get().await?;
        let include_rejected = args.include_rejected;
        let full_description = args.full_description.unwrap_or(false);
        let limit = limit(args.limit);
        let offset = offset(args.offset);
        let cves = db::search_by_cwe(
            db,
            &args.search_values(),
            state_scope(include_rejected),
            limit + 1,
            offset,
        )
        .await?;
        db::paged_search_result(db, cves, limit, full_description).await
    }

    #[tool(
        description = "Search CVEs by affected vendor or product. Exact fields take precedence over substring fields; exclude_collection omits wordpress.org collections."
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
            args.vendor_exact.as_deref(),
            args.product_exact.as_deref(),
            args.exclude_collection.unwrap_or(false),
            state_scope(args.include_rejected),
            limit(args.limit) + 1,
            offset(args.offset),
        )
        .await?;
        db::paged_search_result(
            db,
            cves,
            limit(args.limit),
            args.full_description.unwrap_or(false),
        )
        .await
    }

    #[tool(description = "Search CVE IDs, titles, and English descriptions.")]
    pub(crate) async fn search_text(
        &self,
        Parameters(args): Parameters<TextArgs>,
    ) -> Result<CallToolResult, McpError> {
        let db = self.db.get().await?;
        let cves = db::search_text(
            db,
            &args.query,
            state_scope(args.include_rejected),
            limit(args.limit) + 1,
            offset(args.offset),
        )
        .await?;
        db::paged_search_result(
            db,
            cves,
            limit(args.limit),
            args.full_description.unwrap_or(false),
        )
        .await
    }

    #[tool(description = "Search CVEs by CVSS score, severity, or version.")]
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
            limit(args.limit) + 1,
            offset(args.offset),
        )
        .await?;
        db::paged_search_result(
            db,
            cves,
            limit(args.limit),
            args.full_description.unwrap_or(false),
        )
        .await
    }

    #[tool(description = "Search CVEs by affected vendor or product and minimum CVSS score.")]
    pub(crate) async fn search_product_by_cvss(
        &self,
        Parameters(args): Parameters<ProductCvssArgs>,
    ) -> Result<CallToolResult, McpError> {
        let db = self.db.get().await?;
        let cves = db::search_product_by_cvss(
            db,
            args.vendor.as_deref(),
            args.product.as_deref(),
            args.vendor_exact.as_deref(),
            args.product_exact.as_deref(),
            args.min_score,
            args.severity.as_deref(),
            state_scope(args.include_rejected),
            limit(args.limit) + 1,
            offset(args.offset),
        )
        .await?;
        db::paged_search_result(
            db,
            cves,
            limit(args.limit),
            args.full_description.unwrap_or(false),
        )
        .await
    }

    #[tool(
        description = "Search CVEs by FIRST EPSS score or percentile, ordered by highest EPSS. Returns lightweight risk rows with KEV flag, EPSS, and max CVSS for triage."
    )]
    pub(crate) async fn search_by_epss(
        &self,
        Parameters(args): Parameters<EpssArgs>,
    ) -> Result<CallToolResult, McpError> {
        let db = self.db.get().await?;
        let limit = limit(args.limit);
        db::search_by_epss(
            db,
            args.min_score,
            args.min_percentile,
            state_scope(args.include_rejected),
            limit,
            offset(args.offset),
        )
        .await
    }

    #[tool(description = "Search CVEs by ISO-8601 publication or update time.")]
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
            limit(args.limit) + 1,
            offset(args.offset),
        )
        .await?;
        db::paged_search_result(
            db,
            cves,
            limit(args.limit),
            args.full_description.unwrap_or(false),
        )
        .await
    }

    #[tool(
        description = "Fetch one exact CVE record as a lightweight structured summary with CWE, CVSS, affected product/version data, and no raw JSON."
    )]
    pub(crate) async fn get_cve_summary(
        &self,
        Parameters(args): Parameters<GetCveArgs>,
    ) -> Result<CallToolResult, McpError> {
        let db = self.db.get().await?;
        db::find_cve_summary(db, &args.cve_id).await
    }

    #[tool(
        description = "Fetch reference URLs, names, and tags for one exact CVE ID without returning the full raw CVE JSON."
    )]
    pub(crate) async fn get_cve_references(
        &self,
        Parameters(args): Parameters<GetCveArgs>,
    ) -> Result<CallToolResult, McpError> {
        let db = self.db.get().await?;
        db::find_cve_references(db, &args.cve_id).await
    }

    #[tool(
        description = "Search CVEs by reference URL, reference name, or reference tag text. Useful for finding vendor advisories, patches, commits, and exploit references."
    )]
    pub(crate) async fn search_references(
        &self,
        Parameters(args): Parameters<ReferenceSearchArgs>,
    ) -> Result<CallToolResult, McpError> {
        let db = self.db.get().await?;
        let limit = limit(args.limit);
        let cves = db::search_references(
            db,
            &args.query,
            state_scope(args.include_rejected),
            limit + 1,
            offset(args.offset),
        )
        .await?;
        db::paged_search_result(db, cves, limit, args.full_description.unwrap_or(false)).await
    }

    #[tool(
        description = "Return local database status including CVE/CWE counts, OSV/KEV/EPSS counts, identifier graph counts, and source sync state."
    )]
    pub(crate) async fn get_database_status(&self) -> Result<CallToolResult, McpError> {
        let db = self.db.get().await?;
        db::database_status(db).await
    }

    #[tool(description = "Resolve a vulnerability identifier through the local alias graph.")]
    pub(crate) async fn resolve_identifier(
        &self,
        Parameters(args): Parameters<ResolveIdentifierArgs>,
    ) -> Result<CallToolResult, McpError> {
        let db = self.db.get().await?;
        db::resolve_identifier(db, &args.id).await
    }

    #[tool(
        description = "Return local identifier graph edges for one vulnerability identifier, including source and evidence JSON."
    )]
    pub(crate) async fn get_related_identifiers(
        &self,
        Parameters(args): Parameters<ResolveIdentifierArgs>,
    ) -> Result<CallToolResult, McpError> {
        let db = self.db.get().await?;
        db::get_related_identifiers(db, &args.id).await
    }

    #[tool(
        description = "Fetch one CVE with local OSV aliases, affected packages, CISA KEV, FIRST EPSS, CVSS/CWE details, evidence, and source sync status."
    )]
    pub(crate) async fn get_enriched_cve(
        &self,
        Parameters(args): Parameters<GetEnrichedCveArgs>,
    ) -> Result<CallToolResult, McpError> {
        let db = self.db.get().await?;
        db::get_enriched_cve(db, &args.cve_id).await
    }

    #[tool(
        description = "Batch-check CVE IDs for local CISA KEV listing, FIRST EPSS, and max CVSS. Accepts up to 200 CVE IDs and returns compact risk rows in input order."
    )]
    pub(crate) async fn lookup_cve_risk(
        &self,
        Parameters(args): Parameters<CveRiskLookupArgs>,
    ) -> Result<CallToolResult, McpError> {
        let db = self.db.get().await?;
        db::lookup_cve_risk(db, &args.cve_ids, args.verbosity.as_deref()).await
    }

    #[tool(description = "Fetch one local OSV advisory summary by OSV/GHSA/RUSTSEC/PYSEC/GO ID.")]
    pub(crate) async fn get_enriched_osv(
        &self,
        Parameters(args): Parameters<GetEnrichedOsvArgs>,
    ) -> Result<CallToolResult, McpError> {
        let db = self.db.get().await?;
        db::get_enriched_osv(db, &args.osv_id).await
    }

    #[tool(
        description = "Evaluate a package version against local OSV data and attach CVE, KEV, EPSS, and priority data. Set include_evidence=true for match details."
    )]
    pub(crate) async fn query_package_enriched(
        &self,
        Parameters(args): Parameters<QueryPackageEnrichedArgs>,
    ) -> Result<CallToolResult, McpError> {
        let db = self.db.get().await?;
        db::query_package_enriched(
            db,
            &args.ecosystem,
            &args.package,
            &args.version,
            args.purl.as_deref(),
            args.status.as_deref(),
            limit(args.limit),
            offset(args.offset),
            args.include_evidence.unwrap_or(false),
        )
        .await
    }

    #[tool(
        description = "Batch-query up to 200 package/version tuples. Set verbosity='summary' to omit verbose findings. Set include_fixed=true for OSV fixed-version candidates and include_enrichment=true for per-CVE KEV/EPSS/CVSS rows. Status defaults to affected. PyPI names follow PEP 503 normalization. Evidence is omitted by default; set include_evidence=true for verbose match evidence."
    )]
    pub(crate) async fn query_packages_enriched(
        &self,
        Parameters(args): Parameters<QueryPackagesEnrichedArgs>,
    ) -> Result<CallToolResult, McpError> {
        let db = self.db.get().await?;
        db::query_packages_enriched(
            db,
            args.packages,
            args.status.as_deref(),
            args.include_evidence.unwrap_or(false),
            args.verbosity.as_deref(),
            args.include_fixed.unwrap_or(false),
            args.include_enrichment.unwrap_or(false),
        )
        .await
    }

    #[tool(
        description = "Search CVEs by explicit published/updated date ranges using ISO-8601 timestamp strings."
    )]
    pub(crate) async fn search_by_date_range(
        &self,
        Parameters(args): Parameters<DateRangeArgs>,
    ) -> Result<CallToolResult, McpError> {
        let db = self.db.get().await?;
        let limit = limit(args.limit);
        let cves = db::search_date_range(
            db,
            args.published_from.as_deref(),
            args.published_to.as_deref(),
            args.updated_from.as_deref(),
            args.updated_to.as_deref(),
            state_scope(args.include_rejected),
            limit + 1,
            offset(args.offset),
        )
        .await?;
        db::paged_search_result(db, cves, limit, args.full_description.unwrap_or(false)).await
    }

    #[tool(description = "Search CVEs by CVE ID prefix such as CVE-2026- or CVE-2026-12.")]
    pub(crate) async fn search_by_id_prefix(
        &self,
        Parameters(args): Parameters<IdPrefixArgs>,
    ) -> Result<CallToolResult, McpError> {
        let db = self.db.get().await?;
        let limit = limit(args.limit);
        let cves = db::search_id_prefix(
            db,
            &args.prefix,
            state_scope(args.include_rejected),
            limit + 1,
            offset(args.offset),
        )
        .await?;
        db::paged_search_result(db, cves, limit, args.full_description.unwrap_or(false)).await
    }

    #[tool(description = "Search the local CWE catalog by CWE ID or description text.")]
    pub(crate) async fn search_cwe_catalog(
        &self,
        Parameters(args): Parameters<CweCatalogArgs>,
    ) -> Result<CallToolResult, McpError> {
        let db = self.db.get().await?;
        let capec_id = args
            .capec_id
            .map(|value| cwe_arg_to_i32_with_prefix(value, "CAPEC"))
            .transpose()?;
        db::search_cwe_catalog(
            db,
            args.query.as_deref(),
            limit(args.limit),
            &args.statuses,
            capec_id,
            offset(args.offset),
        )
        .await
    }

    #[tool(description = "Fetch one CWE catalog entry by CWE ID.")]
    pub(crate) async fn get_cwe(
        &self,
        Parameters(args): Parameters<GetCweArgs>,
    ) -> Result<CallToolResult, McpError> {
        let db = self.db.get().await?;
        let cwe_id = cwe_arg_to_i32(args.cwe_id)?;
        db::get_cwe(db, cwe_id).await
    }

    #[tool(
        description = "Search the local CAPEC catalog by ID, name, description, status, type, or related CWE."
    )]
    pub(crate) async fn search_capec_catalog(
        &self,
        Parameters(args): Parameters<CapecCatalogArgs>,
    ) -> Result<CallToolResult, McpError> {
        let db = self.db.get().await?;
        db::search_capec_catalog(db, args).await
    }

    #[tool(
        description = "Fetch one CAPEC entry with optional references, taxonomy details, and history."
    )]
    pub(crate) async fn get_capec(
        &self,
        Parameters(args): Parameters<GetCapecArgs>,
    ) -> Result<CallToolResult, McpError> {
        let db = self.db.get().await?;
        db::get_capec(db, args).await
    }

    #[tool(
        description = "Explain which fields in one CVE match an optional query. Returns lightweight evidence from summary, CWE, CVSS, affected product/version, and references."
    )]
    pub(crate) async fn explain_match(
        &self,
        Parameters(args): Parameters<ExplainMatchArgs>,
    ) -> Result<CallToolResult, McpError> {
        let db = self.db.get().await?;
        let cve = db
            .find_cve_summary_with_detail(&args.cve_id)
            .await
            .map_err(|err| crate::common::error::mcp_error(err.to_string()))?;
        let references = db
            .find_cve_references(&args.cve_id)
            .await
            .map_err(|err| crate::common::error::mcp_error(err.to_string()))?;
        response::explain_match(args.query.as_deref(), cve, references)
    }

    #[tool(
        description = "List CVEs updated on or after an optional ISO-8601 timestamp, ordered by publication date for triage."
    )]
    pub(crate) async fn list_recent_updates(
        &self,
        Parameters(args): Parameters<RecentUpdatesArgs>,
    ) -> Result<CallToolResult, McpError> {
        let db = self.db.get().await?;
        let limit = limit(args.limit);
        let cves = db::list_recent_updates(
            db,
            args.since.as_deref(),
            state_scope(args.include_rejected),
            limit + 1,
            offset(args.offset),
        )
        .await?;
        db::paged_search_result(db, cves, limit, args.full_description.unwrap_or(false)).await
    }

    #[tool(
        description = "Return locally synced CISA KEV known-exploited-vulnerability entries. With cve_id, reports whether that CVE is KEV-listed; without cve_id, returns all local KEV entries."
    )]
    pub(crate) async fn search_known_exploited(
        &self,
        Parameters(args): Parameters<KnownExploitedArgs>,
    ) -> Result<CallToolResult, McpError> {
        let db = self.db.get().await?;
        db::known_exploited(
            db,
            args.cve_id.as_deref(),
            limit(args.limit),
            offset(args.offset),
        )
        .await
    }

    #[tool(
        description = "Return the original CVE JSON for an exact CVE ID. Prefer search tools unless provider-specific fields are required."
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
        description = "Apply a local CVE delta or download current updates, then refresh enrichment data. This changes the database and may access upstream feeds."
    )]
    pub(crate) async fn update_db(
        &self,
        Parameters(args): Parameters<UpdateDbArgs>,
    ) -> Result<CallToolResult, McpError> {
        let db = self.db.get().await?;
        db::apply_updates(
            db,
            args.zip,
            args.max_chunks,
            args.osv_all.unwrap_or(false),
            args.osv_prefixes.as_deref().unwrap_or(&[]),
        )
        .await
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

fn cwe_arg_to_i32(value: CweArgValue) -> Result<i32, McpError> {
    cwe_arg_to_i32_with_prefix(value, "CWE")
}

fn cwe_arg_to_i32_with_prefix(value: CweArgValue, prefix: &str) -> Result<i32, McpError> {
    let value = value.into_search_value();
    let number = value
        .trim()
        .trim_start_matches(&format!("{prefix}-"))
        .trim_start_matches(prefix)
        .parse::<i32>()
        .map_err(|err| {
            crate::common::error::mcp_error(format!("invalid {prefix} ID `{value}`: {err}"))
        })?;
    Ok(number)
}
