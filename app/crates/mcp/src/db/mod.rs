#![allow(clippy::too_many_arguments)]

use crate::{common::error::mcp_error, response};
use qanvuli_app_commands::common::{
    OsvImportSelection, apply_delta_updates, redact_database_url,
    sync_all_enrichment_sources_after_update,
};
use qanvuli_core::database::{
    CveDatabase, CveRiskSummary, CveStateScope, CveSummary, EnrichedFinding,
};
use qanvuli_core::model::RawCveStatusRecord;
use rmcp::{ErrorData as McpError, model::CallToolResult};
use serde::Serialize;
use simd_json::{OwnedValue as Value, json};
use std::collections::BTreeSet;
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
                        redact_database_url(&self.db_url)
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
        .attach_cve_overview_details(cves)
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
    db.search_cve_summaries_free_text_with_state_scope(query, state_scope, limit, offset)
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
    let source_sync = simd_json::serde::to_owned_value(
        db.source_sync_states()
            .await
            .map_err(|err| mcp_error(err.to_string()))?,
    )
    .map_err(|err| mcp_error(err.to_string()))?;
    let Value::Object(ref mut object) = status else {
        return Err(mcp_error("database status did not serialize to an object"));
    };
    object.insert("source_sync".into(), source_sync);
    response::tool_result(status)
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
    status: Option<&str>,
    limit: u64,
    offset: u64,
    include_evidence: bool,
) -> Result<CallToolResult, McpError> {
    let status = status.unwrap_or("affected");
    if !matches!(status, "affected" | "all") {
        return Err(mcp_error("status must be either 'affected' or 'all'"));
    }
    let result = db
        .query_package_enriched_with_evidence(ecosystem, package, version, purl, include_evidence)
        .await
        .map_err(|err| mcp_error(err.to_string()))?;
    let confirmed_count = result
        .iter()
        .filter(|finding| finding.affected.status == "affected")
        .count();
    let mut result = result
        .into_iter()
        .filter(|finding| status == "all" || finding.affected.status == "affected")
        .collect::<Vec<_>>();
    let matching_count = result.len();
    let offset = usize::try_from(offset).unwrap_or(usize::MAX);
    let limit = usize::try_from(limit).unwrap_or(30);
    let has_more = result.len().saturating_sub(offset) > limit;
    let findings = result
        .drain(offset.min(matching_count)..)
        .take(limit)
        .collect::<Vec<_>>();
    let findings = serialize_findings(&findings, include_evidence)?;
    response::tool_result(json!({
        "vulnerable": confirmed_count > 0,
        "confirmed_count": confirmed_count,
        "coverage_notice": coverage_notice(ecosystem, confirmed_count),
        "status": status,
        "has_more": has_more,
        "findings": findings,
    }))
}

pub(crate) async fn query_packages_enriched(
    db: &CveDatabase,
    packages: Vec<crate::args::PackageQueryArgs>,
    status: Option<&str>,
    include_evidence: bool,
) -> Result<CallToolResult, McpError> {
    let status = status.unwrap_or("affected");
    if !matches!(status, "affected" | "all") {
        return Err(mcp_error("status must be either 'affected' or 'all'"));
    }
    let requested = packages.len();
    let mut results = Vec::with_capacity(requested.min(200));
    for package in packages.into_iter().take(200) {
        match db
            .query_package_enriched_with_evidence(
                &package.ecosystem,
                &package.package,
                &package.version,
                package.purl.as_deref(),
                include_evidence,
            )
            .await
        {
            Ok(findings) => {
                let findings = findings
                    .into_iter()
                    .filter(|finding| status == "all" || finding.affected.status == "affected")
                    .collect::<Vec<_>>();
                let cve_ids = findings
                    .iter()
                    .flat_map(|finding| finding.cve_ids.iter().cloned())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>();
                let risk = db
                    .cve_risk_summaries(&cve_ids)
                    .await
                    .map_err(|err| mcp_error(err.to_string()))?;
                let summary = batch_summary(
                    &package,
                    cve_ids,
                    &risk,
                    findings
                        .iter()
                        .any(|finding| finding.affected.status == "affected"),
                );
                let findings = serialize_findings(&findings, include_evidence)?;
                let coverage_notice =
                    coverage_notice(&package.ecosystem, if summary.vulnerable { 1 } else { 0 });
                results.push(json!({"package": package, "findings": findings, "summary": summary, "coverage_notice": coverage_notice}));
            }
            Err(error) => results.push(json!({"package": package, "error": error.to_string()})),
        }
    }
    response::tool_result(
        json!({"requested": requested, "truncated": requested > 200, "status": status, "results": results}),
    )
}

fn coverage_notice(ecosystem: &str, confirmed_count: usize) -> Option<&'static str> {
    (ecosystem.eq_ignore_ascii_case("pypi") && confirmed_count == 0).then_some(
        "No OSV-affected finding was confirmed. OSV ranges can omit vulnerabilities left unpatched on end-of-life branches; cross-check critical EOL packages with CVE List or vendor advisories.",
    )
}

#[derive(Serialize)]
struct BatchPackageSummary {
    package: String,
    version: String,
    vulnerable: bool,
    cve_ids: Vec<String>,
    max_cvss: Option<f64>,
    max_epss: Option<f64>,
    kev: bool,
}

fn batch_summary(
    package: &crate::args::PackageQueryArgs,
    cve_ids: Vec<String>,
    risk: &[CveRiskSummary],
    vulnerable: bool,
) -> BatchPackageSummary {
    BatchPackageSummary {
        package: package.package.clone(),
        version: package.version.clone(),
        vulnerable,
        cve_ids,
        max_cvss: risk
            .iter()
            .filter_map(|summary| summary.max_cvss_score)
            .max_by(f64::total_cmp),
        max_epss: risk
            .iter()
            .filter_map(|summary| summary.epss)
            .max_by(f64::total_cmp),
        kev: risk.iter().any(|summary| summary.kev_listed),
    }
}

fn serialize_findings(
    findings: &[EnrichedFinding],
    include_evidence: bool,
) -> Result<Value, McpError> {
    let mut value = simd_json::serde::to_owned_value(findings)
        .map_err(|err| mcp_error(format!("failed to encode package findings: {err}")))?;
    if include_evidence {
        return Ok(value);
    }

    let Value::Array(values) = &mut value else {
        return Err(mcp_error("package findings did not serialize to an array"));
    };
    for finding in values.iter_mut() {
        let Value::Object(object) = finding else {
            return Err(mcp_error("package finding did not serialize to an object"));
        };
        object.remove("evidence");
    }
    Ok(value)
}

pub(crate) async fn known_exploited(
    db: &CveDatabase,
    cve_id: Option<&str>,
    limit: u64,
    offset: u64,
) -> Result<CallToolResult, McpError> {
    let (count, entries) = if cve_id.is_some() {
        let entries = db
            .kev_entries(cve_id)
            .await
            .map_err(|err| mcp_error(err.to_string()))?;
        (entries.len() as u64, entries)
    } else {
        let count = db
            .kev_entries_count()
            .await
            .map_err(|err| mcp_error(err.to_string()))?;
        let entries = db
            .kev_entries_paged(limit, offset)
            .await
            .map_err(|err| mcp_error(err.to_string()))?;
        (count, entries)
    };
    let has_more = cve_id.is_none() && offset + (entries.len() as u64) < count;
    response::tool_result(json!({
        "available": true,
        "cve_id": cve_id,
        "known_exploited": if cve_id.is_some() { !entries.is_empty() } else { false },
        "count": count,
        "has_more": has_more,
        "entries": entries,
    }))
}

pub(crate) async fn lookup_cve_risk(
    db: &CveDatabase,
    cve_ids: &[String],
) -> Result<CallToolResult, McpError> {
    let requested = cve_ids.len();
    let cve_ids = cve_ids.iter().take(200).cloned().collect::<Vec<_>>();
    let results = db
        .cve_risk_summaries(&cve_ids)
        .await
        .map_err(|err| mcp_error(err.to_string()))?;
    response::tool_result(json!({
        "requested": requested,
        "truncated": requested > cve_ids.len(),
        "results": results,
    }))
}

pub(crate) async fn search_by_epss(
    db: &CveDatabase,
    min_score: Option<f64>,
    min_percentile: Option<f64>,
    state_scope: CveStateScope,
    limit: u64,
    offset: u64,
) -> Result<CallToolResult, McpError> {
    let results = db
        .search_cve_risk_by_epss(min_score, min_percentile, state_scope, limit + 1, offset)
        .await
        .map_err(|err| mcp_error(err.to_string()))?;
    let has_more = results.len() > limit as usize;
    response::tool_result(json!({
        "has_more": has_more,
        "results": results.into_iter().take(limit as usize).collect::<Vec<_>>(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn database_status_returns_tool_result_without_panicking() {
        let db = CveDatabase::connect("sqlite::memory:").await.unwrap();
        db.initialize_schema().await.unwrap();

        let result = database_status(&db).await.unwrap();

        assert_eq!(result.content.len(), 1);
    }

    #[test]
    fn batch_summary_aggregates_all_related_cves() {
        let package = crate::args::PackageQueryArgs {
            ecosystem: "PyPI".to_owned(),
            package: "pillow-heif".to_owned(),
            version: "1.1.1".to_owned(),
            purl: None,
        };
        let risk = vec![
            CveRiskSummary {
                cve_id: "CVE-2099-0001".to_owned(),
                title: None,
                published_at: None,
                updated_at: None,
                state: None,
                kev_listed: false,
                kev_date_added: None,
                kev_due_date: None,
                kev_known_ransomware_campaign_use: None,
                epss: Some(0.12),
                epss_percentile: None,
                epss_score_date: None,
                epss_model_version: None,
                max_cvss_score: Some(7.5),
                max_cvss_severity: None,
                max_cvss_version: None,
            },
            CveRiskSummary {
                cve_id: "CVE-2099-0002".to_owned(),
                title: None,
                published_at: None,
                updated_at: None,
                state: None,
                kev_listed: true,
                kev_date_added: None,
                kev_due_date: None,
                kev_known_ransomware_campaign_use: None,
                epss: Some(0.91),
                epss_percentile: None,
                epss_score_date: None,
                epss_model_version: None,
                max_cvss_score: Some(9.8),
                max_cvss_severity: None,
                max_cvss_version: None,
            },
        ];

        let summary = batch_summary(
            &package,
            vec!["CVE-2099-0001".to_owned(), "CVE-2099-0002".to_owned()],
            &risk,
            true,
        );

        assert!(summary.vulnerable);
        assert!(summary.kev);
        assert_eq!(summary.max_cvss, Some(9.8));
        assert_eq!(summary.max_epss, Some(0.91));
    }
}
