#![allow(clippy::too_many_arguments)]

use crate::{
    args::{CapecCatalogArgs, CweArgValue, GetCapecArgs},
    common::{
        error::mcp_error,
        params::{limit, offset},
    },
    response,
};
use qanvuli_app_commands::common::{
    CveArchiveOwnership, OsvImportSelection, apply_delta_updates, cleanup_processed_cve_archive,
    redact_database_url, sync_all_enrichment_sources_after_update, sync_osv_after_update,
};
use qanvuli_core::database::{
    CveDatabase, CveRiskSummary, CveStateScope, CveSummary, CveSummaryWithDetail, EnrichedFinding,
    PackageQuery, cve_state_label, normalize_package_name, versions_equivalent,
};
use qanvuli_core::model::RawCveStatusRecord;
use rmcp::{ErrorData as McpError, model::CallToolResult};
use serde::Serialize;
use simd_json::{
    OwnedValue as Value, json,
    prelude::{ValueAsArray, ValueAsObject, ValueAsScalar},
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::OnceCell;

const BATCH_COVERAGE_NOTICE: &str = "osv_covered=false means OSV has no local coverage; it does not prove there are no CVEs. Cross-check end-of-life or critical packages with the CVE List and vendor advisories.";

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
                let db = CveDatabase::connect(&self.db_url).await.map_err(|err| {
                    mcp_error(format!(
                        "failed to connect database `{}`: {err}",
                        redact_database_url(&self.db_url)
                    ))
                })?;
                db.check_required_schema().await.map_err(|err| {
                    mcp_error(format!(
                        "database rebuild required before MCP startup: {err}"
                    ))
                })?;
                Ok(db)
            })
            .await
    }
}

pub(crate) async fn paged_search_result(
    db: &CveDatabase,
    mut cves: Vec<CveSummary>,
    requested_limit: u64,
    full_description: bool,
) -> Result<CallToolResult, McpError> {
    let has_more = cves.len() > requested_limit as usize;
    cves.truncate(requested_limit as usize);
    let cves = db
        .attach_cve_overview_details(cves)
        .await
        .map_err(|err| mcp_error(err.to_string()))?;
    response::tool_result(json!({
        "has_more": has_more,
        "results": if full_description {
            response::summaries_with_detail(cves)
        } else {
            response::summaries_with_detail_compact(cves)
        },
    }))
}

pub(crate) async fn paged_recent_updates_result(
    db: &CveDatabase,
    mut cves: Vec<CveSummary>,
    requested_limit: u64,
    verbosity: Option<&str>,
    full_description: bool,
) -> Result<CallToolResult, McpError> {
    let verbosity = verbosity.unwrap_or(if full_description { "full" } else { "summary" });
    if !matches!(verbosity, "full" | "summary") {
        return Err(mcp_error("verbosity must be either 'full' or 'summary'"));
    }
    if verbosity == "full" {
        return paged_search_result(db, cves, requested_limit, full_description).await;
    }

    let has_more = cves.len() > requested_limit as usize;
    cves.truncate(requested_limit as usize);
    let cve_ids = cves
        .iter()
        .map(|cve| cve.cve_id.clone())
        .collect::<Vec<_>>();
    let mut risk_by_cve = db
        .cve_risk_summaries(&cve_ids)
        .await
        .map_err(|err| mcp_error(err.to_string()))?
        .into_iter()
        .map(|risk| (risk.cve_id.clone(), risk))
        .collect::<BTreeMap<_, _>>();
    let results = cves
        .into_iter()
        .map(|cve| {
            let risk = risk_by_cve.remove(&cve.cve_id);
            json!({
                "cve_id": cve.cve_id,
                "state": cve_state_label(cve.state),
                "published_at": cve.published_at,
                "updated_at": cve.updated_at,
                "title": cve.title,
                "description_preview": cve.description_en.as_deref().map(|value| response::preview(value, response::DESC_PREVIEW_CHARS)),
                "max_cvss_version": risk.as_ref().and_then(|risk| risk.max_cvss_version.clone()),
                "max_cvss_severity": risk.as_ref().and_then(|risk| risk.max_cvss_severity.clone()),
                "max_cvss_score": risk.as_ref().and_then(|risk| risk.max_cvss_score),
                "kev_listed": risk.as_ref().is_some_and(|risk| risk.kev_listed),
                "epss": risk.as_ref().and_then(|risk| risk.epss),
                "epss_percentile": risk.as_ref().and_then(|risk| risk.epss_percentile),
                "epss_score_date": risk.as_ref().and_then(|risk| risk.epss_score_date.clone()),
            })
        })
        .collect::<Vec<_>>();
    response::tool_result(json!({
        "has_more": has_more,
        "verbosity": verbosity,
        "results": results,
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
    exclude_wordpress_collection: bool,
    state_scope: CveStateScope,
    limit: u64,
    offset: u64,
) -> Result<Vec<CveSummary>, McpError> {
    db.search_cve_summaries_by_vendor_product_exact_with_state_scope(
        vendor,
        product,
        vendor_exact,
        product_exact,
        exclude_wordpress_collection,
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
        .find_enriched_osv(osv_id)
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
    let has_osv_advisory = db
        .has_osv_package_advisory(ecosystem, package, purl)
        .await
        .map_err(|err| mcp_error(err.to_string()))?;
    let confirmed_count = result
        .iter()
        .filter(|finding| finding.affected.status == "affected")
        .count();
    let review_count = result
        .iter()
        .filter(|finding| {
            !matches!(
                finding.affected.status.as_str(),
                "affected" | "not_affected"
            )
        })
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
    let findings = serialize_findings(&findings, include_evidence, false)?;
    response::tool_result(json!({
        "vulnerable": confirmed_count > 0,
        "confirmed_count": confirmed_count,
        "review_count": review_count,
        "evaluation_notice": (review_count > 0).then_some("One or more advisories use a version scheme that could not be evaluated; request status='all' to inspect them."),
        "coverage_notice": coverage_notice(ecosystem, !has_osv_advisory),
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
    verbosity: Option<&str>,
    include_fixed: bool,
    include_enrichment: bool,
) -> Result<CallToolResult, McpError> {
    let status = status.unwrap_or("affected");
    if !matches!(status, "affected" | "all") {
        return Err(mcp_error("status must be either 'affected' or 'all'"));
    }
    let verbosity = verbosity.unwrap_or("summary");
    if !matches!(verbosity, "full" | "summary") {
        return Err(mcp_error("verbosity must be either 'full' or 'summary'"));
    }
    let requested = packages.len();
    let packages = packages.into_iter().take(200).collect::<Vec<_>>();
    let queries = packages
        .iter()
        .map(|package| PackageQuery {
            ecosystem: package.ecosystem.clone(),
            package: package.package.clone(),
            version: package.version.clone(),
            purl: package.purl.clone(),
        })
        .collect::<Vec<_>>();
    let findings_by_package = db
        .query_package_matches_batch(&queries)
        .await
        .map_err(|err| mcp_error(err.to_string()))?;
    let coverage = db
        .has_osv_package_advisories_batch(&queries)
        .await
        .map_err(|err| mcp_error(err.to_string()))?;
    let all_cve_ids = findings_by_package
        .iter()
        .flatten()
        .filter(|finding| status == "all" || finding.affected.status == "affected")
        .flat_map(|finding| finding.cve_ids.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let risks_by_cve = db
        .cve_risk_summaries(&all_cve_ids)
        .await
        .map_err(|err| mcp_error(err.to_string()))?
        .into_iter()
        .map(|risk| (risk.cve_id.clone(), risk))
        .collect::<BTreeMap<_, _>>();
    let details_by_cve = db
        .cve_summaries_with_details_batch(&all_cve_ids, CveStateScope::PublishedOnly)
        .await
        .map_err(|err| mcp_error(err.to_string()))?
        .into_iter()
        .flatten()
        .map(|detail| (detail.summary.cve_id.clone(), detail))
        .collect::<BTreeMap<_, _>>();
    let mut results = Vec::with_capacity(packages.len());
    for ((package, findings), has_osv_advisory) in
        packages.into_iter().zip(findings_by_package).zip(coverage)
    {
        let uncertain_findings = findings
            .iter()
            .filter(|finding| {
                !matches!(
                    finding.affected.status.as_str(),
                    "affected" | "not_affected"
                )
            })
            .collect::<Vec<_>>();
        let uncertain_cve_ids = uncertain_findings
            .iter()
            .flat_map(|finding| finding.cve_ids.iter().cloned())
            .collect::<BTreeSet<_>>();
        let review_advisory_ids = uncertain_findings
            .iter()
            .map(|finding| finding.primary_id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let findings = findings
            .into_iter()
            .filter(|finding| status == "all" || finding.affected.status == "affected")
            .collect::<Vec<_>>();
        let candidate_cve_ids = findings
            .iter()
            .flat_map(|finding| finding.cve_ids.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let source_conflicts =
            cna_explicit_version_conflicts(&package, &candidate_cve_ids, &details_by_cve);
        let review_cve_ids = source_conflicts
            .iter()
            .map(|conflict| conflict.cve_id.clone())
            .chain(uncertain_cve_ids)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let confirmed_findings = findings
            .iter()
            .filter(|finding| finding.affected.status == "affected")
            .collect::<Vec<_>>();
        let confirmed_cve_ids = confirmed_findings
            .iter()
            .flat_map(|finding| finding.cve_ids.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let risk = confirmed_cve_ids
            .iter()
            .filter_map(|cve_id| risks_by_cve.get(cve_id).cloned())
            .collect::<Vec<_>>();
        let summary = batch_summary(
            &package,
            confirmed_cve_ids,
            &risk,
            !confirmed_findings.is_empty(),
            include_fixed.then(|| fixed_versions_from_refs(&confirmed_findings)),
            review_cve_ids,
            review_advisory_ids,
        );
        let mut result = json!({
            "package": package,
            "summary": summary,
            "osv_covered": has_osv_advisory,
        });
        let Value::Object(object) = &mut result else {
            return Err(mcp_error("package result did not serialize to an object"));
        };
        if verbosity == "full" {
            object.insert(
                "findings".into(),
                serialize_findings(&findings, include_evidence, include_fixed)?,
            );
        }
        if include_enrichment {
            object.insert(
                "cve_risk".into(),
                simd_json::serde::to_owned_value(&risk)
                    .map_err(|err| mcp_error(format!("failed to encode CVE risk: {err}")))?,
            );
        }
        if !source_conflicts.is_empty() {
            object.insert(
                "source_conflicts".into(),
                simd_json::serde::to_owned_value(&source_conflicts).map_err(|err| {
                    mcp_error(format!("failed to encode source conflicts: {err}"))
                })?,
            );
        }
        results.push(result);
    }
    response::tool_result(json!({
        "requested": requested,
        "truncated": requested > 200,
        "status": status,
        "verbosity": verbosity,
        "coverage_notice": BATCH_COVERAGE_NOTICE,
        "results": results,
    }))
}

fn coverage_notice(ecosystem: &str, no_osv_candidates: bool) -> Option<String> {
    no_osv_candidates.then(|| format!(
        "No local OSV advisory covers this {ecosystem} package. Check CVE List and vendor advisories for critical or end-of-life packages."
    ))
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
    /// A source disagrees with, or cannot establish, the package identity.
    /// This never negates an otherwise affected OSV finding.
    needs_review: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    review_cve_ids: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    review_advisory_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fixed_versions: Option<Vec<String>>,
}

fn batch_summary(
    package: &crate::args::PackageQueryArgs,
    cve_ids: Vec<String>,
    risk: &[CveRiskSummary],
    vulnerable: bool,
    fixed_versions: Option<Vec<String>>,
    review_cve_ids: Vec<String>,
    review_advisory_ids: Vec<String>,
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
        needs_review: !review_cve_ids.is_empty() || !review_advisory_ids.is_empty(),
        review_cve_ids,
        review_advisory_ids,
        fixed_versions,
    }
}

fn fixed_versions_from_refs(findings: &[&EnrichedFinding]) -> Vec<String> {
    findings
        .iter()
        .flat_map(|finding| finding.fixed_versions.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[derive(Serialize)]
struct CnaExplicitVersionConflict {
    cve_id: String,
    package_name: String,
    queried_version: String,
    cna_versions: Vec<String>,
    reason: &'static str,
}

fn cna_explicit_version_conflicts(
    package: &crate::args::PackageQueryArgs,
    cve_ids: &[String],
    details_by_cve: &BTreeMap<String, CveSummaryWithDetail>,
) -> Vec<CnaExplicitVersionConflict> {
    cve_ids
        .iter()
        .filter_map(|cve_id| details_by_cve.get(cve_id))
        .flat_map(|detail| cna_explicit_version_conflicts_for_detail(package, detail))
        .collect()
}

fn cna_explicit_version_conflicts_for_detail(
    package: &crate::args::PackageQueryArgs,
    detail: &CveSummaryWithDetail,
) -> Vec<CnaExplicitVersionConflict> {
    detail
        .detail
        .affected
        .iter()
        .filter(|affected| {
            affected
                .package_name
                .as_deref()
                .or(affected.product.as_deref())
                .is_some_and(|name| {
                    normalize_package_name(&package.ecosystem, name)
                        == normalize_package_name(&package.ecosystem, &package.package)
                })
        })
        .filter_map(|affected| {
            let versions = &affected.versions;
            (!versions.is_empty()
                && versions.iter().all(|version| {
                    version_is_affected(version, affected.default_status.as_deref())
                        && version.less_than.is_none()
                        && version.less_than_or_equal.is_none()
                        && version.version.as_deref().is_some_and(is_bare_version_literal)
                }))
            .then(|| {
                versions
                    .iter()
                    .filter_map(|version| version.version.as_deref().map(decode_html_entities))
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>()
            })
        })
        .filter(|versions| {
            !versions.is_empty()
                && !versions.iter().any(|version| {
                    versions_equivalent(&package.ecosystem, version, &package.version)
                })
        })
        .map(|cna_versions| CnaExplicitVersionConflict {
            cve_id: detail.summary.cve_id.clone(),
            package_name: package.package.clone(),
            queried_version: package.version.clone(),
            cna_versions,
            reason: "OSV matched, while CNA's affected-version enumeration does not include the queried version; review the source disagreement",
        })
        .collect()
}

fn version_is_affected(
    version: &qanvuli_core::database::CveAffectedVersionDetail,
    default_status: Option<&str>,
) -> bool {
    version
        .status
        .as_deref()
        .or(default_status)
        .is_none_or(|status| status.eq_ignore_ascii_case("affected"))
}

/// CVE 5 records sometimes put a constraint expression in `version` rather
/// than in `lessThan`.  Only an unadorned version token is safe to treat as an
/// enumerated version.
fn is_bare_version_literal(value: &str) -> bool {
    let value = decode_html_entities(value);
    !value.is_empty()
        && !value.chars().any(|character| {
            character.is_whitespace()
                || matches!(character, '<' | '>' | '=' | ',' | '*' | '~' | '^')
        })
        && !["before", "after", "through", "and", "or", "to"]
            .iter()
            .any(|keyword| {
                value.eq_ignore_ascii_case(keyword) || value.to_ascii_lowercase().contains(keyword)
            })
}

fn decode_html_entities(value: &str) -> String {
    value
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

fn serialize_findings(
    findings: &[EnrichedFinding],
    include_evidence: bool,
    include_fixed: bool,
) -> Result<Value, McpError> {
    let mut value = simd_json::serde::to_owned_value(findings)
        .map_err(|err| mcp_error(format!("failed to encode package findings: {err}")))?;
    let Value::Array(values) = &mut value else {
        return Err(mcp_error("package findings did not serialize to an array"));
    };
    for finding in values.iter_mut() {
        let Value::Object(object) = finding else {
            return Err(mcp_error("package finding did not serialize to an object"));
        };
        if !include_evidence {
            object.remove("evidence");
        } else if object
            .get("evidence")
            .and_then(Value::as_array)
            .is_none_or(Vec::is_empty)
        {
            // Batch package queries use the bounded matcher directly. Supply
            // the same compact match evidence as the single-query path.
            let source = object
                .get("source")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_owned();
            let primary_id = object
                .get("primary_id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let package = object
                .get("package")
                .cloned()
                .unwrap_or_else(|| json!(null));
            let affected = object
                .get("affected")
                .cloned()
                .unwrap_or_else(|| json!(null));
            let fixed_versions = object
                .get("fixed_versions")
                .cloned()
                .unwrap_or_else(|| json!([]));
            let cve_id = object
                .get("cve_ids")
                .and_then(Value::as_array)
                .and_then(|ids| ids.first())
                .and_then(Value::as_str)
                .map(str::to_owned);
            let osv_id = (source == "osv").then(|| primary_id.clone());
            let from = package.as_object().map(|package| {
                format!(
                    "{}:{}@{}",
                    package
                        .get("ecosystem")
                        .and_then(Value::as_str)
                        .unwrap_or_default(),
                    package
                        .get("package")
                        .and_then(Value::as_str)
                        .unwrap_or_default(),
                    package
                        .get("version")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                )
            });
            let purl = package
                .as_object()
                .and_then(|package| package.get("purl"))
                .cloned()
                .unwrap_or_else(|| json!(null));
            let status = affected
                .as_object()
                .and_then(|affected| affected.get("status"))
                .cloned()
                .unwrap_or_else(|| json!(null));
            let confidence = affected
                .as_object()
                .and_then(|affected| affected.get("confidence"))
                .cloned()
                .unwrap_or_else(|| json!(null));
            let detail = json!({
                "status": status,
                "confidence": confidence,
                "purl": purl,
                "fixed_versions": fixed_versions,
            })
            .to_string();
            object.insert(
                "evidence".to_owned(),
                json!([{
                    "kind": "package_version_evaluation",
                    "source": source,
                    "from": from,
                    "to": primary_id,
                    "cve_id": cve_id,
                    "osv_id": osv_id,
                    "detail": detail,
                }]),
            );
            object.insert("evidence_status".to_owned(), json!("available"));
        }
        if !include_fixed {
            object.remove("fixed_versions");
            object.remove("fixed_versions_status");
        }
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
            .kev_entries(cve_id, 1, 0)
            .await
            .map_err(|err| mcp_error(err.to_string()))?;
        (entries.len() as u64, entries)
    } else {
        let count = db
            .kev_entries_count()
            .await
            .map_err(|err| mcp_error(err.to_string()))?;
        let entries = db
            .kev_entries(None, limit as i64, offset as i64)
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
    verbosity: Option<&str>,
) -> Result<CallToolResult, McpError> {
    let full = matches!(verbosity, Some("full"));
    let requested = cve_ids.len();
    let cve_ids = cve_ids.iter().take(200).cloned().collect::<Vec<_>>();
    let results = db
        .cve_risk_summaries(&cve_ids)
        .await
        .map_err(|err| mcp_error(err.to_string()))?;
    let results = if full {
        simd_json::serde::to_owned_value(&results)
            .map_err(|err| mcp_error(format!("failed to encode CVE risk: {err}")))?
    } else {
        let mut results = simd_json::serde::to_owned_value(&results)
            .map_err(|err| mcp_error(format!("failed to encode CVE risk: {err}")))?;
        if let Value::Array(rows) = &mut results {
            for row in rows.iter_mut() {
                if let Value::Object(row) = row {
                    for key in [
                        "title",
                        "published_at",
                        "updated_at",
                        "state",
                        "epss_model_version",
                    ] {
                        row.remove(key);
                    }
                }
            }
        }
        results
    };
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

pub(crate) async fn search_cwe_catalog(
    db: &CveDatabase,
    query: Option<&str>,
    limit: u64,
    statuses: &[String],
    capec_id: Option<i32>,
    offset: u64,
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
    let mut entries = db
        .search_cwe_entries_filtered(
            query.unwrap_or_default(),
            limit.saturating_add(offset),
            &statuses,
            capec_id,
        )
        .await
        .map_err(|err| mcp_error(err.to_string()))?;
    let entries = entries
        .drain(offset.min(entries.len() as u64) as usize..)
        .take(limit as usize)
        .collect::<Vec<_>>();
    response::tool_result(json!(entries))
}

pub(crate) async fn get_cwe(db: &CveDatabase, cwe_id: i32) -> Result<CallToolResult, McpError> {
    let entry = db
        .find_cwe_entry(cwe_id)
        .await
        .map_err(|err| mcp_error(err.to_string()))?;
    response::tool_result(json!(entry))
}

pub(crate) async fn search_capec_catalog(
    db: &CveDatabase,
    args: CapecCatalogArgs,
) -> Result<CallToolResult, McpError> {
    let cwe_id = args
        .cwe_id
        .map(|value| parse_catalog_id(value, "CWE"))
        .transpose()?;
    let entries = db
        .search_capec_entries(qanvuli_core::database::CapecSearchFilters {
            query: args.query,
            statuses: args.statuses,
            types: args.types,
            cwe_id,
            limit: limit(args.limit),
            offset: offset(args.offset),
        })
        .await
        .map_err(|err| mcp_error(err.to_string()))?;
    response::tool_result(json!(entries))
}

pub(crate) async fn get_capec(
    db: &CveDatabase,
    args: GetCapecArgs,
) -> Result<CallToolResult, McpError> {
    let id = parse_catalog_id(args.capec_id, "CAPEC")?;
    let mut value = serde_json::to_value(
        db.find_capec(id)
            .await
            .map_err(|err| mcp_error(err.to_string()))?,
    )
    .map_err(|err| mcp_error(err.to_string()))?;
    if let Some(detail) = value.as_object_mut() {
        let include_references = args.include_references.unwrap_or(false);
        let include_history = args.include_history.unwrap_or(false);
        if !include_references {
            detail.remove("references");
        }
        if args.include_taxonomy.unwrap_or(false) {
            for classification in ["categories", "views"] {
                if let Some(items) = detail
                    .get_mut(classification)
                    .and_then(serde_json::Value::as_array_mut)
                {
                    for item in items {
                        if let Some(item) = item.as_object_mut() {
                            if !include_references {
                                item.remove("references");
                            }
                            if !include_history {
                                item.remove("history");
                            }
                        }
                    }
                }
            }
        } else {
            detail.remove("categories");
            detail.remove("views");
        }
    }
    response::tool_result(
        simd_json::serde::to_owned_value(&value).map_err(|err| mcp_error(err.to_string()))?,
    )
}

fn parse_catalog_id(value: CweArgValue, prefix: &str) -> Result<i32, McpError> {
    let value = value.into_search_value();
    let upper = value.trim().to_ascii_uppercase();
    upper
        .strip_prefix(prefix)
        .unwrap_or(&upper)
        .trim_start_matches('-')
        .parse()
        .map_err(|err| mcp_error(format!("invalid {prefix} ID `{value}`: {err}")))
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
    db.check_required_schema()
        .await
        .map_err(|err| mcp_error(format!("database rebuild required before update: {err}")))?;

    let local_zip = zip.is_some();
    let applied = apply_delta_updates(db, zip.map(PathBuf::from), max_chunks)
        .await
        .map_err(mcp_error)?;
    let cve_changed = !applied.is_empty();

    let osv_additions = OsvImportSelection::update_additions(osv_all, osv_prefixes);
    if local_zip {
        // Match `qanvuli update --zip`: a local CVE archive only expands OSV
        // coverage when explicitly requested and does not refresh other feeds.
        if let Some(osv_additions) = osv_additions.as_ref() {
            sync_osv_after_update(db, "mcp update_db", Some(osv_additions))
                .await
                .map_err(mcp_error)?;
        }
    } else {
        sync_all_enrichment_sources_after_update(
            db,
            "mcp update_db",
            osv_additions.as_ref(),
            cve_changed,
        )
        .await
        .map_err(mcp_error)?;
    }

    db.check_search_integrity_quick()
        .await
        .map_err(|err| mcp_error(format!("post-update database check failed: {err}")))?;

    db.rebuild_identifier_graph()
        .await
        .map_err(|err| mcp_error(format!("failed to rebuild identifier graph: {err}")))?;

    if !local_zip {
        for path in &applied {
            cleanup_processed_cve_archive(path, CveArchiveOwnership::Downloaded, false)
                .map_err(mcp_error)?;
        }
    }

    response::tool_result(json!({
        "updated": true,
        "applied_assets": applied.into_iter().map(|path| path.display().to_string()).collect::<Vec<_>>(),
        "identifier_graph": (),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call_result_payload(result: CallToolResult) -> (serde_json::Value, usize) {
        let value = serde_json::to_value(result).unwrap();
        let text = value
            .pointer("/content/0/text")
            .and_then(serde_json::Value::as_str)
            .unwrap();
        (serde_json::from_str(text).unwrap(), text.len())
    }

    #[tokio::test]
    async fn database_status_returns_tool_result_without_panicking() {
        let db = CveDatabase::connect("sqlite::memory:").await.unwrap();
        db.initialize_schema().await.unwrap();

        let result = database_status(&db).await.unwrap();

        assert_eq!(result.content.len(), 1);
    }

    #[tokio::test]
    async fn enriched_cve_returns_normalized_ssvc_assessments() {
        let db = CveDatabase::connect("sqlite::memory:").await.unwrap();
        db.initialize_schema().await.unwrap();
        db.import_cve_raw_json(
            r#"{"cveMetadata":{"cveId":"CVE-2099-0201","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-02T00:00:00Z"},"containers":{"cna":{"title":"SSVC MCP fixture","descriptions":[{"lang":"en","value":"SSVC MCP contract test"}],"affected":[]},"adp":[{"providerMetadata":{"shortName":"CISA-ADP"},"metrics":[{"other":{"type":"ssvc","content":{"timestamp":"2099-01-03T00:00:00Z","id":"CVE-2099-0201","options":[{"Exploitation":"active"},{"Automatable":"yes"},{"Technical Impact":"total"}],"role":"CISA Coordinator","version":"2.0.3"}}}]}]}}"#.to_owned(),
        )
        .await
        .unwrap();

        let result = get_enriched_cve(&db, "CVE-2099-0201").await.unwrap();
        let (payload, _) = call_result_payload(result);

        assert_eq!(payload["ssvc"][0]["provider"], "CISA-ADP");
        assert_eq!(payload["ssvc"][0]["role"], "CISA Coordinator");
        assert_eq!(payload["ssvc"][0]["version"], "2.0.3");
        assert_eq!(payload["ssvc"][0]["exploitation"], "active");
        assert_eq!(payload["ssvc"][0]["automatable"], "yes");
        assert_eq!(payload["ssvc"][0]["technical_impact"], "total");
    }

    #[tokio::test]
    async fn recent_updates_default_to_compact_risk_triage_with_full_details_available() {
        let db = CveDatabase::connect("sqlite::memory:").await.unwrap();
        db.initialize_schema().await.unwrap();
        db.import_cve_raw_json(
            r#"{"cveMetadata":{"cveId":"CVE-2099-0101","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-02T00:00:00Z"},"containers":{"cna":{"title":"compact recent fixture","descriptions":[{"lang":"en","value":"description for compact recent update testing"}],"problemTypes":[{"descriptions":[{"lang":"en","description":"CWE-79","cweId":"CWE-79"}]}],"metrics":[{"cvssV3_1":{"version":"3.1","vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","baseScore":9.8,"baseSeverity":"CRITICAL"}}],"affected":[{"vendor":"example","product":"widget","versions":[{"version":"1.0.0","status":"affected"}]}]}}}"#.to_owned(),
        )
        .await
        .unwrap();
        let cve: CveSummary = db
            .find_cve_summary("CVE-2099-0101")
            .await
            .unwrap()
            .unwrap()
            .into();

        let compact = paged_recent_updates_result(&db, vec![cve.clone()], 10, None, false)
            .await
            .unwrap();
        let full = paged_recent_updates_result(&db, vec![cve], 10, Some("full"), false)
            .await
            .unwrap();
        let (compact, compact_len) = call_result_payload(compact);
        let (full, full_len) = call_result_payload(full);

        assert_eq!(compact["verbosity"], "summary");
        assert_eq!(compact["results"][0]["cve_id"], "CVE-2099-0101");
        assert_eq!(compact["results"][0]["max_cvss_score"], 9.8);
        assert_eq!(compact["results"][0]["max_cvss_severity"], "CRITICAL");
        assert_eq!(compact["results"][0]["kev_listed"], false);
        assert!(compact["results"][0].get("affected").is_none());
        assert!(compact["results"][0].get("cwe").is_none());
        assert!(full["results"][0]["affected"].is_array());
        assert!(full["results"][0]["cwe"].is_array());
        assert!(full["results"][0]["cvss"].is_array());
        assert!(compact_len < full_len);
    }

    #[tokio::test]
    async fn package_batches_default_to_decision_preserving_summaries() {
        use qanvuli_core::database::OsvRawRecord;

        let db = CveDatabase::connect("sqlite::memory:").await.unwrap();
        db.initialize_schema().await.unwrap();
        db.import_osv_record(OsvRawRecord {
            source_path: None,
            raw_json: r#"{"schema_version":"1.8.0","id":"GHSA-2099-compact-batch","modified":"2099-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"example"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]}]}"#.to_owned(),
        })
        .await
        .unwrap();
        let package = || crate::args::PackageQueryArgs {
            ecosystem: "npm".to_owned(),
            package: "example".to_owned(),
            version: "1.0.0".to_owned(),
            purl: Some("pkg:npm/example".to_owned()),
        };

        let compact = query_packages_enriched(&db, vec![package()], None, false, None, true, false)
            .await
            .unwrap();
        let full =
            query_packages_enriched(&db, vec![package()], None, false, Some("full"), true, false)
                .await
                .unwrap();
        let (compact, compact_len) = call_result_payload(compact);
        let (full, full_len) = call_result_payload(full);

        assert_eq!(compact["verbosity"], "summary");
        assert_eq!(compact["results"][0]["summary"]["vulnerable"], true);
        assert_eq!(compact["results"][0]["summary"]["needs_review"], false);
        assert_eq!(
            compact["results"][0]["summary"]["fixed_versions"][0],
            "2.0.0"
        );
        assert!(compact["results"][0].get("findings").is_none());
        assert!(full["results"][0]["findings"].is_array());
        assert!(compact_len < full_len);
    }

    #[tokio::test]
    async fn package_query_resolves_native_maven_ranges_and_match_evidence() {
        use qanvuli_core::database::OsvRawRecord;

        let db = CveDatabase::connect("sqlite::memory:").await.unwrap();
        db.initialize_schema().await.unwrap();
        db.import_osv_record(OsvRawRecord {
            source_path: None,
            raw_json: r#"{"schema_version":"1.8.0","id":"GHSA-2099-maven-review","modified":"2099-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"Maven","name":"org.example:core"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0-final"}]}]}]}"#.to_owned(),
        })
        .await
        .unwrap();

        let result = query_package_enriched(
            &db,
            "Maven",
            "org.example:core",
            "1.5-final",
            None,
            Some("all"),
            30,
            0,
            true,
        )
        .await
        .unwrap();
        let value = serde_json::to_value(result).unwrap();
        let text = value
            .pointer("/content/0/text")
            .and_then(serde_json::Value::as_str)
            .unwrap();
        let payload: serde_json::Value = serde_json::from_str(text).unwrap();

        assert_eq!(payload["vulnerable"], true);
        assert_eq!(payload["confirmed_count"], 1);
        assert_eq!(payload["review_count"], 0);
        assert!(payload["evaluation_notice"].is_null());
        assert_eq!(payload["findings"][0]["affected"]["status"], "affected");
        assert_eq!(payload["findings"][0]["evidence_status"], "available");
        assert_eq!(
            payload["findings"][0]["evidence"].as_array().unwrap().len(),
            1
        );
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
            None,
            Vec::new(),
            Vec::new(),
        );

        assert!(summary.vulnerable);
        assert!(summary.kev);
        assert_eq!(summary.max_cvss, Some(9.8));
        assert_eq!(summary.max_epss, Some(0.91));
    }

    #[test]
    fn batch_summary_flags_an_uncertain_advisory_without_a_cve_alias() {
        let package = crate::args::PackageQueryArgs {
            ecosystem: "Maven".to_owned(),
            package: "org.example:core".to_owned(),
            version: "1.0-final".to_owned(),
            purl: None,
        };
        let summary = batch_summary(
            &package,
            Vec::new(),
            &[],
            false,
            None,
            Vec::new(),
            vec!["GHSA-2099-needs-review".to_owned()],
        );

        assert!(summary.needs_review);
        assert_eq!(summary.review_advisory_ids, ["GHSA-2099-needs-review"]);
    }

    #[test]
    fn batch_coverage_notice_is_shared_and_osv_coverage_is_boolean() {
        assert!(BATCH_COVERAGE_NOTICE.contains("osv_covered=false"));
        assert!(BATCH_COVERAGE_NOTICE.contains("does not prove"));
    }

    #[test]
    fn cna_explicit_versions_excluding_the_query_are_reported_as_a_source_conflict() {
        use qanvuli_core::database::{CveAffectedDetail, CveAffectedVersionDetail, CveDetail};

        let package = crate::args::PackageQueryArgs {
            ecosystem: "PyPI".to_owned(),
            package: "Pygments".to_owned(),
            version: "2.15.1".to_owned(),
            purl: None,
        };
        let detail = CveSummaryWithDetail {
            summary: CveSummary {
                cve_id: "CVE-2026-4539".to_owned(),
                state: 0,
                published_at: "2026-01-01T00:00:00Z".to_owned(),
                updated_at: "2026-01-01T00:00:00Z".to_owned(),
                title: String::new(),
                description_en: None,
            },
            detail: CveDetail {
                affected: vec![CveAffectedDetail {
                    vendor: None,
                    product: Some("pygments".to_owned()),
                    package_name: None,
                    description: None,
                    collection_url: None,
                    default_status: None,
                    versions: vec![
                        CveAffectedVersionDetail {
                            version: Some("2.19.0".to_owned()),
                            ..Default::default()
                        },
                        CveAffectedVersionDetail {
                            version: Some("2.19.1".to_owned()),
                            ..Default::default()
                        },
                    ],
                }],
                ..Default::default()
            },
        };

        let conflicts = cna_explicit_version_conflicts_for_detail(&package, &detail);

        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].cna_versions, ["2.19.0", "2.19.1"]);
    }

    #[test]
    fn cna_constraint_strings_are_not_treated_as_explicit_versions() {
        use qanvuli_core::database::{CveAffectedDetail, CveAffectedVersionDetail, CveDetail};

        let package = crate::args::PackageQueryArgs {
            ecosystem: "PyPI".to_owned(),
            package: "aiohttp".to_owned(),
            version: "3.12.13".to_owned(),
            purl: None,
        };
        for version in ["< 3.12.14", ">= 2.2.0, < 2.5.0", "&lt; 3.12.14"] {
            let detail = CveSummaryWithDetail {
                summary: CveSummary {
                    cve_id: "CVE-2099-0001".to_owned(),
                    state: 0,
                    published_at: String::new(),
                    updated_at: String::new(),
                    title: String::new(),
                    description_en: None,
                },
                detail: CveDetail {
                    affected: vec![CveAffectedDetail {
                        vendor: None,
                        product: Some("aiohttp".to_owned()),
                        package_name: None,
                        description: None,
                        collection_url: None,
                        default_status: Some("affected".to_owned()),
                        versions: vec![CveAffectedVersionDetail {
                            version: Some(version.to_owned()),
                            ..Default::default()
                        }],
                    }],
                    ..Default::default()
                },
            };
            assert!(
                cna_explicit_version_conflicts_for_detail(&package, &detail).is_empty(),
                "{version}"
            );
        }
    }

    #[test]
    fn unaffected_cna_versions_are_not_an_explicit_affected_enumeration() {
        use qanvuli_core::database::{CveAffectedDetail, CveAffectedVersionDetail, CveDetail};
        let package = crate::args::PackageQueryArgs {
            ecosystem: "PyPI".to_owned(),
            package: "aiohttp".to_owned(),
            version: "3.12.13".to_owned(),
            purl: None,
        };
        let detail = CveSummaryWithDetail {
            summary: CveSummary {
                cve_id: "CVE-2099-0001".to_owned(),
                state: 0,
                published_at: String::new(),
                updated_at: String::new(),
                title: String::new(),
                description_en: None,
            },
            detail: CveDetail {
                affected: vec![CveAffectedDetail {
                    vendor: None,
                    product: Some("aiohttp".to_owned()),
                    package_name: None,
                    description: None,
                    collection_url: None,
                    default_status: Some("unaffected".to_owned()),
                    versions: vec![CveAffectedVersionDetail {
                        version: Some("2.19.0".to_owned()),
                        ..Default::default()
                    }],
                }],
                ..Default::default()
            },
        };
        assert!(cna_explicit_version_conflicts_for_detail(&package, &detail).is_empty());
    }
}
