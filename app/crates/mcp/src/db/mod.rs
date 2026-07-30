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
    OsvImportSelection, apply_delta_updates, redact_database_url,
    sync_all_enrichment_sources_after_update,
};
use qanvuli_core::database::{
    CveDatabase, CveRiskSummary, CveStateScope, CveSummary, CveSummaryWithDetail, EnrichedFinding,
    PackageQuery,
};
use qanvuli_core::model::RawCveStatusRecord;
use rmcp::{ErrorData as McpError, model::CallToolResult};
use serde::Serialize;
use simd_json::{OwnedValue as Value, json};
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
    let verbosity = verbosity.unwrap_or("full");
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
        let uncertain_cve_ids = findings
            .iter()
            .filter(|finding| finding.affected.status == "unknown")
            .flat_map(|finding| finding.cve_ids.iter().cloned())
            .collect::<BTreeSet<_>>();
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
        needs_review: !review_cve_ids.is_empty(),
        review_cve_ids,
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
                    normalized_package_name(name) == normalized_package_name(&package.package)
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
        .filter(|versions| !versions.is_empty() && !versions.iter().any(|version| version == &package.version))
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

fn normalized_package_name(name: &str) -> String {
    let mut normalized = String::with_capacity(name.len());
    let mut previous_separator = false;
    for character in name.chars() {
        if matches!(character, '-' | '_' | '.') {
            if !previous_separator {
                normalized.push('-');
            }
            previous_separator = true;
        } else {
            normalized.push(character.to_ascii_lowercase());
            previous_separator = false;
        }
    }
    normalized
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

    db.rebuild_identifier_graph()
        .await
        .map_err(|err| mcp_error(format!("failed to rebuild identifier graph: {err}")))?;

    response::tool_result(json!({
        "updated": true,
        "applied_assets": applied.into_iter().map(|path| path.display().to_string()).collect::<Vec<_>>(),
        "identifier_graph": (),
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
            None,
            Vec::new(),
        );

        assert!(summary.vulnerable);
        assert!(summary.kev);
        assert_eq!(summary.max_cvss, Some(9.8));
        assert_eq!(summary.max_epss, Some(0.91));
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
