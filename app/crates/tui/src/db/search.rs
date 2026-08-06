use crate::mode::SearchMode;
use qanvuli_core::database::{
    CveAdvancedQueryMode, CveAdvancedSearch, CveDatabase, CveStateScope, CveSummary,
    CveSummarySortOrder, CveSummaryWithDetail, EnrichedCveSummary, OsvSummary,
};
use std::collections::{BTreeSet, HashMap, HashSet};

#[derive(Debug)]
pub(crate) struct SearchResult {
    pub(crate) rows: Vec<CveSummaryWithDetail>,
    pub(crate) osv_rows: Vec<OsvSummary>,
    pub(crate) enrichment: Vec<EnrichedCveSummary>,
    pub(crate) linked_osv: HashMap<String, Vec<OsvSummary>>,
    pub(crate) consumed: u64,
    pub(crate) exhausted: bool,
}

#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum SearchRequest {
    Mode {
        mode: SearchMode,
        query: String,
        state_scope: CveStateScope,
        kev_only: bool,
        sort_order: CveSummarySortOrder,
    },
    Advanced {
        options: CveAdvancedSearch,
        include_cve: bool,
        include_osv: bool,
        osv_families: Vec<String>,
        ecosystems: Option<Vec<String>>,
    },
}

pub(crate) async fn run_search_request(
    db: CveDatabase,
    request: SearchRequest,
    limit: u64,
    offset: u64,
) -> Result<SearchResult, String> {
    match request {
        SearchRequest::Mode {
            mode,
            query,
            state_scope,
            kev_only,
            sort_order,
        } => {
            let rows = if kev_only {
                db.search_cve_summaries_advanced(
                    &CveAdvancedSearch {
                        query: Some(query.clone()),
                        query_mode: Some(mode.into()),
                        state_scope,
                        kev_only: true,
                        sort_order,
                        ..Default::default()
                    },
                    limit,
                    offset,
                )
                .await
                .map_err(|err| err.to_string())?
            } else {
                search_by_mode(&db, mode, &query, state_scope, sort_order, limit, offset).await?
            };
            let osv_rows = if kev_only {
                Vec::new()
            } else {
                search_osv_by_mode(&db, mode, &query, sort_order, limit, offset).await?
            };
            let consumed = rows.len().max(osv_rows.len()) as u64;
            let exhausted = rows.len() < limit as usize && osv_rows.len() < limit as usize;
            let (rows, osv_rows) =
                collapse_linked_osv(&db, rows, osv_rows, state_scope, sort_order).await?;
            let rows = db
                .attach_cve_overview_details(rows)
                .await
                .map_err(|err| err.to_string())?;
            let enrichment = load_enrichment_summaries(&db, &rows).await?;
            let linked_osv = load_linked_osv(&db, &rows).await?;
            Ok(SearchResult {
                rows,
                osv_rows,
                enrichment,
                linked_osv,
                consumed,
                exhausted,
            })
        }
        SearchRequest::Advanced {
            options,
            include_cve,
            include_osv,
            osv_families,
            ecosystems,
        } => {
            let osv_query = advanced_osv_query(&options);
            let package_version = package_version_query(&options);
            let rows = if include_cve {
                if let Some((ecosystem, package, version)) = package_version.as_ref() {
                    let findings = db
                        .query_package_matches(ecosystem, package, version, None)
                        .await
                        .map_err(|err| err.to_string())?;
                    let cve_ids = findings
                        .into_iter()
                        .filter(|finding| finding.affected.status == "affected")
                        .flat_map(|finding| finding.cve_ids)
                        .collect::<std::collections::BTreeSet<_>>()
                        .into_iter()
                        .collect::<Vec<_>>();
                    db.cve_summaries_by_ids_sorted(
                        &cve_ids,
                        options.state_scope,
                        options.sort_order,
                        limit,
                        offset,
                    )
                    .await
                    .map_err(|err| err.to_string())?
                } else {
                    db.search_cve_summaries_advanced(&options, limit, offset)
                        .await
                        .map_err(|err| err.to_string())?
                }
            } else {
                Vec::new()
            };
            let osv_rows = if package_version.is_some()
                || options.kev_only
                || !include_osv
                || has_cve_only_advanced_filters(&options)
            {
                Vec::new()
            } else if uses_osv_text_fts(&options, &osv_families, ecosystems.as_deref()) {
                db.search_osv_summaries_free_text_sorted(
                    options.query.as_deref().unwrap_or_default(),
                    options.sort_order,
                    limit,
                    offset,
                )
                .await
                .map_err(|err| err.to_string())?
            } else if let Some(package_name) = options
                .product_exact
                .as_deref()
                .map(str::trim)
                .filter(|name| !name.is_empty())
            {
                db.search_osv_summaries_scoped_by_exact_package_sorted(
                    osv_query.as_deref(),
                    &osv_families,
                    ecosystems.as_deref(),
                    package_name,
                    options.sort_order,
                    limit,
                    offset,
                )
                .await
                .map_err(|err| err.to_string())?
            } else {
                db.search_osv_summaries_scoped_sorted(
                    osv_query.as_deref(),
                    &osv_families,
                    ecosystems.as_deref(),
                    options.sort_order,
                    limit,
                    offset,
                )
                .await
                .map_err(|err| err.to_string())?
            };
            let consumed = rows.len().max(osv_rows.len()) as u64;
            let exhausted = rows.len() < limit as usize && osv_rows.len() < limit as usize;
            let (rows, osv_rows) = if include_cve {
                collapse_linked_osv(&db, rows, osv_rows, options.state_scope, options.sort_order)
                    .await?
            } else {
                (rows, osv_rows)
            };
            let rows = db
                .attach_cve_overview_details(rows)
                .await
                .map_err(|err| err.to_string())?;
            let enrichment = load_enrichment_summaries(&db, &rows).await?;
            let linked_osv = load_linked_osv(&db, &rows).await?;
            Ok(SearchResult {
                rows,
                osv_rows,
                enrichment,
                linked_osv,
                consumed,
                exhausted,
            })
        }
    }
}

async fn load_linked_osv(
    db: &CveDatabase,
    rows: &[CveSummaryWithDetail],
) -> Result<HashMap<String, Vec<OsvSummary>>, String> {
    let cve_ids = rows
        .iter()
        .map(|row| row.summary.cve_id.clone())
        .collect::<Vec<_>>();
    db.osv_summaries_for_cve_ids(&cve_ids)
        .await
        .map_err(|err| err.to_string())
}

async fn collapse_linked_osv(
    db: &CveDatabase,
    mut rows: Vec<CveSummary>,
    osv_rows: Vec<OsvSummary>,
    state_scope: CveStateScope,
    sort_order: CveSummarySortOrder,
) -> Result<(Vec<CveSummary>, Vec<OsvSummary>), String> {
    let osv_ids = osv_rows
        .iter()
        .map(|row| row.osv_id.clone())
        .collect::<Vec<_>>();
    let aliases = db
        .cve_aliases_for_osv_ids(&osv_ids, state_scope)
        .await
        .map_err(|err| err.to_string())?;
    if aliases.is_empty() {
        return Ok((rows, osv_rows));
    }

    let mut known_cves = rows
        .iter()
        .map(|row| row.cve_id.clone())
        .collect::<HashSet<_>>();
    let promoted_ids = aliases
        .values()
        .flatten()
        .filter(|cve_id| known_cves.insert((*cve_id).clone()))
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if !promoted_ids.is_empty() {
        rows.extend(
            db.cve_summaries_by_ids_with_state_scope(&promoted_ids, state_scope)
                .await
                .map_err(|err| err.to_string())?,
        );
        let ids = rows
            .iter()
            .map(|row| row.cve_id.clone())
            .collect::<Vec<_>>();
        rows = db
            .cve_summaries_by_ids_sorted(&ids, state_scope, sort_order, ids.len() as u64, 0)
            .await
            .map_err(|err| err.to_string())?;
    }
    let osv_rows = osv_rows
        .into_iter()
        .filter(|row| !aliases.contains_key(&row.osv_id))
        .collect();
    Ok((rows, osv_rows))
}

async fn search_osv_by_mode(
    db: &CveDatabase,
    mode: SearchMode,
    query: &str,
    sort_order: CveSummarySortOrder,
    limit: u64,
    offset: u64,
) -> Result<Vec<OsvSummary>, String> {
    match mode {
        SearchMode::FreeText => db
            .search_osv_summaries_free_text_sorted(query, sort_order, limit, offset)
            .await
            .map_err(|err| err.to_string()),
        SearchMode::Identifier => {
            let resolution = db
                .resolve_identifier(query)
                .await
                .map_err(|err| err.to_string())?;
            db.osv_summaries_by_ids_sorted(&resolution.related_osv_ids, sort_order, limit, offset)
                .await
                .map_err(|err| err.to_string())
        }
        SearchMode::Product => db
            .search_osv_summaries_scoped_by_exact_package_sorted(
                None,
                &[],
                None,
                query,
                sort_order,
                limit,
                offset,
            )
            .await
            .map_err(|err| err.to_string()),
        SearchMode::Vendor => db
            .search_osv_summaries_free_text_sorted(query, sort_order, limit, offset)
            .await
            .map_err(|err| err.to_string()),
        SearchMode::Cwe | SearchMode::Cve => Ok(Vec::new()),
    }
}

async fn load_enrichment_summaries(
    db: &CveDatabase,
    rows: &[CveSummaryWithDetail],
) -> Result<Vec<EnrichedCveSummary>, String> {
    let cve_ids = rows
        .iter()
        .map(|row| row.summary.cve_id.clone())
        .collect::<Vec<_>>();
    db.enriched_cve_summaries(&cve_ids)
        .await
        .map_err(|err| err.to_string())
}

pub(crate) async fn run_count_request(
    db: CveDatabase,
    request: SearchRequest,
) -> Result<u64, String> {
    match request {
        SearchRequest::Mode {
            mode,
            query,
            state_scope,
            kev_only,
            sort_order,
        } => {
            if kev_only {
                let cve = db
                    .count_cve_summaries_advanced(&CveAdvancedSearch {
                        query: Some(query.clone()),
                        query_mode: Some(mode.into()),
                        state_scope,
                        kev_only: true,
                        sort_order,
                        ..Default::default()
                    })
                    .await
                    .map_err(|err| err.to_string())?;
                Ok(cve)
            } else {
                count_by_mode(&db, mode, &query, state_scope).await
            }
        }
        SearchRequest::Advanced {
            options,
            include_cve,
            include_osv,
            osv_families,
            ecosystems,
        } => {
            let osv_query = advanced_osv_query(&options);
            let cve = if include_cve {
                if let Some((ecosystem, package, version)) = package_version_query(&options) {
                    let findings = db
                        .query_package_matches(&ecosystem, &package, &version, None)
                        .await
                        .map_err(|err| err.to_string())?;
                    findings
                        .into_iter()
                        .filter(|finding| finding.affected.status == "affected")
                        .flat_map(|finding| finding.cve_ids)
                        .collect::<std::collections::BTreeSet<_>>()
                        .len() as u64
                } else {
                    db.count_cve_summaries_advanced(&options)
                        .await
                        .map_err(|err| err.to_string())?
                }
            } else {
                0
            };
            let osv = if package_version_query(&options).is_some()
                || options.kev_only
                || !include_osv
                || has_cve_only_advanced_filters(&options)
            {
                0
            } else if uses_osv_text_fts(&options, &osv_families, ecosystems.as_deref()) {
                db.count_osv_summaries_free_text(options.query.as_deref().unwrap_or_default())
                    .await
                    .map_err(|err| err.to_string())?
            } else if let Some(package_name) = options
                .product_exact
                .as_deref()
                .map(str::trim)
                .filter(|name| !name.is_empty())
            {
                db.count_osv_summaries_scoped_by_exact_package(
                    osv_query.as_deref(),
                    &osv_families,
                    ecosystems.as_deref(),
                    package_name,
                )
                .await
                .map_err(|err| err.to_string())?
            } else {
                db.count_osv_summaries_scoped(
                    osv_query.as_deref(),
                    &osv_families,
                    ecosystems.as_deref(),
                )
                .await
                .map_err(|err| err.to_string())?
            };
            Ok(cve + osv)
        }
    }
}

fn has_cve_only_advanced_filters(options: &CveAdvancedSearch) -> bool {
    [
        options.published_from.as_deref(),
        options.published_to.as_deref(),
        options.cwe.as_deref(),
    ]
    .into_iter()
    .any(|value| value.is_some_and(|value| !value.trim().is_empty()))
        || options.kev_only
}

/// Package matching requires ecosystem, name, and version.
fn package_version_query(options: &CveAdvancedSearch) -> Option<(String, String, String)> {
    let ecosystem = options.package_ecosystem.as_deref()?.trim();
    let package = options
        .product_exact
        .as_deref()
        .or(options.product.as_deref())?
        .trim();
    let version = options.package_version.as_deref()?.trim();
    (!ecosystem.is_empty() && !package.is_empty() && !version.is_empty())
        .then(|| (ecosystem.to_owned(), package.to_owned(), version.to_owned()))
}

/// A plain free-text query can use OSV's FTS5 projection. Other advanced filters still need
/// normalized package joins, but routing this common TUI path away from LIKE/DISTINCT avoids a
/// full advisory/package scan for every keystroke search.
fn uses_osv_text_fts(
    options: &CveAdvancedSearch,
    families: &[String],
    ecosystems: Option<&[String]>,
) -> bool {
    options.query_mode.unwrap_or(CveAdvancedQueryMode::FreeText) == CveAdvancedQueryMode::FreeText
        && options
            .query
            .as_deref()
            .is_some_and(|query| !query.trim().is_empty())
        && options.product.is_none()
        && options.product_exact.is_none()
        && options.vendor.is_none()
        && options.vendor_exact.is_none()
        && families.is_empty()
        && ecosystems.is_none_or(|ecosystems| ecosystems.is_empty())
}

fn advanced_osv_query(options: &CveAdvancedSearch) -> Option<String> {
    let query = [
        options.query.as_deref(),
        options.product.as_deref(),
        options.vendor.as_deref(),
        options.vendor_exact.as_deref(),
    ]
    .into_iter()
    .filter_map(|value| value.map(str::trim).filter(|value| !value.is_empty()))
    .collect::<Vec<_>>()
    .join(" ");
    (!query.is_empty()).then_some(query)
}

async fn search_by_mode(
    db: &CveDatabase,
    mode: SearchMode,
    query: &str,
    state_scope: CveStateScope,
    sort_order: CveSummarySortOrder,
    limit: u64,
    offset: u64,
) -> Result<Vec<CveSummary>, String> {
    if mode == SearchMode::Identifier {
        let resolution = db
            .resolve_identifier(query)
            .await
            .map_err(|err| err.to_string())?;
        return db
            .cve_summaries_by_ids_sorted(
                &resolution.related_cve_ids,
                state_scope,
                sort_order,
                limit,
                offset,
            )
            .await
            .map_err(|err| err.to_string());
    }
    db.search_cve_summaries_advanced(
        &CveAdvancedSearch {
            query: Some(query.to_owned()),
            query_mode: Some(mode.into()),
            state_scope,
            sort_order,
            ..Default::default()
        },
        limit,
        offset,
    )
    .await
    .map_err(|err| err.to_string())
}

async fn count_by_mode(
    db: &CveDatabase,
    mode: SearchMode,
    query: &str,
    state_scope: CveStateScope,
) -> Result<u64, String> {
    match mode {
        SearchMode::FreeText => {
            let cves = db
                .count_cve_summaries_free_text_with_state_scope(query, state_scope)
                .await
                .map_err(|err| err.to_string())?;
            let osv = db
                .count_osv_summaries_free_text(query)
                .await
                .map_err(|err| err.to_string())?;
            Ok(cves + osv)
        }
        SearchMode::Product => {
            let cves = db
                .count_cve_summaries_by_vendor_product_with_state_scope(
                    None,
                    Some(query),
                    state_scope,
                )
                .await
                .map_err(|err| err.to_string())?;
            let osv = db
                .count_osv_summaries_by_package(query)
                .await
                .map_err(|err| err.to_string())?;
            Ok(cves + osv)
        }
        SearchMode::Vendor => {
            let cves = db
                .count_cve_summaries_by_vendor_product_with_state_scope(
                    Some(query),
                    None,
                    state_scope,
                )
                .await
                .map_err(|err| err.to_string())?;
            let osv = db
                .count_osv_summaries_free_text(query)
                .await
                .map_err(|err| err.to_string())?;
            Ok(cves + osv)
        }
        SearchMode::Cwe => {
            db.count_cve_summaries_by_cwe_with_state_scope(&[query.to_owned()], state_scope)
                .await
        }
        SearchMode::Cve => {
            db.count_cve_summaries_by_cve_id_prefix_with_state_scope(query, state_scope)
                .await
        }
        SearchMode::Identifier => db.resolve_identifier(query).await.map(|resolution| {
            (resolution.related_cve_ids.len() + resolution.related_osv_ids.len()) as u64
        }),
    }
    .map_err(|err| err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use qanvuli_core::database::OsvRawRecord;

    #[test]
    fn advanced_osv_search_excludes_cve_only_filters() {
        assert!(!has_cve_only_advanced_filters(&CveAdvancedSearch::default()));
        assert!(!has_cve_only_advanced_filters(&CveAdvancedSearch {
            vendor: Some("Example".to_owned()),
            ..Default::default()
        }));
        assert!(!has_cve_only_advanced_filters(&CveAdvancedSearch {
            product_exact: Some("Django".to_owned()),
            ..Default::default()
        }));
        assert!(has_cve_only_advanced_filters(&CveAdvancedSearch {
            published_from: Some("2026-01-01".to_owned()),
            ..Default::default()
        }));
        assert!(has_cve_only_advanced_filters(&CveAdvancedSearch {
            cwe: Some("CWE-79".to_owned()),
            ..Default::default()
        }));
        assert!(has_cve_only_advanced_filters(&CveAdvancedSearch {
            kev_only: true,
            ..Default::default()
        }));
    }

    #[test]
    fn plain_advanced_free_text_uses_osv_fts() {
        assert!(uses_osv_text_fts(
            &CveAdvancedSearch {
                query: Some("openssl".to_owned()),
                query_mode: Some(CveAdvancedQueryMode::FreeText),
                ..Default::default()
            },
            &[],
            None,
        ));
        assert!(!uses_osv_text_fts(
            &CveAdvancedSearch {
                query: Some("openssl".to_owned()),
                product: Some("openssl".to_owned()),
                ..Default::default()
            },
            &[],
            None,
        ));
        assert!(!uses_osv_text_fts(
            &CveAdvancedSearch {
                query: Some("openssl".to_owned()),
                ..Default::default()
            },
            &["GHSA".to_owned()],
            None,
        ));
    }

    #[test]
    fn package_version_query_requires_ecosystem_package_and_version() {
        assert!(package_version_query(&CveAdvancedSearch::default()).is_none());
        assert!(
            package_version_query(&CveAdvancedSearch {
                package_ecosystem: Some("npm".to_owned()),
                product_exact: Some("jquery".to_owned()),
                ..Default::default()
            })
            .is_none()
        );
        assert_eq!(
            package_version_query(&CveAdvancedSearch {
                package_ecosystem: Some("npm".to_owned()),
                product_exact: Some("jquery".to_owned()),
                package_version: Some("1.10.2".to_owned()),
                ..Default::default()
            }),
            Some(("npm".to_owned(), "jquery".to_owned(), "1.10.2".to_owned()))
        );
    }

    #[test]
    fn identifier_and_free_text_modes_return_osv_only_aliases() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let db = CveDatabase::connect("sqlite::memory:").await.unwrap();
            db.initialize_schema().await.unwrap();
            db.import_osv_records(vec![OsvRawRecord {
                source_path: Some("MAL-2099-1.json".to_owned()),
                raw_json: r#"{
                    "schema_version":"1.7.5",
                    "id":"MAL-2099-1",
                    "modified":"2099-01-02T00:00:00Z",
                    "published":"2099-01-01T00:00:00Z",
                    "aliases":["GHSA-test-alias-only"],
                    "summary":"Malicious test package",
                    "details":"OSV-only fixture",
                    "affected":[],
                    "references":[]
                }"#
                .to_owned(),
            }])
            .await
            .unwrap();

            for mode in [SearchMode::Identifier, SearchMode::FreeText] {
                let result = run_search_request(
                    db.clone(),
                    SearchRequest::Mode {
                        mode,
                        query: "GHSA-test-alias-only".to_owned(),
                        state_scope: CveStateScope::PublishedOnly,
                        kev_only: false,
                        sort_order: CveSummarySortOrder::PublishedDesc,
                    },
                    10,
                    0,
                )
                .await
                .unwrap();
                assert!(result.rows.is_empty());
                assert_eq!(result.osv_rows.len(), 1);
                assert_eq!(result.osv_rows[0].osv_id, "MAL-2099-1");
                assert_eq!(
                    result.osv_rows[0].details.as_deref(),
                    Some("OSV-only fixture")
                );
            }

            let request = SearchRequest::Mode {
                mode: SearchMode::FreeText,
                query: "GHSA-test-alias-only".to_owned(),
                state_scope: CveStateScope::PublishedOnly,
                kev_only: true,
                sort_order: CveSummarySortOrder::PublishedDesc,
            };
            let result = run_search_request(db.clone(), request.clone(), 10, 0)
                .await
                .unwrap();
            assert!(result.rows.is_empty());
            assert!(result.osv_rows.is_empty());
            assert_eq!(run_count_request(db, request).await.unwrap(), 0);
        });
    }

    #[test]
    fn linked_osv_result_is_promoted_to_its_cve() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let db = CveDatabase::connect("sqlite::memory:").await.unwrap();
            db.initialize_schema().await.unwrap();
            db.import_cve_raw_json(
                r#"{
                    "cveMetadata":{
                        "cveId":"CVE-2099-4242",
                        "state":"PUBLISHED",
                        "datePublished":"2099-01-01T00:00:00Z",
                        "dateUpdated":"2099-01-01T00:00:00Z"
                    },
                    "containers":{"cna":{"title":"CVE fixture"}}
                }"#
                .to_owned(),
            )
            .await
            .unwrap();
            db.import_osv_records(vec![OsvRawRecord {
                source_path: Some("GHSA-2099-promoted.json".to_owned()),
                raw_json: r#"{
                    "schema_version":"1.7.5",
                    "id":"GHSA-2099-promoted",
                    "published":"2099-01-01T12:00:00Z",
                    "modified":"2099-01-02T00:00:00Z",
                    "aliases":["CVE-2099-4242"],
                    "summary":"unique-osv-search-needle",
                    "details":"OSV details",
                    "affected":[],
                    "references":[]
                }"#
                .to_owned(),
            }])
            .await
            .unwrap();

            let result = run_search_request(
                db,
                SearchRequest::Mode {
                    mode: SearchMode::FreeText,
                    query: "unique-osv-search-needle".to_owned(),
                    state_scope: CveStateScope::PublishedOnly,
                    kev_only: false,
                    sort_order: CveSummarySortOrder::PublishedDesc,
                },
                10,
                0,
            )
            .await
            .unwrap();

            assert_eq!(result.rows.len(), 1);
            assert_eq!(result.rows[0].summary.cve_id, "CVE-2099-4242");
            assert!(result.osv_rows.is_empty());
            assert_eq!(result.enrichment.len(), 1);
            assert_eq!(result.enrichment[0].osv_ids, "GHSA-2099-promoted");
            let linked = &result.linked_osv["CVE-2099-4242"][0];
            assert_eq!(linked.osv_id, "GHSA-2099-promoted");
            assert_eq!(linked.summary.as_deref(), Some("unique-osv-search-needle"));
            assert_eq!(linked.details.as_deref(), Some("OSV details"));
            assert_eq!(linked.published_at.as_deref(), Some("2099-01-01T12:00:00Z"));
            assert_eq!(result.consumed, 1);
            assert!(result.exhausted);
        });
    }

    #[test]
    fn osv_results_follow_the_tui_sort_order() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let db = CveDatabase::connect("sqlite::memory:").await.unwrap();
            db.initialize_schema().await.unwrap();
            db.import_osv_records(vec![
                OsvRawRecord {
                    source_path: Some("GHSA-sort-older.json".to_owned()),
                    raw_json: r#"{"schema_version":"1.7.5","id":"GHSA-sort-older","published":"2099-01-01T00:00:00Z","modified":"2099-03-01T00:00:00Z","summary":"shared-sort-needle","affected":[],"references":[]}"#.to_owned(),
                },
                OsvRawRecord {
                    source_path: Some("GHSA-sort-newer.json".to_owned()),
                    raw_json: r#"{"schema_version":"1.7.5","id":"GHSA-sort-newer","published":"2099-02-01T00:00:00Z","modified":"2099-01-01T00:00:00Z","summary":"shared-sort-needle","affected":[],"references":[]}"#.to_owned(),
                },
            ])
            .await
            .unwrap();

            for (sort_order, expected) in [
                (CveSummarySortOrder::PublishedAsc, "GHSA-sort-older"),
                (CveSummarySortOrder::PublishedDesc, "GHSA-sort-newer"),
                (CveSummarySortOrder::UpdatedAsc, "GHSA-sort-newer"),
                (CveSummarySortOrder::UpdatedDesc, "GHSA-sort-older"),
            ] {
                let result = run_search_request(
                    db.clone(),
                    SearchRequest::Mode {
                        mode: SearchMode::FreeText,
                        query: "shared-sort-needle".to_owned(),
                        state_scope: CveStateScope::PublishedOnly,
                        kev_only: false,
                        sort_order,
                    },
                    10,
                    0,
                )
                .await
                .unwrap();
                assert_eq!(result.osv_rows[0].osv_id, expected);
            }
        });
    }

    #[test]
    fn product_and_vendor_modes_search_osv_advisories() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let db = CveDatabase::connect("sqlite::memory:").await.unwrap();
            db.initialize_schema().await.unwrap();
            db.import_osv_records(vec![OsvRawRecord {
                source_path: Some("GHSA-product-vendor.json".to_owned()),
                raw_json: r#"{
                    "schema_version":"1.7.5",
                    "id":"GHSA-product-vendor",
                    "modified":"2099-01-02T00:00:00Z",
                    "published":"2099-01-01T00:00:00Z",
                    "summary":"Example Vendor advisory",
                    "affected":[{
                        "package":{"ecosystem":"crates.io","name":"example-product"}
                    }],
                    "references":[]
                }"#
                .to_owned(),
            }])
            .await
            .unwrap();

            for (mode, query) in [
                (SearchMode::Product, "example-product"),
                (SearchMode::Vendor, "Example Vendor"),
            ] {
                let result = run_search_request(
                    db.clone(),
                    SearchRequest::Mode {
                        mode,
                        query: query.to_owned(),
                        state_scope: CveStateScope::PublishedOnly,
                        kev_only: false,
                        sort_order: CveSummarySortOrder::PublishedDesc,
                    },
                    10,
                    0,
                )
                .await
                .unwrap();
                assert!(result.rows.is_empty());
                assert_eq!(result.osv_rows.len(), 1);

                let count = run_count_request(
                    db.clone(),
                    SearchRequest::Mode {
                        mode,
                        query: query.to_owned(),
                        state_scope: CveStateScope::PublishedOnly,
                        kev_only: false,
                        sort_order: CveSummarySortOrder::PublishedDesc,
                    },
                )
                .await
                .unwrap();
                assert_eq!(count, 1);
            }

            let request = SearchRequest::Advanced {
                options: CveAdvancedSearch {
                    product: Some("example-product".to_owned()),
                    ..Default::default()
                },
                include_cve: false,
                include_osv: true,
                osv_families: vec!["GHSA".to_owned()],
                ecosystems: None,
            };
            let result = run_search_request(db.clone(), request.clone(), 10, 0)
                .await
                .unwrap();
            assert_eq!(result.osv_rows.len(), 1);
            assert_eq!(run_count_request(db.clone(), request).await.unwrap(), 1);

            for (name, options) in [
                (
                    "published_from",
                    CveAdvancedSearch {
                        published_from: Some("2099-01-01".to_owned()),
                        ..Default::default()
                    },
                ),
                (
                    "cwe",
                    CveAdvancedSearch {
                        cwe: Some("CWE-79".to_owned()),
                        ..Default::default()
                    },
                ),
            ] {
                let request = SearchRequest::Advanced {
                    options,
                    include_cve: false,
                    include_osv: true,
                    osv_families: vec!["GHSA".to_owned()],
                    ecosystems: None,
                };
                let result = run_search_request(db.clone(), request.clone(), 10, 0)
                    .await
                    .unwrap();
                assert!(result.osv_rows.is_empty(), "{name}");
                assert_eq!(
                    run_count_request(db.clone(), request).await.unwrap(),
                    0,
                    "{name}"
                );
            }
        });
    }
}
