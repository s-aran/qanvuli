use crate::mode::SearchMode;
use qanvuli_core::database::{
    CveAdvancedSearch, CveDatabase, CveStateScope, CveSummary, CveSummaryWithDetail,
    EnrichedCveSummary, OsvSummary,
};

#[derive(Debug)]
pub(crate) struct SearchResult {
    pub(crate) rows: Vec<CveSummaryWithDetail>,
    pub(crate) osv_rows: Vec<OsvSummary>,
    pub(crate) enrichment: Vec<EnrichedCveSummary>,
}

#[derive(Clone, Debug)]
pub(crate) enum SearchRequest {
    Mode {
        mode: SearchMode,
        query: String,
        state_scope: CveStateScope,
        kev_only: bool,
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
        } => {
            let rows = if kev_only {
                db.search_cve_summaries_advanced(
                    &CveAdvancedSearch {
                        query: Some(query.clone()),
                        query_mode: Some(mode.into()),
                        state_scope,
                        kev_only: true,
                        ..Default::default()
                    },
                    limit,
                    offset,
                )
                .await
                .map_err(|err| err.to_string())?
            } else {
                search_by_mode(&db, mode, &query, state_scope, limit, offset).await?
            };
            let osv_rows = if kev_only {
                Vec::new()
            } else {
                search_osv_by_mode(&db, mode, &query, limit, offset).await?
            };
            let rows = db
                .attach_cve_overview_details(rows)
                .await
                .map_err(|err| err.to_string())?;
            let enrichment = load_enrichment_summaries(&db, &rows).await?;
            Ok(SearchResult {
                rows,
                osv_rows,
                enrichment,
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
            let rows = if include_cve {
                db.search_cve_summaries_advanced(&options, limit, offset)
                    .await
                    .map_err(|err| err.to_string())?
            } else {
                Vec::new()
            };
            let osv_rows =
                if options.kev_only || !include_osv || has_cve_only_advanced_filters(&options) {
                    Vec::new()
                } else if let Some(package_name) = options
                    .product_exact
                    .as_deref()
                    .map(str::trim)
                    .filter(|name| !name.is_empty())
                {
                    db.search_osv_summaries_scoped_by_exact_package(
                        osv_query.as_deref(),
                        &osv_families,
                        ecosystems.as_deref(),
                        package_name,
                        limit,
                        offset,
                    )
                    .await
                    .map_err(|err| err.to_string())?
                } else {
                    db.search_osv_summaries_scoped(
                        osv_query.as_deref(),
                        &osv_families,
                        ecosystems.as_deref(),
                        limit,
                        offset,
                    )
                    .await
                    .map_err(|err| err.to_string())?
                };
            let rows = db
                .attach_cve_overview_details(rows)
                .await
                .map_err(|err| err.to_string())?;
            let enrichment = load_enrichment_summaries(&db, &rows).await?;
            Ok(SearchResult {
                rows,
                osv_rows,
                enrichment,
            })
        }
    }
}

async fn search_osv_by_mode(
    db: &CveDatabase,
    mode: SearchMode,
    query: &str,
    limit: u64,
    offset: u64,
) -> Result<Vec<OsvSummary>, String> {
    match mode {
        SearchMode::FreeText => db
            .search_osv_summaries_free_text(query, limit, offset)
            .await
            .map_err(|err| err.to_string()),
        SearchMode::Identifier => {
            let resolution = db
                .resolve_identifier(query)
                .await
                .map_err(|err| err.to_string())?;
            let osv_ids = resolution
                .related_osv_ids
                .into_iter()
                .skip(offset as usize)
                .take(limit as usize)
                .collect::<Vec<_>>();
            db.get_enriched_osv_many(&osv_ids)
                .await
                .map_err(|err| err.to_string())
        }
        SearchMode::Product => db
            .search_osv_summaries_by_package(query, limit, offset)
            .await
            .map_err(|err| err.to_string()),
        SearchMode::Vendor => db
            .search_osv_summaries_free_text(query, limit, offset)
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
        } => {
            if kev_only {
                let cve = db
                    .count_cve_summaries_advanced(&CveAdvancedSearch {
                        query: Some(query.clone()),
                        query_mode: Some(mode.into()),
                        state_scope,
                        kev_only: true,
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
                db.count_cve_summaries_advanced(&options)
                    .await
                    .map_err(|err| err.to_string())?
            } else {
                0
            };
            let osv = if options.kev_only || !include_osv || has_cve_only_advanced_filters(&options)
            {
                0
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
    limit: u64,
    offset: u64,
) -> Result<Vec<CveSummary>, String> {
    match mode {
        SearchMode::FreeText => {
            db.search_cve_summaries_free_text_with_state_scope(query, state_scope, limit, offset)
                .await
        }
        SearchMode::Product => {
            db.search_cve_summaries_by_vendor_product_with_state_scope(
                None,
                Some(query),
                state_scope,
                limit,
                offset,
            )
            .await
        }
        SearchMode::Vendor => {
            db.search_cve_summaries_by_vendor_product_with_state_scope(
                Some(query),
                None,
                state_scope,
                limit,
                offset,
            )
            .await
        }
        SearchMode::Cwe => {
            db.search_cve_summaries_by_cwe_with_state_scope(
                &[query.to_owned()],
                state_scope,
                limit,
                offset,
            )
            .await
        }
        SearchMode::Cve => {
            db.search_cve_summaries_by_cve_id_prefix_with_state_scope(
                query,
                state_scope,
                limit,
                offset,
            )
            .await
        }
        SearchMode::Identifier => {
            let resolution = db
                .resolve_identifier(query)
                .await
                .map_err(|err| err.to_string())?;
            let mut rows = Vec::new();
            for cve_id in resolution
                .related_cve_ids
                .into_iter()
                .skip(offset as usize)
                .take(limit as usize)
            {
                if let Some(row) = db
                    .find_cve_summary_with_detail(&cve_id)
                    .await
                    .map_err(|err| err.to_string())?
                {
                    rows.push(row.summary);
                }
            }
            Ok(rows)
        }
    }
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
                    },
                    10,
                    0,
                )
                .await
                .unwrap();
                assert!(result.rows.is_empty());
                assert_eq!(result.osv_rows.len(), 1);
                assert_eq!(result.osv_rows[0].osv_id, "MAL-2099-1");
            }

            let request = SearchRequest::Mode {
                mode: SearchMode::FreeText,
                query: "GHSA-test-alias-only".to_owned(),
                state_scope: CveStateScope::PublishedOnly,
                kev_only: true,
            };
            let result = run_search_request(db.clone(), request.clone(), 10, 0)
                .await
                .unwrap();
            assert!(result.rows.is_empty());
            assert_eq!(result.osv_rows.len(), 1);
            assert_eq!(run_count_request(db, request).await.unwrap(), 1);
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
