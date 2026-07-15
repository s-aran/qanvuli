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
    },
    Advanced {
        options: CveAdvancedSearch,
        include_cve: bool,
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
        } => {
            let rows = search_by_mode(&db, mode, &query, state_scope, limit, offset).await?;
            let osv_rows = search_osv_by_mode(&db, mode, &query, limit, offset).await?;
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
            osv_families,
            ecosystems,
        } => {
            let rows = if include_cve {
                db.search_cve_summaries_advanced(&options, limit, offset)
                    .await
                    .map_err(|err| err.to_string())?
            } else {
                Vec::new()
            };
            let osv_rows = if osv_families.is_empty() {
                Vec::new()
            } else {
                db.search_osv_summaries_scoped(
                    options.query.as_deref(),
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
            let mut rows = Vec::new();
            for osv_id in resolution
                .related_osv_ids
                .into_iter()
                .skip(offset as usize)
                .take(limit as usize)
            {
                if let Some(row) = db
                    .get_enriched_osv(&osv_id)
                    .await
                    .map_err(|err| err.to_string())?
                {
                    rows.push(row);
                }
            }
            Ok(rows)
        }
        _ => Ok(Vec::new()),
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
        } => count_by_mode(&db, mode, &query, state_scope).await,
        SearchRequest::Advanced {
            options,
            include_cve,
            osv_families,
            ecosystems,
        } => {
            let cve = if include_cve {
                db.count_cve_summaries_advanced(&options)
                    .await
                    .map_err(|err| err.to_string())?
            } else {
                0
            };
            let osv = if osv_families.is_empty() {
                0
            } else {
                db.count_osv_summaries_scoped(
                    options.query.as_deref(),
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
            db.count_cve_summaries_by_vendor_product_with_state_scope(
                None,
                Some(query),
                state_scope,
            )
            .await
        }
        SearchMode::Vendor => {
            db.count_cve_summaries_by_vendor_product_with_state_scope(
                Some(query),
                None,
                state_scope,
            )
            .await
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
        });
    }
}
