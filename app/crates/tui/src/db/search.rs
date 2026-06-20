use crate::mode::SearchMode;
use qanvuli_db::{CveAdvancedSearch, CveDatabase, CveStateScope, CveSummary, CveSummaryWithDetail};

#[derive(Debug)]
pub(crate) struct SearchResult {
    pub(crate) rows: Vec<CveSummaryWithDetail>,
    pub(crate) total: u64,
}

#[derive(Clone, Debug)]
pub(crate) enum SearchRequest {
    Mode {
        mode: SearchMode,
        query: String,
        state_scope: CveStateScope,
    },
    Advanced(CveAdvancedSearch),
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
            let (rows, total) = tokio::try_join!(
                async {
                    let rows =
                        search_by_mode(&db, mode, &query, state_scope, limit, offset).await?;
                    db.attach_cve_details(rows)
                        .await
                        .map_err(|err| err.to_string())
                },
                count_by_mode(&db, mode, &query, state_scope)
            )?;
            Ok(SearchResult { rows, total })
        }
        SearchRequest::Advanced(options) => {
            let (rows, total) = tokio::try_join!(
                async {
                    let rows = db
                        .search_cve_summaries_advanced(&options, limit, offset)
                        .await
                        .map_err(|err| err.to_string())?;
                    db.attach_cve_details(rows)
                        .await
                        .map_err(|err| err.to_string())
                },
                async {
                    db.count_cve_summaries_advanced(&options)
                        .await
                        .map_err(|err| err.to_string())
                }
            )?;
            Ok(SearchResult { rows, total })
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
            db.count_cve_summaries_free_text_with_state_scope(query, state_scope)
                .await
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
    }
    .map_err(|err| err.to_string())
}
