use super::mode::SearchMode;
use qanvuli_db::{CveAdvancedSearch, CveDatabase, CveSummary};

#[derive(Debug)]
pub(super) struct SearchResult {
    pub(super) rows: Vec<CveSummary>,
    pub(super) total: u64,
}

#[derive(Clone, Debug)]
pub(super) enum SearchRequest {
    Mode { mode: SearchMode, query: String },
    Advanced(CveAdvancedSearch),
}

pub(super) async fn run_search_request(
    db: CveDatabase,
    request: SearchRequest,
    limit: u64,
    offset: u64,
) -> Result<SearchResult, String> {
    match request {
        SearchRequest::Mode { mode, query } => {
            let (rows, total) = tokio::try_join!(
                mode.search(&db, &query, limit, offset),
                mode.count(&db, &query)
            )?;
            Ok(SearchResult { rows, total })
        }
        SearchRequest::Advanced(options) => {
            let (rows, total) = tokio::try_join!(
                async {
                    db.search_cve_summaries_advanced(&options, limit, offset)
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
