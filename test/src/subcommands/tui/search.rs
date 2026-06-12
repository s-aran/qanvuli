use super::mode::SearchMode;
use qanvuli_db::{CveAdvancedSearch, CveDatabase, CveSummary};

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
) -> Result<Vec<CveSummary>, String> {
    match request {
        SearchRequest::Mode { mode, query } => mode.search(&db, &query, limit, offset).await,
        SearchRequest::Advanced(options) => db
            .search_cve_summaries_advanced(&options, limit, offset)
            .await
            .map_err(|err| err.to_string()),
    }
}
