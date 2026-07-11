use crate::mode::SearchMode;
use qanvuli_core::database::{
    CveAdvancedSearch, CveDatabase, CveStateScope, CveSummary, CveSummaryWithDetail,
    EnrichedCveSummary,
};

#[derive(Debug)]
pub(crate) struct SearchResult {
    pub(crate) rows: Vec<CveSummaryWithDetail>,
    pub(crate) enrichment: Vec<EnrichedCveSummary>,
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
            let rows = search_by_mode(&db, mode, &query, state_scope, limit, offset).await?;
            let rows = db
                .attach_cve_overview_details(rows)
                .await
                .map_err(|err| err.to_string())?;
            let enrichment = load_enrichment_summaries(&db, &rows).await?;
            Ok(SearchResult { rows, enrichment })
        }
        SearchRequest::Advanced(options) => {
            let rows = db
                .search_cve_summaries_advanced(&options, limit, offset)
                .await
                .map_err(|err| err.to_string())?;
            let rows = db
                .attach_cve_overview_details(rows)
                .await
                .map_err(|err| err.to_string())?;
            let enrichment = load_enrichment_summaries(&db, &rows).await?;
            Ok(SearchResult { rows, enrichment })
        }
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
        SearchRequest::Advanced(options) => db
            .count_cve_summaries_advanced(&options)
            .await
            .map_err(|err| err.to_string()),
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
        SearchMode::Identifier => db
            .resolve_identifier(query)
            .await
            .map(|resolution| resolution.related_cve_ids.len() as u64),
    }
    .map_err(|err| err.to_string())
}
