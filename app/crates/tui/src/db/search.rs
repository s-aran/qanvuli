use crate::mode::SearchMode;
use qanvuli_core::database::{
    CveAdvancedQueryMode, CveAdvancedSearch, CveDatabase, CveStateScope, CveSummary,
    CveSummarySortOrder, CveSummaryWithDetail, EnrichedCveSummary, OsvSummary,
};
use std::{
    cmp::Ordering,
    collections::{BTreeSet, HashMap},
};

#[derive(Debug)]
pub(crate) struct SearchResult {
    pub(crate) candidates: Vec<SearchCandidate>,
    pub(crate) enrichment: Vec<EnrichedCveSummary>,
    pub(crate) linked_osv: HashMap<String, Vec<OsvSummary>>,
    pub(crate) consumed: u64,
    pub(crate) exhausted: bool,
    pub(crate) continuation: SearchContinuation,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct SearchContinuation {
    cve_offset: u64,
    osv_offset: u64,
}

#[derive(Debug)]
pub(crate) enum SearchCandidate {
    Cve(CveSummaryWithDetail),
    Osv(OsvSummary),
}

enum CandidateSummary {
    Cve(CveSummary),
    Osv(OsvSummary),
}

struct RankedCandidate {
    source_rank: u64,
    summary: CandidateSummary,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum SearchTerm {
    FreeText(String),
    Product(String),
    Vendor(String),
    Cwe(String),
    CvePrefix(String),
    Identifier(String),
}

impl SearchTerm {
    pub(crate) fn new(mode: SearchMode, value: String) -> Self {
        match mode {
            SearchMode::FreeText => Self::FreeText(value),
            SearchMode::Product => Self::Product(value),
            SearchMode::Vendor => Self::Vendor(value),
            SearchMode::Cwe => Self::Cwe(value),
            SearchMode::Cve => Self::CvePrefix(value),
            SearchMode::Identifier => Self::Identifier(value),
        }
    }

    fn value(&self) -> &str {
        match self {
            Self::FreeText(value)
            | Self::Product(value)
            | Self::Vendor(value)
            | Self::Cwe(value)
            | Self::CvePrefix(value)
            | Self::Identifier(value) => value,
        }
    }

    fn advanced_query_mode(&self) -> Option<CveAdvancedQueryMode> {
        match self {
            Self::FreeText(_) => Some(CveAdvancedQueryMode::FreeText),
            Self::Product(_) => Some(CveAdvancedQueryMode::Product),
            Self::Vendor(_) => Some(CveAdvancedQueryMode::Vendor),
            Self::Cwe(_) => Some(CveAdvancedQueryMode::Cwe),
            Self::CvePrefix(_) => Some(CveAdvancedQueryMode::Cve),
            Self::Identifier(_) => None,
        }
    }

    fn advanced_options(
        &self,
        state_scope: CveStateScope,
        kev_only: bool,
        sort_order: CveSummarySortOrder,
    ) -> Option<CveAdvancedSearch> {
        Some(CveAdvancedSearch {
            query: Some(self.value().to_owned()),
            query_mode: Some(self.advanced_query_mode()?),
            state_scope,
            kev_only,
            sort_order,
            ..Default::default()
        })
    }
}

#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum SearchRequest {
    Query {
        term: SearchTerm,
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

impl SearchRequest {
    /// An unfiltered browse can page efficiently, but an exact total requires scanning the whole
    /// CVE table. Keep the total unknown instead of making the TUI compete with that scan.
    pub(crate) fn should_count(&self) -> bool {
        !matches!(
            self,
            Self::Advanced {
                options,
                osv_families,
                ecosystems,
                ..
            } if is_unfiltered_browse(options)
                && osv_families.is_empty()
                && ecosystems.as_ref().is_none_or(Vec::is_empty)
        )
    }
}

fn is_unfiltered_browse(options: &CveAdvancedSearch) -> bool {
    [
        options.query.as_deref(),
        options.published_from.as_deref(),
        options.published_to.as_deref(),
        options.cwe.as_deref(),
        options.product.as_deref(),
        options.product_exact.as_deref(),
        options.package_ecosystem.as_deref(),
        options.package_version.as_deref(),
        options.vendor.as_deref(),
        options.vendor_exact.as_deref(),
    ]
    .into_iter()
    .all(|value| value.is_none_or(|value| value.trim().is_empty()))
        && !options.kev_only
}

pub(crate) async fn run_search_request(
    db: CveDatabase,
    request: SearchRequest,
    limit: u64,
    offset: u64,
) -> Result<SearchResult, String> {
    run_search_request_at(db, request, limit, SearchPosition::Offset(offset)).await
}

pub(crate) async fn run_search_request_after(
    db: CveDatabase,
    request: SearchRequest,
    limit: u64,
    continuation: SearchContinuation,
) -> Result<SearchResult, String> {
    run_search_request_at(db, request, limit, SearchPosition::Continue(continuation)).await
}

async fn run_search_request_at(
    db: CveDatabase,
    request: SearchRequest,
    limit: u64,
    position: SearchPosition,
) -> Result<SearchResult, String> {
    let limit = limit.max(1);
    match request {
        SearchRequest::Query {
            term,
            state_scope,
            kev_only,
            sort_order,
        } => {
            let include_cve = !kev_only || term.advanced_query_mode().is_some();
            let include_osv = !kev_only
                && matches!(
                    term,
                    SearchTerm::FreeText(_) | SearchTerm::Product(_) | SearchTerm::Identifier(_)
                );
            let page = source_page(limit, position, include_cve && include_osv);
            let osv_db = independent_database(&db).await;
            let rows_future = async {
                if kev_only
                    && let Some(options) = term.advanced_options(state_scope, true, sort_order)
                {
                    db.search_cve_summaries_advanced(&options, page.fetch_limit, page.cve_offset)
                        .await
                        .map_err(|err| err.to_string())
                } else if kev_only {
                    Ok(Vec::new())
                } else {
                    search_by_term(
                        &db,
                        &term,
                        state_scope,
                        sort_order,
                        page.fetch_limit,
                        page.cve_offset,
                    )
                    .await
                }
            };
            let osv_future = async {
                if kev_only {
                    Ok(Vec::new())
                } else {
                    search_osv_by_term(
                        &osv_db,
                        &term,
                        sort_order,
                        page.fetch_limit,
                        page.osv_offset,
                    )
                    .await
                }
            };
            let (rows, osv_rows) = tokio::try_join!(rows_future, osv_future)?;
            finish_search_result(&db, &osv_db, rows, osv_rows, sort_order, page).await
        }
        SearchRequest::Advanced {
            options,
            include_cve,
            include_osv,
            osv_families,
            ecosystems,
        } => {
            let include_osv = include_osv
                && package_version_query(&options).is_none()
                && !options.kev_only
                && !has_cve_only_advanced_filters(&options);
            let page = source_page(limit, position, include_cve && include_osv);
            let osv_db = independent_database(&db).await;
            let (rows, osv_rows) = tokio::try_join!(
                search_advanced_cves(
                    &db,
                    &options,
                    include_cve,
                    page.fetch_limit,
                    page.cve_offset,
                ),
                search_advanced_osv(
                    &osv_db,
                    &options,
                    include_osv,
                    &osv_families,
                    ecosystems.as_deref(),
                    page.fetch_limit,
                    page.osv_offset,
                )
            )?;
            finish_search_result(&db, &osv_db, rows, osv_rows, options.sort_order, page).await
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SearchPosition {
    Offset(u64),
    Continue(SearchContinuation),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SourcePage {
    page_limit: u64,
    fetch_limit: u64,
    cve_offset: u64,
    osv_offset: u64,
    slice_offset: u64,
}

fn source_page(limit: u64, position: SearchPosition, mixed_sources: bool) -> SourcePage {
    match position {
        SearchPosition::Continue(continuation) => SourcePage {
            page_limit: limit,
            fetch_limit: limit.saturating_add(1),
            cve_offset: continuation.cve_offset,
            osv_offset: continuation.osv_offset,
            slice_offset: 0,
        },
        SearchPosition::Offset(offset) if mixed_sources => {
            // Direct callers may request an arbitrary global offset. The sequential TUI path
            // resumes each source independently through the continuation branch above.
            SourcePage {
                page_limit: limit,
                fetch_limit: offset.saturating_add(limit).saturating_add(1),
                cve_offset: 0,
                osv_offset: 0,
                slice_offset: offset,
            }
        }
        SearchPosition::Offset(offset) => SourcePage {
            page_limit: limit,
            fetch_limit: limit.saturating_add(1),
            cve_offset: offset,
            osv_offset: offset,
            slice_offset: 0,
        },
    }
}

async fn finish_search_result(
    db: &CveDatabase,
    related_db: &CveDatabase,
    rows: Vec<CveSummary>,
    osv_rows: Vec<OsvSummary>,
    sort_order: CveSummarySortOrder,
    page: SourcePage,
) -> Result<SearchResult, String> {
    let mut merged = rows
        .into_iter()
        .enumerate()
        .map(|(source_rank, row)| RankedCandidate {
            source_rank: page.cve_offset.saturating_add(source_rank as u64),
            summary: CandidateSummary::Cve(row),
        })
        .chain(
            osv_rows
                .into_iter()
                .enumerate()
                .map(|(source_rank, row)| RankedCandidate {
                    source_rank: page.osv_offset.saturating_add(source_rank as u64),
                    summary: CandidateSummary::Osv(row),
                }),
        )
        .collect::<Vec<_>>();
    merged.sort_by(|left, right| compare_ranked_candidates(left, right, sort_order));
    let merged_len = merged.len();
    let consumed_prefix = merged
        .iter()
        .take(page.slice_offset.saturating_add(page.page_limit) as usize)
        .fold(SearchContinuation::default(), |mut consumed, candidate| {
            match candidate.summary {
                CandidateSummary::Cve(_) => consumed.cve_offset += 1,
                CandidateSummary::Osv(_) => consumed.osv_offset += 1,
            }
            consumed
        });
    let page_candidates = merged
        .into_iter()
        .skip(page.slice_offset as usize)
        .take(page.page_limit as usize)
        .map(|candidate| candidate.summary)
        .collect::<Vec<_>>();
    let cve_rows = page_candidates
        .iter()
        .filter_map(|candidate| match candidate {
            CandidateSummary::Cve(row) => Some(row.clone()),
            CandidateSummary::Osv(_) => None,
        })
        .collect::<Vec<_>>();
    let (rows, enrichment, linked_osv) = attach_search_data(db, related_db, cve_rows).await?;
    let mut rows = rows
        .into_iter()
        .map(|row| (row.summary.cve_id.clone(), row))
        .collect::<HashMap<_, _>>();
    let candidates = page_candidates
        .into_iter()
        .filter_map(|candidate| match candidate {
            CandidateSummary::Cve(row) => rows.remove(&row.cve_id).map(SearchCandidate::Cve),
            CandidateSummary::Osv(row) => Some(SearchCandidate::Osv(row)),
        })
        .collect::<Vec<_>>();
    let consumed = candidates.len() as u64;
    let exhausted = merged_len <= page.slice_offset.saturating_add(page.page_limit) as usize;
    Ok(SearchResult {
        candidates,
        enrichment,
        linked_osv,
        consumed,
        exhausted,
        continuation: SearchContinuation {
            cve_offset: page.cve_offset.saturating_add(consumed_prefix.cve_offset),
            osv_offset: page.osv_offset.saturating_add(consumed_prefix.osv_offset),
        },
    })
}

fn compare_ranked_candidates(
    left: &RankedCandidate,
    right: &RankedCandidate,
    sort_order: CveSummarySortOrder,
) -> Ordering {
    match sort_order {
        CveSummarySortOrder::PublishedAsc | CveSummarySortOrder::PublishedDesc => {
            let ascending = sort_order == CveSummarySortOrder::PublishedAsc;
            compare_optional_datetime(
                candidate_published(&left.summary),
                candidate_published(&right.summary),
                ascending,
            )
            .then_with(|| candidate_source(&left.summary).cmp(&candidate_source(&right.summary)))
            .then_with(|| left.source_rank.cmp(&right.source_rank))
        }
        CveSummarySortOrder::UpdatedAsc | CveSummarySortOrder::UpdatedDesc => {
            let ascending = sort_order == CveSummarySortOrder::UpdatedAsc;
            compare_optional_datetime(
                candidate_updated(&left.summary),
                candidate_updated(&right.summary),
                ascending,
            )
            .then_with(|| candidate_source(&left.summary).cmp(&candidate_source(&right.summary)))
            .then_with(|| left.source_rank.cmp(&right.source_rank))
        }
        CveSummarySortOrder::CveIdAsc => candidate_source(&left.summary)
            .cmp(&candidate_source(&right.summary))
            .then_with(|| left.source_rank.cmp(&right.source_rank)),
        CveSummarySortOrder::CveIdDesc => candidate_source(&left.summary)
            .cmp(&candidate_source(&right.summary))
            .reverse()
            .then_with(|| left.source_rank.cmp(&right.source_rank)),
        CveSummarySortOrder::ScoreAsc | CveSummarySortOrder::ScoreDesc => {
            candidate_source(&left.summary)
                .cmp(&candidate_source(&right.summary))
                .then_with(|| left.source_rank.cmp(&right.source_rank))
        }
        CveSummarySortOrder::RelationRankAsc | CveSummarySortOrder::RelationRankDesc => left
            .source_rank
            .cmp(&right.source_rank)
            .then_with(|| candidate_source(&left.summary).cmp(&candidate_source(&right.summary))),
    }
}

fn candidate_published(candidate: &CandidateSummary) -> Option<&str> {
    match candidate {
        CandidateSummary::Cve(row) => Some(&row.published_at),
        CandidateSummary::Osv(row) => row.published_at.as_deref(),
    }
}

fn candidate_updated(candidate: &CandidateSummary) -> Option<&str> {
    match candidate {
        CandidateSummary::Cve(row) => Some(&row.updated_at),
        CandidateSummary::Osv(row) => row.modified_at.as_deref(),
    }
}

fn candidate_source(candidate: &CandidateSummary) -> u8 {
    match candidate {
        CandidateSummary::Cve(_) => 0,
        CandidateSummary::Osv(_) => 1,
    }
}

fn compare_optional_datetime(left: Option<&str>, right: Option<&str>, ascending: bool) -> Ordering {
    match (left, right) {
        (Some(left), Some(right)) => {
            // Match SQLite's ordering exactly so each source prefix remains valid for the merge.
            let order = left.cmp(right);
            if ascending { order } else { order.reverse() }
        }
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

async fn attach_search_data(
    db: &CveDatabase,
    related_db: &CveDatabase,
    rows: Vec<CveSummary>,
) -> Result<
    (
        Vec<CveSummaryWithDetail>,
        Vec<EnrichedCveSummary>,
        HashMap<String, Vec<OsvSummary>>,
    ),
    String,
> {
    let cve_ids = rows
        .iter()
        .map(|row| row.cve_id.clone())
        .collect::<Vec<_>>();
    let details = async {
        db.attach_cve_overview_details(rows)
            .await
            .map_err(|err| err.to_string())
    };
    let related = async {
        let enrichment = related_db
            .enriched_cve_summaries(&cve_ids)
            .await
            .map_err(|err| err.to_string())?;
        let linked_osv = related_db
            .osv_summaries_for_cve_ids(&cve_ids)
            .await
            .map_err(|err| err.to_string())?;
        Ok::<_, String>((enrichment, linked_osv))
    };
    let (rows, (enrichment, linked_osv)) = tokio::try_join!(details, related)?;
    Ok((rows, enrichment, linked_osv))
}

async fn search_advanced_cves(
    db: &CveDatabase,
    options: &CveAdvancedSearch,
    include_cve: bool,
    limit: u64,
    offset: u64,
) -> Result<Vec<CveSummary>, String> {
    if !include_cve {
        return Ok(Vec::new());
    }
    if let Some((ecosystem, package, version)) = package_version_query(options) {
        let findings = db
            .query_package_matches(&ecosystem, &package, &version, None)
            .await
            .map_err(|err| err.to_string())?;
        let cve_ids = findings
            .into_iter()
            .filter(|finding| finding.affected.status == "affected")
            .flat_map(|finding| finding.cve_ids)
            .collect::<BTreeSet<_>>()
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
        .map_err(|err| err.to_string())
    } else {
        db.search_cve_summaries_advanced(options, limit, offset)
            .await
            .map_err(|err| err.to_string())
    }
}

#[allow(clippy::too_many_arguments)]
async fn search_advanced_osv(
    db: &CveDatabase,
    options: &CveAdvancedSearch,
    include_osv: bool,
    osv_families: &[String],
    ecosystems: Option<&[String]>,
    limit: u64,
    offset: u64,
) -> Result<Vec<OsvSummary>, String> {
    let osv_text_query = advanced_osv_text_query(options);
    if package_version_query(options).is_some()
        || options.kev_only
        || !include_osv
        || has_cve_only_advanced_filters(options)
    {
        return Ok(Vec::new());
    }
    if let Some(package) = osv_package_query(options) {
        db.search_osv_summaries_scoped_by_package_and_text_sorted(
            osv_text_query,
            osv_families,
            ecosystems,
            package,
            options.sort_order,
            limit,
            offset,
        )
        .await
        .map_err(|err| err.to_string())
    } else if uses_osv_text_fts(options, osv_families, ecosystems) {
        db.search_osv_summaries_free_text_sorted(
            options.query.as_deref().unwrap_or_default(),
            options.sort_order,
            limit,
            offset,
        )
        .await
        .map_err(|err| err.to_string())
    } else if let Some(package_name) = options
        .product_exact
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
    {
        db.search_osv_summaries_scoped_by_exact_package_sorted(
            osv_text_query,
            osv_families,
            ecosystems,
            package_name,
            options.sort_order,
            limit,
            offset,
        )
        .await
        .map_err(|err| err.to_string())
    } else {
        db.search_osv_summaries_scoped_sorted(
            osv_text_query,
            osv_families,
            ecosystems,
            options.sort_order,
            limit,
            offset,
        )
        .await
        .map_err(|err| err.to_string())
    }
}

async fn search_osv_by_term(
    db: &CveDatabase,
    term: &SearchTerm,
    sort_order: CveSummarySortOrder,
    limit: u64,
    offset: u64,
) -> Result<Vec<OsvSummary>, String> {
    match term {
        SearchTerm::FreeText(query) => db
            .search_osv_summaries_free_text_sorted(query, sort_order, limit, offset)
            .await
            .map_err(|err| err.to_string()),
        SearchTerm::Identifier(query) => {
            let resolution = db
                .resolve_identifier(query)
                .await
                .map_err(|err| err.to_string())?;
            db.osv_summaries_by_ids_sorted(&resolution.related_osv_ids, sort_order, limit, offset)
                .await
                .map_err(|err| err.to_string())
        }
        SearchTerm::Product(query) => db
            .search_osv_summaries_scoped_by_package_sorted(
                &[],
                None,
                query,
                sort_order,
                limit,
                offset,
            )
            .await
            .map_err(|err| err.to_string()),
        // OSV has no normalized vendor field. Treating arbitrary advisory text as a vendor
        // match produces false positives, so vendor searches intentionally remain CVE-only.
        SearchTerm::Vendor(_) | SearchTerm::Cwe(_) | SearchTerm::CvePrefix(_) => Ok(Vec::new()),
    }
}

pub(crate) async fn run_count_request(
    db: CveDatabase,
    request: SearchRequest,
) -> Result<u64, String> {
    // Counting starts after the first page is visible. Keep this potentially expensive full-result
    // query off the primary connection so detail loading and subsequent interaction stay responsive.
    let db = independent_database(&db).await;
    match request {
        SearchRequest::Query {
            term,
            state_scope,
            kev_only,
            sort_order,
        } => {
            if kev_only && let Some(options) = term.advanced_options(state_scope, true, sort_order)
            {
                let cve = db
                    .count_cve_summaries_advanced(&options)
                    .await
                    .map_err(|err| err.to_string())?;
                Ok(cve)
            } else if kev_only {
                Ok(0)
            } else {
                count_by_term(&db, &term, state_scope).await
            }
        }
        SearchRequest::Advanced {
            options,
            include_cve,
            include_osv,
            osv_families,
            ecosystems,
        } => {
            let osv_text_query = advanced_osv_text_query(&options);
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
            } else if let Some(package) = osv_package_query(&options) {
                db.count_osv_summaries_scoped_by_package_and_text(
                    osv_text_query,
                    &osv_families,
                    ecosystems.as_deref(),
                    package,
                )
                .await
                .map_err(|err| err.to_string())?
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
                    osv_text_query,
                    &osv_families,
                    ecosystems.as_deref(),
                    package_name,
                )
                .await
                .map_err(|err| err.to_string())?
            } else {
                db.count_osv_summaries_scoped(osv_text_query, &osv_families, ecosystems.as_deref())
                    .await
                    .map_err(|err| err.to_string())?
            };
            Ok(cve + osv)
        }
    }
}

async fn independent_database(db: &CveDatabase) -> CveDatabase {
    db.independent_connection()
        .await
        .unwrap_or_else(|_| db.clone())
}

fn has_cve_only_advanced_filters(options: &CveAdvancedSearch) -> bool {
    [
        options.published_from.as_deref(),
        options.published_to.as_deref(),
        options.cwe.as_deref(),
    ]
    .into_iter()
    .any(|value| value.is_some_and(|value| !value.trim().is_empty()))
        || (matches!(
            options.query_mode,
            Some(
                CveAdvancedQueryMode::Vendor
                    | CveAdvancedQueryMode::Cwe
                    | CveAdvancedQueryMode::Cve
            )
        ) && options
            .query
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty()))
        || options
            .vendor
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
        || options
            .vendor_exact
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
        || options.kev_only
}

fn osv_package_query(options: &CveAdvancedSearch) -> Option<&str> {
    let value = if options.query_mode == Some(CveAdvancedQueryMode::Product) {
        options.query.as_deref()
    } else {
        options.product.as_deref()
    }?;
    let value = value.trim();
    (!value.is_empty()).then_some(value)
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

fn advanced_osv_text_query(options: &CveAdvancedSearch) -> Option<&str> {
    (options.query_mode.unwrap_or(CveAdvancedQueryMode::FreeText) == CveAdvancedQueryMode::FreeText)
        .then_some(options.query.as_deref())
        .flatten()
        .map(str::trim)
        .filter(|query| !query.is_empty())
}

async fn search_by_term(
    db: &CveDatabase,
    term: &SearchTerm,
    state_scope: CveStateScope,
    sort_order: CveSummarySortOrder,
    limit: u64,
    offset: u64,
) -> Result<Vec<CveSummary>, String> {
    if let SearchTerm::Identifier(query) = term {
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
    let options = term
        .advanced_options(state_scope, false, sort_order)
        .expect("only identifiers lack an advanced query mode");
    db.search_cve_summaries_advanced(&options, limit, offset)
        .await
        .map_err(|err| err.to_string())
}

async fn count_by_term(
    db: &CveDatabase,
    term: &SearchTerm,
    state_scope: CveStateScope,
) -> Result<u64, String> {
    match term {
        SearchTerm::FreeText(query) => {
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
        SearchTerm::Product(query) => {
            let cves = db
                .count_cve_summaries_by_vendor_product_with_state_scope(
                    None,
                    Some(query),
                    state_scope,
                )
                .await
                .map_err(|err| err.to_string())?;
            let osv = db
                .count_osv_summaries_scoped_by_package(&[], None, query)
                .await
                .map_err(|err| err.to_string())?;
            Ok(cves + osv)
        }
        SearchTerm::Vendor(query) => {
            let cves = db
                .count_cve_summaries_by_vendor_product_with_state_scope(
                    Some(query),
                    None,
                    state_scope,
                )
                .await
                .map_err(|err| err.to_string())?;
            Ok(cves)
        }
        SearchTerm::Cwe(query) => {
            db.count_cve_summaries_by_cwe_with_state_scope(std::slice::from_ref(query), state_scope)
                .await
        }
        SearchTerm::CvePrefix(query) => {
            db.count_cve_summaries_by_cve_id_prefix_with_state_scope(query, state_scope)
                .await
        }
        SearchTerm::Identifier(query) => db.resolve_identifier(query).await.map(|resolution| {
            (resolution.related_cve_ids.len() + resolution.related_osv_ids.len()) as u64
        }),
    }
    .map_err(|err| err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use qanvuli_core::database::OsvRawRecord;

    fn cve_candidates(result: &SearchResult) -> Vec<&CveSummaryWithDetail> {
        result
            .candidates
            .iter()
            .filter_map(|candidate| match candidate {
                SearchCandidate::Cve(cve) => Some(cve),
                SearchCandidate::Osv(_) => None,
            })
            .collect()
    }

    fn osv_candidates(result: &SearchResult) -> Vec<&OsvSummary> {
        result
            .candidates
            .iter()
            .filter_map(|candidate| match candidate {
                SearchCandidate::Cve(_) => None,
                SearchCandidate::Osv(osv) => Some(osv),
            })
            .collect()
    }

    fn candidate_ids(result: &SearchResult) -> Vec<&str> {
        result
            .candidates
            .iter()
            .map(|candidate| match candidate {
                SearchCandidate::Cve(cve) => cve.summary.cve_id.as_str(),
                SearchCandidate::Osv(osv) => osv.osv_id.as_str(),
            })
            .collect()
    }

    #[test]
    fn advanced_osv_search_excludes_cve_only_filters() {
        assert!(!has_cve_only_advanced_filters(&CveAdvancedSearch::default()));
        assert!(has_cve_only_advanced_filters(&CveAdvancedSearch {
            vendor: Some("Example".to_owned()),
            ..Default::default()
        }));
        for query_mode in [
            CveAdvancedQueryMode::Vendor,
            CveAdvancedQueryMode::Cwe,
            CveAdvancedQueryMode::Cve,
        ] {
            assert!(has_cve_only_advanced_filters(&CveAdvancedSearch {
                query: Some("Example".to_owned()),
                query_mode: Some(query_mode),
                ..Default::default()
            }));
        }
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
    fn arbitrary_offsets_use_a_prefix_but_continuations_resume_each_source() {
        assert_eq!(
            source_page(30, SearchPosition::Offset(3_000), false),
            SourcePage {
                page_limit: 30,
                fetch_limit: 31,
                cve_offset: 3_000,
                osv_offset: 3_000,
                slice_offset: 0,
            }
        );
        assert_eq!(
            source_page(30, SearchPosition::Offset(3_000), true),
            SourcePage {
                page_limit: 30,
                fetch_limit: 3_031,
                cve_offset: 0,
                osv_offset: 0,
                slice_offset: 3_000,
            }
        );
        assert_eq!(
            source_page(
                30,
                SearchPosition::Continue(SearchContinuation {
                    cve_offset: 2_100,
                    osv_offset: 900,
                }),
                true,
            ),
            SourcePage {
                page_limit: 30,
                fetch_limit: 31,
                cve_offset: 2_100,
                osv_offset: 900,
                slice_offset: 0,
            }
        );
    }

    #[test]
    fn only_an_unfiltered_browse_skips_the_expensive_exact_count() {
        let request = SearchRequest::Advanced {
            options: CveAdvancedSearch::default(),
            include_cve: true,
            include_osv: false,
            osv_families: Vec::new(),
            ecosystems: None,
        };
        assert!(!request.should_count());

        let blank_query = SearchRequest::Advanced {
            options: CveAdvancedSearch {
                query: Some("  \t".to_owned()),
                ..Default::default()
            },
            include_cve: true,
            include_osv: false,
            osv_families: Vec::new(),
            ecosystems: None,
        };
        assert!(!blank_query.should_count());

        for (name, options) in [
            (
                "query",
                CveAdvancedSearch {
                    query: Some("openssl".to_owned()),
                    ..Default::default()
                },
            ),
            (
                "published_from",
                CveAdvancedSearch {
                    published_from: Some("2099-01-01".to_owned()),
                    ..Default::default()
                },
            ),
            (
                "published_to",
                CveAdvancedSearch {
                    published_to: Some("2099-12-31".to_owned()),
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
            (
                "product",
                CveAdvancedSearch {
                    product: Some("openssl".to_owned()),
                    ..Default::default()
                },
            ),
            (
                "product_exact",
                CveAdvancedSearch {
                    product_exact: Some("openssl".to_owned()),
                    ..Default::default()
                },
            ),
            (
                "ecosystem",
                CveAdvancedSearch {
                    package_ecosystem: Some("crates.io".to_owned()),
                    ..Default::default()
                },
            ),
            (
                "version",
                CveAdvancedSearch {
                    package_version: Some("1.0.0".to_owned()),
                    ..Default::default()
                },
            ),
            (
                "vendor",
                CveAdvancedSearch {
                    vendor: Some("Acme".to_owned()),
                    ..Default::default()
                },
            ),
            (
                "vendor_exact",
                CveAdvancedSearch {
                    vendor_exact: Some("Acme".to_owned()),
                    ..Default::default()
                },
            ),
            (
                "kev",
                CveAdvancedSearch {
                    kev_only: true,
                    ..Default::default()
                },
            ),
        ] {
            let filtered = SearchRequest::Advanced {
                options,
                include_cve: true,
                include_osv: false,
                osv_families: Vec::new(),
                ecosystems: None,
            };
            assert!(filtered.should_count(), "{name} filter was ignored");
        }

        for (name, osv_families, ecosystems) in [
            ("OSV family", vec!["GHSA".to_owned()], None),
            (
                "OSV ecosystem",
                Vec::new(),
                Some(vec!["crates.io".to_owned()]),
            ),
        ] {
            let filtered = SearchRequest::Advanced {
                options: CveAdvancedSearch::default(),
                include_cve: true,
                include_osv: true,
                osv_families,
                ecosystems,
            };
            assert!(filtered.should_count(), "{name} filter was ignored");
        }
    }

    #[test]
    fn empty_published_browse_stays_sorted_across_page_boundaries() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let db = CveDatabase::connect("sqlite::memory:").await.unwrap();
            db.initialize_schema().await.unwrap();
            let base = chrono::DateTime::parse_from_rfc3339("2099-03-01T00:00:00Z").unwrap();
            let records = (0..23)
                .map(|index| {
                    let published = (base - chrono::Duration::minutes(index)).to_rfc3339();
                    let id_year = if index % 2 == 0 { 2098 } else { 2099 };
                    format!(
                        r#"{{"cveMetadata":{{"cveId":"CVE-{id_year}-{index:04}","state":"PUBLISHED","datePublished":"{published}","dateUpdated":"{published}"}},"containers":{{"cna":{{"title":"paged browse {index}"}}}}}}"#
                    )
                })
                .collect();
            db.import_cve_raw_jsons(records).await.unwrap();
            let request = SearchRequest::Advanced {
                options: CveAdvancedSearch {
                    query_mode: Some(CveAdvancedQueryMode::FreeText),
                    sort_order: CveSummarySortOrder::PublishedDesc,
                    ..Default::default()
                },
                include_cve: true,
                include_osv: false,
                osv_families: Vec::new(),
                ecosystems: None,
            };
            let mut rows = Vec::new();
            for offset in [0, 10, 20] {
                let result = run_search_request(db.clone(), request.clone(), 10, offset)
                    .await
                    .unwrap();
                let expected_page_len = if offset == 20 { 3 } else { 10 };
                assert_eq!(result.consumed, expected_page_len);
                assert_eq!(result.exhausted, offset == 20);
                rows.extend(result.candidates.into_iter().map(|candidate| match candidate {
                    SearchCandidate::Cve(cve) => cve,
                    SearchCandidate::Osv(osv) => {
                        panic!("CVE-only browse returned unexpected OSV {}", osv.osv_id)
                    }
                }));
            }

            let expected_ids = (0..23)
                .map(|index| {
                    let id_year = if index % 2 == 0 { 2098 } else { 2099 };
                    format!("CVE-{id_year}-{index:04}")
                })
                .collect::<Vec<_>>();
            assert_eq!(
                rows.iter()
                    .map(|row| row.summary.cve_id.as_str())
                    .collect::<Vec<_>>(),
                expected_ids
            );
            assert!(rows.windows(2).all(|pair| {
                pair[0].summary.published_at >= pair[1].summary.published_at
            }));
        });
    }

    #[tokio::test]
    async fn mixed_date_sorts_keep_exact_order_with_ties_missing_dates_and_variable_pages() {
        let db = CveDatabase::connect("sqlite::memory:").await.unwrap();
        db.initialize_schema().await.unwrap();
        db.import_cve_raw_jsons(vec![
            r#"{"cveMetadata":{"cveId":"CVE-2099-1","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-04-01T00:00:00Z"},"containers":{"cna":{"title":"boundaryaudit one"}}}"#.to_owned(),
            r#"{"cveMetadata":{"cveId":"CVE-2099-2","state":"PUBLISHED","datePublished":"2099-02-01T00:00:00Z","dateUpdated":"2099-03-01T00:00:00Z"},"containers":{"cna":{"title":"boundaryaudit two"}}}"#.to_owned(),
        ])
        .await
        .unwrap();
        db.import_osv_records(vec![
            OsvRawRecord {
                source_path: None,
                raw_json: r#"{"schema_version":"1.7.5","id":"GHSA-boundary-one","published":"2099-01-01T00:00:00Z","modified":"2099-02-01T00:00:00Z","summary":"boundaryaudit three","affected":[]}"#.to_owned(),
            },
            OsvRawRecord {
                source_path: None,
                raw_json: r#"{"schema_version":"1.7.5","id":"GHSA-boundary-two","published":"2099-03-01T00:00:00Z","modified":"2099-03-01T00:00:00Z","summary":"boundaryaudit four","affected":[]}"#.to_owned(),
            },
            OsvRawRecord {
                source_path: None,
                raw_json: r#"{"schema_version":"1.7.5","id":"GHSA-boundary-undated","modified":"2099-01-01T00:00:00Z","summary":"boundaryaudit five","affected":[]}"#.to_owned(),
            },
        ])
        .await
        .unwrap();

        for (sort_order, expected) in [
            (
                CveSummarySortOrder::PublishedAsc,
                [
                    "CVE-2099-1",
                    "GHSA-boundary-one",
                    "CVE-2099-2",
                    "GHSA-boundary-two",
                    "GHSA-boundary-undated",
                ],
            ),
            (
                CveSummarySortOrder::PublishedDesc,
                [
                    "GHSA-boundary-two",
                    "CVE-2099-2",
                    "CVE-2099-1",
                    "GHSA-boundary-one",
                    "GHSA-boundary-undated",
                ],
            ),
            (
                CveSummarySortOrder::UpdatedAsc,
                [
                    "GHSA-boundary-undated",
                    "GHSA-boundary-one",
                    "CVE-2099-2",
                    "GHSA-boundary-two",
                    "CVE-2099-1",
                ],
            ),
            (
                CveSummarySortOrder::UpdatedDesc,
                [
                    "CVE-2099-1",
                    "CVE-2099-2",
                    "GHSA-boundary-two",
                    "GHSA-boundary-one",
                    "GHSA-boundary-undated",
                ],
            ),
        ] {
            let request = SearchRequest::Query {
                term: SearchTerm::FreeText("boundaryaudit".to_owned()),
                state_scope: CveStateScope::PublishedOnly,
                kev_only: false,
                sort_order,
            };
            let complete = run_search_request(db.clone(), request.clone(), 10, 0)
                .await
                .unwrap();
            assert_eq!(
                candidate_ids(&complete),
                expected,
                "unexpected {sort_order:?}"
            );
            assert!(complete.exhausted);

            let mut paged = Vec::new();
            let mut continuation = None;
            for page_size in [2, 1, 2] {
                let result = if let Some(continuation) = continuation {
                    run_search_request_after(db.clone(), request.clone(), page_size, continuation)
                        .await
                } else {
                    run_search_request(db.clone(), request.clone(), page_size, 0).await
                }
                .unwrap();
                continuation = Some(result.continuation);
                paged.extend(candidate_ids(&result).into_iter().map(str::to_owned));
            }
            assert_eq!(
                paged.iter().map(String::as_str).collect::<Vec<_>>(),
                expected,
                "variable pages changed {sort_order:?} order"
            );
        }

        for sort_order in [
            CveSummarySortOrder::RelationRankAsc,
            CveSummarySortOrder::RelationRankDesc,
        ] {
            let request = SearchRequest::Query {
                term: SearchTerm::FreeText("boundaryaudit".to_owned()),
                state_scope: CveStateScope::PublishedOnly,
                kev_only: false,
                sort_order,
            };
            let complete = run_search_request(db.clone(), request.clone(), 10, 0)
                .await
                .unwrap();
            let expected = candidate_ids(&complete)
                .into_iter()
                .map(str::to_owned)
                .collect::<Vec<_>>();
            let mut continuation = None;
            let mut paged = Vec::new();
            for _ in 0..expected.len() {
                let result = if let Some(continuation) = continuation {
                    run_search_request_after(db.clone(), request.clone(), 1, continuation).await
                } else {
                    run_search_request(db.clone(), request.clone(), 1, 0).await
                }
                .unwrap();
                continuation = Some(result.continuation);
                paged.extend(candidate_ids(&result).into_iter().map(str::to_owned));
            }
            assert_eq!(paged, expected, "continuation changed {sort_order:?} order");
        }
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
                    SearchRequest::Query {
                        term: SearchTerm::new(mode, "GHSA-test-alias-only".to_owned()),
                        state_scope: CveStateScope::PublishedOnly,
                        kev_only: false,
                        sort_order: CveSummarySortOrder::PublishedDesc,
                    },
                    10,
                    0,
                )
                .await
                .unwrap();
                assert!(cve_candidates(&result).is_empty());
                let osv = osv_candidates(&result);
                assert_eq!(osv.len(), 1);
                assert_eq!(osv[0].osv_id, "MAL-2099-1");
                assert_eq!(osv[0].details.as_deref(), Some("OSV-only fixture"));
            }

            let request = SearchRequest::Query {
                term: SearchTerm::FreeText("GHSA-test-alias-only".to_owned()),
                state_scope: CveStateScope::PublishedOnly,
                kev_only: true,
                sort_order: CveSummarySortOrder::PublishedDesc,
            };
            let result = run_search_request(db.clone(), request.clone(), 10, 0)
                .await
                .unwrap();
            assert!(result.candidates.is_empty());
            assert_eq!(run_count_request(db, request).await.unwrap(), 0);
        });
    }

    #[test]
    fn linked_osv_result_keeps_the_matching_osv_as_the_candidate() {
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
                SearchRequest::Query {
                    term: SearchTerm::FreeText("unique-osv-search-needle".to_owned()),
                    state_scope: CveStateScope::PublishedOnly,
                    kev_only: false,
                    sort_order: CveSummarySortOrder::PublishedDesc,
                },
                10,
                0,
            )
            .await
            .unwrap();

            assert_eq!(candidate_ids(&result), ["GHSA-2099-promoted"]);
            assert!(result.enrichment.is_empty());
            assert!(result.linked_osv.is_empty());
            let osv = osv_candidates(&result);
            assert_eq!(osv[0].summary.as_deref(), Some("unique-osv-search-needle"));
            assert_eq!(osv[0].details.as_deref(), Some("OSV details"));
            assert_eq!(osv[0].published_at.as_deref(), Some("2099-01-01T12:00:00Z"));
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
                OsvRawRecord {
                    source_path: Some("GHSA-sort-undated.json".to_owned()),
                    raw_json: r#"{"schema_version":"1.7.5","id":"GHSA-sort-undated","modified":"2099-02-01T00:00:00Z","summary":"shared-sort-needle","affected":[],"references":[]}"#.to_owned(),
                },
            ])
            .await
            .unwrap();

            let unfiltered = run_search_request(
                db.clone(),
                SearchRequest::Advanced {
                    options: CveAdvancedSearch {
                        sort_order: CveSummarySortOrder::PublishedDesc,
                        ..Default::default()
                    },
                    include_cve: false,
                    include_osv: true,
                    osv_families: Vec::new(),
                    ecosystems: None,
                },
                10,
                0,
            )
            .await
            .unwrap();
            assert_eq!(
                candidate_ids(&unfiltered),
                ["GHSA-sort-newer", "GHSA-sort-older", "GHSA-sort-undated"]
            );

            for (sort_order, expected) in [
                (
                    CveSummarySortOrder::PublishedAsc,
                    ["GHSA-sort-older", "GHSA-sort-newer", "GHSA-sort-undated"],
                ),
                (
                    CveSummarySortOrder::PublishedDesc,
                    ["GHSA-sort-newer", "GHSA-sort-older", "GHSA-sort-undated"],
                ),
                (
                    CveSummarySortOrder::UpdatedAsc,
                    ["GHSA-sort-newer", "GHSA-sort-undated", "GHSA-sort-older"],
                ),
                (
                    CveSummarySortOrder::UpdatedDesc,
                    ["GHSA-sort-older", "GHSA-sort-undated", "GHSA-sort-newer"],
                ),
                (
                    CveSummarySortOrder::CveIdAsc,
                    ["GHSA-sort-newer", "GHSA-sort-older", "GHSA-sort-undated"],
                ),
                (
                    CveSummarySortOrder::CveIdDesc,
                    ["GHSA-sort-undated", "GHSA-sort-older", "GHSA-sort-newer"],
                ),
            ] {
                let result = run_search_request(
                    db.clone(),
                    SearchRequest::Query {
                        term: SearchTerm::FreeText("shared-sort-needle".to_owned()),
                        state_scope: CveStateScope::PublishedOnly,
                        kev_only: false,
                        sort_order,
                    },
                    10,
                    0,
                )
                .await
                .unwrap();
                assert_eq!(candidate_ids(&result), expected, "unexpected {sort_order:?}");
            }

            let published = run_search_request(
                db,
                SearchRequest::Query {
                    term: SearchTerm::FreeText("shared-sort-needle".to_owned()),
                    state_scope: CveStateScope::PublishedOnly,
                    kev_only: false,
                    sort_order: CveSummarySortOrder::PublishedDesc,
                },
                10,
                0,
            )
            .await
            .unwrap();
            assert_eq!(
                osv_candidates(&published)
                    .into_iter()
                    .map(|row| row.published_at.as_deref())
                    .collect::<Vec<_>>(),
                [
                    Some("2099-02-01T00:00:00Z"),
                    Some("2099-01-01T00:00:00Z"),
                    None,
                ]
            );
        });
    }

    #[test]
    fn product_mode_uses_osv_packages_while_vendor_mode_remains_cve_only() {
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
                    "summary":"Example Vendor remote advisory",
                    "details":"execution consequence",
                    "affected":[{
                        "package":{"ecosystem":"crates.io","name":"example-product"}
                    }],
                    "references":[]
                }"#
                .to_owned(),
            }])
            .await
            .unwrap();
            db.import_osv_records(vec![OsvRawRecord {
                source_path: Some("GHSA-product-name-only.json".to_owned()),
                raw_json: r#"{
                    "schema_version":"1.7.5",
                    "id":"GHSA-product-name-only",
                    "modified":"2099-01-03T00:00:00Z",
                    "published":"2099-01-02T00:00:00Z",
                    "summary":"example-product is mentioned but not affected",
                    "affected":[],
                    "references":[]
                }"#
                .to_owned(),
            }])
            .await
            .unwrap();
            db.import_cve_raw_jsons(vec![
                r#"{"cveMetadata":{"cveId":"CVE-2099-3001","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-01T00:00:00Z"},"containers":{"cna":{"title":"actual affected vendor","affected":[{"vendor":"Example Vendor","product":"unrelated"}]}}}"#.to_owned(),
                r#"{"cveMetadata":{"cveId":"CVE-2099-3002","state":"PUBLISHED","datePublished":"2099-02-01T00:00:00Z","dateUpdated":"2099-02-01T00:00:00Z"},"containers":{"cna":{"title":"Example Vendor appears only in free text","affected":[{"vendor":"Other Vendor","product":"unrelated"}]}}}"#.to_owned(),
            ])
            .await
            .unwrap();

            let product_request = SearchRequest::Query {
                term: SearchTerm::Product("example-product".to_owned()),
                state_scope: CveStateScope::PublishedOnly,
                kev_only: false,
                sort_order: CveSummarySortOrder::PublishedDesc,
            };
            let product_result = run_search_request(db.clone(), product_request.clone(), 10, 0)
                .await
                .unwrap();
            assert!(cve_candidates(&product_result).is_empty());
            assert_eq!(candidate_ids(&product_result), ["GHSA-product-vendor"]);
            assert_eq!(
                run_count_request(db.clone(), product_request)
                    .await
                    .unwrap(),
                1
            );

            let vendor_request = SearchRequest::Query {
                term: SearchTerm::Vendor("Example Vendor".to_owned()),
                state_scope: CveStateScope::PublishedOnly,
                kev_only: false,
                sort_order: CveSummarySortOrder::PublishedDesc,
            };
            let vendor_result = run_search_request(db.clone(), vendor_request.clone(), 10, 0)
                .await
                .unwrap();
            let vendor_cves = cve_candidates(&vendor_result);
            assert_eq!(vendor_cves.len(), 1);
            assert_eq!(vendor_cves[0].summary.cve_id, "CVE-2099-3001");
            assert!(osv_candidates(&vendor_result).is_empty());
            assert_eq!(
                run_count_request(db.clone(), vendor_request).await.unwrap(),
                1
            );

            db.import_osv_records(vec![OsvRawRecord {
                source_path: Some("GHSA-product-older.json".to_owned()),
                raw_json: r#"{
                    "schema_version":"1.7.5",
                    "id":"GHSA-product-older",
                    "modified":"2099-01-01T00:00:00Z",
                    "published":"2098-12-31T00:00:00Z",
                    "summary":"Older matching package",
                    "affected":[{
                        "package":{"ecosystem":"crates.io","name":"example-product-addon"}
                    }],
                    "references":[]
                }"#
                .to_owned(),
            }])
            .await
            .unwrap();

            for query in ["remote execution", "execution remote"] {
                let request = SearchRequest::Advanced {
                    options: CveAdvancedSearch {
                        query: Some(query.to_owned()),
                        query_mode: Some(CveAdvancedQueryMode::FreeText),
                        product: Some("example-product".to_owned()),
                        ..Default::default()
                    },
                    include_cve: false,
                    include_osv: true,
                    osv_families: vec!["GHSA".to_owned()],
                    ecosystems: Some(vec!["crates.io".to_owned()]),
                };
                let result = run_search_request(db.clone(), request.clone(), 10, 0)
                    .await
                    .unwrap();
                assert_eq!(candidate_ids(&result), ["GHSA-product-vendor"]);
                assert_eq!(run_count_request(db.clone(), request).await.unwrap(), 1);
            }

            let scoped_text_request = SearchRequest::Advanced {
                options: CveAdvancedSearch {
                    query: Some("execution remote".to_owned()),
                    query_mode: Some(CveAdvancedQueryMode::FreeText),
                    ..Default::default()
                },
                include_cve: false,
                include_osv: true,
                osv_families: vec!["GHSA".to_owned()],
                ecosystems: None,
            };
            let result =
                run_search_request(db.clone(), scoped_text_request.clone(), 10, 0)
                    .await
                    .unwrap();
            assert_eq!(candidate_ids(&result), ["GHSA-product-vendor"]);
            assert_eq!(
                run_count_request(db.clone(), scoped_text_request)
                    .await
                    .unwrap(),
                1
            );

            let product_request = SearchRequest::Advanced {
                options: CveAdvancedSearch {
                    query: Some("example-product".to_owned()),
                    query_mode: Some(CveAdvancedQueryMode::Product),
                    sort_order: CveSummarySortOrder::UpdatedDesc,
                    ..Default::default()
                },
                include_cve: false,
                include_osv: true,
                osv_families: Vec::new(),
                ecosystems: None,
            };
            let product_result = run_search_request(db.clone(), product_request.clone(), 10, 0)
                .await
                .unwrap();
            let product_osv = osv_candidates(&product_result);
            assert_eq!(product_osv.len(), 2);
            assert_eq!(product_osv[0].osv_id, "GHSA-product-vendor");
            assert_eq!(
                product_osv[0].package_summary.as_deref(),
                Some("crates.io:example-product")
            );
            assert_eq!(product_osv[1].osv_id, "GHSA-product-older");
            assert_eq!(
                run_count_request(db.clone(), product_request)
                    .await
                    .unwrap(),
                2
            );

            for (sort_order, expected) in [
                (
                    CveSummarySortOrder::UpdatedAsc,
                    ["GHSA-product-older", "GHSA-product-vendor"],
                ),
                (
                    CveSummarySortOrder::UpdatedDesc,
                    ["GHSA-product-vendor", "GHSA-product-older"],
                ),
                (
                    CveSummarySortOrder::CveIdAsc,
                    ["GHSA-product-older", "GHSA-product-vendor"],
                ),
                (
                    CveSummarySortOrder::CveIdDesc,
                    ["GHSA-product-vendor", "GHSA-product-older"],
                ),
            ] {
                let result = run_search_request(
                    db.clone(),
                    SearchRequest::Query {
                        term: SearchTerm::Product("example-product".to_owned()),
                        state_scope: CveStateScope::PublishedOnly,
                        kev_only: false,
                        sort_order,
                    },
                    10,
                    0,
                )
                .await
                .unwrap();
                assert_eq!(
                    osv_candidates(&result)
                        .into_iter()
                        .map(|row| row.osv_id.as_str())
                        .collect::<Vec<_>>(),
                    expected,
                    "unexpected product OSV {sort_order:?} order"
                );
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
            assert_eq!(
                candidate_ids(&result),
                ["GHSA-product-vendor", "GHSA-product-older"]
            );
            assert_eq!(run_count_request(db.clone(), request).await.unwrap(), 2);

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
                (
                    "vendor query mode",
                    CveAdvancedSearch {
                        query: Some("Example Vendor".to_owned()),
                        query_mode: Some(CveAdvancedQueryMode::Vendor),
                        ..Default::default()
                    },
                ),
                (
                    "CWE query mode",
                    CveAdvancedSearch {
                        query: Some("Example".to_owned()),
                        query_mode: Some(CveAdvancedQueryMode::Cwe),
                        ..Default::default()
                    },
                ),
                (
                    "CVE query mode",
                    CveAdvancedSearch {
                        query: Some("Example".to_owned()),
                        query_mode: Some(CveAdvancedQueryMode::Cve),
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
                assert!(result.candidates.is_empty(), "{name}");
                assert_eq!(
                    run_count_request(db.clone(), request).await.unwrap(),
                    0,
                    "{name}"
                );
            }
        });
    }

    #[test]
    fn product_mode_does_not_fall_back_to_cve_free_text() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let db = CveDatabase::connect("sqlite::memory:").await.unwrap();
            db.initialize_schema().await.unwrap();
            db.import_cve_raw_jsons(vec![
                r#"{"cveMetadata":{"cveId":"CVE-2099-1001","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-01T00:00:00Z"},"containers":{"cna":{"title":"actual affected product","affected":[{"vendor":"Acme","product":"example-product"}]}}}"#.to_owned(),
                r#"{"cveMetadata":{"cveId":"CVE-2099-1002","state":"PUBLISHED","datePublished":"2099-02-01T00:00:00Z","dateUpdated":"2099-02-01T00:00:00Z"},"containers":{"cna":{"title":"example-product appears only in free text","affected":[{"vendor":"Other","product":"unrelated"}]}}}"#.to_owned(),
            ])
            .await
            .unwrap();

            let result = run_search_request(
                db,
                SearchRequest::Advanced {
                    options: CveAdvancedSearch {
                        query: Some("example-product".to_owned()),
                        query_mode: Some(CveAdvancedQueryMode::Product),
                        sort_order: CveSummarySortOrder::PublishedDesc,
                        ..Default::default()
                    },
                    include_cve: true,
                    include_osv: false,
                    osv_families: Vec::new(),
                    ecosystems: None,
                },
                10,
                0,
            )
            .await
            .unwrap();

            let cves = cve_candidates(&result);
            assert_eq!(cves.len(), 1);
            assert_eq!(cves[0].summary.cve_id, "CVE-2099-1001");
            assert_eq!(
                cves[0].detail.affected[0].product.as_deref(),
                Some("example-product")
            );
        });
    }

    #[test]
    fn every_typed_cve_search_honors_updated_and_natural_id_sorting() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let db = CveDatabase::connect("sqlite::memory:").await.unwrap();
            db.initialize_schema().await.unwrap();
            db.import_cve_raw_jsons(vec![
                r#"{"cveMetadata":{"cveId":"CVE-2099-9998","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-04-01T00:00:00Z"},"containers":{"cna":{"title":"shared matrix sorting needle","affected":[{"vendor":"Matrix Vendor","product":"matrix-product"}],"problemTypes":[{"descriptions":[{"cweId":"CWE-79"}]}]}}}"#.to_owned(),
                r#"{"cveMetadata":{"cveId":"CVE-2099-9999","state":"PUBLISHED","datePublished":"2099-02-01T00:00:00Z","dateUpdated":"2099-01-01T00:00:00Z"},"containers":{"cna":{"title":"shared matrix sorting needle","affected":[{"vendor":"Matrix Vendor","product":"matrix-product"}],"problemTypes":[{"descriptions":[{"cweId":"CWE-79"}]}]}}}"#.to_owned(),
                r#"{"cveMetadata":{"cveId":"CVE-2099-10000","state":"PUBLISHED","datePublished":"2099-03-01T00:00:00Z","dateUpdated":"2099-01-01T00:00:00Z"},"containers":{"cna":{"title":"shared matrix sorting needle","affected":[{"vendor":"Matrix Vendor","product":"matrix-product"}],"problemTypes":[{"descriptions":[{"cweId":"CWE-79"}]}]}}}"#.to_owned(),
            ])
            .await
            .unwrap();
            db.import_osv_records(vec![OsvRawRecord {
                source_path: Some("GHSA-matrix-sort.json".to_owned()),
                raw_json: r#"{
                    "schema_version":"1.7.5",
                    "id":"GHSA-matrix-sort",
                    "modified":"2099-04-01T00:00:00Z",
                    "published":"2099-04-01T00:00:00Z",
                    "summary":"identifier relation fixture",
                    "aliases":["CVE-2099-9998","CVE-2099-9999","CVE-2099-10000"],
                    "affected":[],
                    "references":[]
                }"#
                .to_owned(),
            }])
            .await
            .unwrap();

            let terms = [
                SearchTerm::FreeText("shared matrix sorting".to_owned()),
                SearchTerm::Product("matrix-product".to_owned()),
                SearchTerm::Vendor("Matrix Vendor".to_owned()),
                SearchTerm::Cwe("cwe-79".to_owned()),
                SearchTerm::CvePrefix("CVE-2099-".to_owned()),
                SearchTerm::Identifier("GHSA-matrix-sort".to_owned()),
            ];
            for term in terms {
                for (sort_order, expected) in [
                    (
                        CveSummarySortOrder::UpdatedAsc,
                        ["CVE-2099-9999", "CVE-2099-10000", "CVE-2099-9998"],
                    ),
                    (
                        CveSummarySortOrder::UpdatedDesc,
                        ["CVE-2099-9998", "CVE-2099-10000", "CVE-2099-9999"],
                    ),
                    (
                        CveSummarySortOrder::CveIdAsc,
                        ["CVE-2099-9998", "CVE-2099-9999", "CVE-2099-10000"],
                    ),
                    (
                        CveSummarySortOrder::CveIdDesc,
                        ["CVE-2099-10000", "CVE-2099-9999", "CVE-2099-9998"],
                    ),
                ] {
                    let result = run_search_request(
                        db.clone(),
                        SearchRequest::Query {
                            term: term.clone(),
                            state_scope: CveStateScope::PublishedOnly,
                            kev_only: false,
                            sort_order,
                        },
                        10,
                        0,
                    )
                    .await
                    .unwrap();
                    assert_eq!(
                        cve_candidates(&result)
                            .into_iter()
                            .map(|row| row.summary.cve_id.as_str())
                            .collect::<Vec<_>>(),
                        expected,
                        "unexpected {sort_order:?} order for {term:?}"
                    );
                }
            }
        });
    }

    #[test]
    fn free_text_requires_every_whitespace_separated_term_for_cve_and_osv() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let db = CveDatabase::connect("sqlite::memory:").await.unwrap();
            db.initialize_schema().await.unwrap();
            db.import_cve_raw_jsons(vec![
                r#"{"cveMetadata":{"cveId":"CVE-2099-4101","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-01T00:00:00Z"},"containers":{"cna":{"title":"quartz material","descriptions":[{"lang":"en","value":"a distant falcon appears in another field"}]}}}"#.to_owned(),
                r#"{"cveMetadata":{"cveId":"CVE-2099-4102","state":"PUBLISHED","datePublished":"2099-01-02T00:00:00Z","dateUpdated":"2099-01-02T00:00:00Z"},"containers":{"cna":{"title":"quartz only"}}}"#.to_owned(),
                r#"{"cveMetadata":{"cveId":"CVE-2099-4103","state":"PUBLISHED","datePublished":"2099-01-03T00:00:00Z","dateUpdated":"2099-01-03T00:00:00Z"},"containers":{"cna":{"title":"falcon only"}}}"#.to_owned(),
            ])
            .await
            .unwrap();
            db.import_osv_records(vec![
                OsvRawRecord {
                    source_path: Some("GHSA-2099-both.json".to_owned()),
                    raw_json: r#"{"schema_version":"1.7.5","id":"GHSA-2099-both","modified":"2099-01-01T00:00:00Z","summary":"quartz advisory","details":"the separate details contain falcon","affected":[],"references":[]}"#.to_owned(),
                },
                OsvRawRecord {
                    source_path: Some("GHSA-2099-quartz.json".to_owned()),
                    raw_json: r#"{"schema_version":"1.7.5","id":"GHSA-2099-quartz","modified":"2099-01-02T00:00:00Z","summary":"quartz only","affected":[],"references":[]}"#.to_owned(),
                },
                OsvRawRecord {
                    source_path: Some("GHSA-2099-falcon.json".to_owned()),
                    raw_json: r#"{"schema_version":"1.7.5","id":"GHSA-2099-falcon","modified":"2099-01-03T00:00:00Z","summary":"falcon only","affected":[],"references":[]}"#.to_owned(),
                },
            ])
            .await
            .unwrap();

            for query in ["quartz falcon", "falcon quartz"] {
                let request = SearchRequest::Query {
                    term: SearchTerm::FreeText(query.to_owned()),
                    state_scope: CveStateScope::PublishedOnly,
                    kev_only: false,
                    sort_order: CveSummarySortOrder::PublishedDesc,
                };
                let result = run_search_request(db.clone(), request.clone(), 10, 0)
                    .await
                    .unwrap();

                assert_eq!(
                    candidate_ids(&result),
                    ["CVE-2099-4101", "GHSA-2099-both"],
                    "query order changed AND semantics: {query}"
                );
                assert_eq!(run_count_request(db.clone(), request).await.unwrap(), 2);
            }
        });
    }
}
