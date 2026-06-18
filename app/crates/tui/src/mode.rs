use qanvuli_db::{CveDatabase, CveStateScope, CveSummary};
use ratatui::style::Color;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SearchMode {
    FreeText,
    Product,
    Vendor,
    Cwe,
    Cve,
}

impl SearchMode {
    pub(super) fn next(self) -> Self {
        match self {
            Self::FreeText => Self::Product,
            Self::Product => Self::Vendor,
            Self::Vendor => Self::Cwe,
            Self::Cwe => Self::Cve,
            Self::Cve => Self::FreeText,
        }
    }

    pub(super) fn previous(self) -> Self {
        match self {
            Self::FreeText => Self::Cve,
            Self::Product => Self::FreeText,
            Self::Vendor => Self::Product,
            Self::Cwe => Self::Vendor,
            Self::Cve => Self::Cwe,
        }
    }

    pub(super) fn from_query_prefix(query: &str) -> Option<Self> {
        let query = query.trim_start();
        if query
            .get(..4)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("CWE-"))
        {
            Some(Self::Cwe)
        } else if query
            .get(..4)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("CVE-"))
        {
            Some(Self::Cve)
        } else {
            None
        }
    }

    pub(super) async fn search(
        self,
        db: &CveDatabase,
        query: &str,
        state_scope: CveStateScope,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, String> {
        match self {
            Self::FreeText => {
                db.search_cve_summaries_free_text_with_state_scope(
                    query,
                    state_scope,
                    limit,
                    offset,
                )
                .await
            }
            Self::Product => {
                db.search_cve_summaries_by_vendor_product_with_state_scope(
                    None,
                    Some(query),
                    state_scope,
                    limit,
                    offset,
                )
                .await
            }
            Self::Vendor => {
                db.search_cve_summaries_by_vendor_product_with_state_scope(
                    Some(query),
                    None,
                    state_scope,
                    limit,
                    offset,
                )
                .await
            }
            Self::Cwe => {
                db.search_cve_summaries_by_cwe_with_state_scope(
                    &[query.to_owned()],
                    state_scope,
                    limit,
                    offset,
                )
                .await
            }
            Self::Cve => {
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

    pub(super) async fn count(
        self,
        db: &CveDatabase,
        query: &str,
        state_scope: CveStateScope,
    ) -> Result<u64, String> {
        match self {
            Self::FreeText => {
                db.count_cve_summaries_free_text_with_state_scope(query, state_scope)
                    .await
            }
            Self::Product => {
                db.count_cve_summaries_by_vendor_product_with_state_scope(
                    None,
                    Some(query),
                    state_scope,
                )
                .await
            }
            Self::Vendor => {
                db.count_cve_summaries_by_vendor_product_with_state_scope(
                    Some(query),
                    None,
                    state_scope,
                )
                .await
            }
            Self::Cwe => {
                db.count_cve_summaries_by_cwe_with_state_scope(&[query.to_owned()], state_scope)
                    .await
            }
            Self::Cve => {
                db.count_cve_summaries_by_cve_id_prefix_with_state_scope(query, state_scope)
                    .await
            }
        }
        .map_err(|err| err.to_string())
    }

    pub(super) fn footer_text(self) -> &'static str {
        match self {
            Self::FreeText => "free text",
            Self::Product => "product",
            Self::Vendor => "vendor",
            Self::Cwe => "CWE",
            Self::Cve => "CVE prefix",
        }
    }

    pub(super) fn color(self) -> Color {
        match self {
            Self::FreeText => Color::Cyan,
            Self::Product => Color::Green,
            Self::Vendor => Color::Magenta,
            Self::Cwe => Color::Yellow,
            Self::Cve => Color::Blue,
        }
    }
}
