use qanvuli_core::database::{CapecEntry, CapecSearchFilters, SqlxDatabase};

const CAPEC_TUI_LIMIT: u64 = 4_000;

pub(crate) async fn search_capec_entries(
    db: SqlxDatabase,
    filters: CapecSearchFilters,
) -> Result<Vec<CapecEntry>, String> {
    let mut filters = filters;
    filters.limit = CAPEC_TUI_LIMIT;
    db.search_capec_entries(filters)
        .await
        .map_err(|err| format!("failed to search CAPEC: {err}"))
}
