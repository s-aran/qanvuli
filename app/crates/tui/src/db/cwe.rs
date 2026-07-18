use qanvuli_core::database::{CweEntry, SqlxDatabase};

const CWE_TUI_LIMIT: u64 = 2_000;

pub(crate) async fn search_cwe_entries(
    db: SqlxDatabase,
    query: String,
    statuses: Vec<String>,
) -> Result<Vec<CweEntry>, String> {
    db.search_cwe_entries(&query, CWE_TUI_LIMIT, &statuses)
        .await
        .map_err(|err| format!("failed to search CWE: {err}"))
}
