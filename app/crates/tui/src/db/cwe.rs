use qanvuli_core::database::{CweEntry, SqlxDatabase};

const CWE_TUI_LIMIT: u64 = 2_000;

pub(crate) async fn search_cwe_entries(
    db: SqlxDatabase,
    query: String,
    statuses: Vec<String>,
    capec_id: Option<i32>,
) -> Result<Vec<CweEntry>, String> {
    db.search_cwe_entries_filtered(&query, CWE_TUI_LIMIT, &statuses, capec_id)
        .await
        .map_err(|err| format!("failed to search CWE: {err}"))
}
