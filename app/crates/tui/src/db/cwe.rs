use qanvuli_db::{CveDatabase, CweEntry};

pub(crate) async fn search_cwe_entries(
    db: CveDatabase,
    query: String,
    statuses: Vec<String>,
) -> Result<Vec<CweEntry>, String> {
    db.search_cwe_entries(&query, 200, &statuses)
        .await
        .map_err(|err| format!("failed to search CWE: {err}"))
}
