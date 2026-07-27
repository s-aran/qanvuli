use qanvuli_app_commands::common::connect_database;
use qanvuli_core::database::SqlxDatabase;

pub(crate) async fn connect(db_url: &str) -> Result<SqlxDatabase, String> {
    let db = connect_database(db_url).await?;
    db.check_required_schema()
        .await
        .map_err(|error| format!("database rebuild required before opening TUI: {error}"))?;
    Ok(db)
}

pub(crate) async fn close(db: SqlxDatabase) -> Result<(), String> {
    db.close()
        .await
        .map_err(|err| format!("failed to close database: {err}"))
}

pub(crate) async fn latest_data_timestamp(db: &SqlxDatabase) -> Result<Option<String>, String> {
    db.latest_cve_updated_at()
        .await
        .map_err(|error| format!("failed to read DB timestamp: {error}"))
}
