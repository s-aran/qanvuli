use qanvuli_app_commands::common::connect_db;
use qanvuli_db::CveDatabase;

pub(crate) async fn connect(db_url: &str) -> Result<CveDatabase, String> {
    connect_db(db_url).await
}

pub(crate) async fn close(db: CveDatabase) -> Result<(), String> {
    db.close()
        .await
        .map_err(|err| format!("failed to close database: {err}"))
}

pub(crate) async fn latest_data_timestamp(db: &CveDatabase) -> Result<Option<String>, String> {
    match db.latest_cve_zip_datetime().await {
        Ok(Some(value)) => Ok(Some(value)),
        Ok(None) => db
            .latest_cve_updated_at()
            .await
            .map_err(|err| format!("failed to read DB timestamp: {err}")),
        Err(err) => Err(format!("failed to read CVE release timestamp: {err}")),
    }
}
