use qanvuli_core::database::CveDatabase;

pub(crate) async fn load_cve_raw_json(db: CveDatabase, cve_id: String) -> Result<String, String> {
    let raw_json = db
        .find_cve_raw_json_by_id(&cve_id)
        .await
        .map_err(|err| format!("failed to load raw JSON: {err}"))?
        .ok_or_else(|| format!("{cve_id} not found"))?;
    serde_json::to_string_pretty(&raw_json)
        .map_err(|err| format!("failed to encode raw JSON: {err}"))
}
