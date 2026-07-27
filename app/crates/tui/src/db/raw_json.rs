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

pub(crate) async fn load_osv_raw_json(db: CveDatabase, osv_id: String) -> Result<String, String> {
    let raw_json = db
        .find_osv_raw_json_by_id(&osv_id)
        .await
        .map_err(|err| format!("failed to load raw JSON: {err}"))?
        .ok_or_else(|| format!("{osv_id} not found"))?;
    serde_json::to_string_pretty(&raw_json)
        .map_err(|err| format!("failed to encode raw JSON: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use qanvuli_core::database::OsvRawRecord;

    #[test]
    fn loads_raw_json_for_an_osv_advisory() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let db = CveDatabase::connect("sqlite::memory:").await.unwrap();
            db.initialize_schema().await.unwrap();
            db.import_osv_records(vec![OsvRawRecord {
                source_path: Some("GHSA-raw-json-test.json".to_owned()),
                raw_json: r#"{
                    "schema_version":"1.7.5",
                    "id":"GHSA-raw-json-test",
                    "modified":"2099-01-02T00:00:00Z",
                    "published":"2099-01-01T00:00:00Z",
                    "summary":"raw JSON fixture",
                    "affected":[],
                    "references":[]
                }"#
                .to_owned(),
            }])
            .await
            .unwrap();

            let raw = load_osv_raw_json(db, "GHSA-RAW-JSON-TEST".to_owned())
                .await
                .unwrap();
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&raw).unwrap()["id"],
                "GHSA-raw-json-test"
            );
        });
    }
}
