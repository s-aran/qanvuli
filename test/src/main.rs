use qanvuli_collector::providers::cve::CveRelease;
use qanvuli_db::{CveActiveModels, connect_database, initialize_schema, upsert_cve_models};
use qanvuli_models::parse_json_with_raw;
use qanvuli_utils::loader::{self, FileStorageTrait};
use rayon::prelude::*;
use tokio::runtime::Runtime;

const DB_CONNECTION_STRING: &str = "sqlite://./db.sqlite?mode=rwc";
const INGEST_CHUNK_SIZE: usize = 1000;

fn main() {
    let mut cve = CveRelease::new();
    if let Err(err) = cve.get() {
        panic!("failed to fetch CVE release list: {err}");
    }

    println!("{:?}", cve.get_latest_all_file());
    println!("{:?}", cve.get_latest_delta_file());
    println!("{:?}", cve.get_latest_delta_midnight_file());

    let asset = if let Some(a) = cve.get_latest_all_file() {
        a
    } else {
        panic!("no asset");
    };

    if let Err(err) = asset.download_as_file() {
        panic!("failed to download {}: {err}", asset.name);
    };

    let mut storage = loader::ZipStorage::new(format!("./{}", asset.name));
    let json_paths = storage.enum_json_list().collect::<Vec<String>>();
    println!("json_count={}", json_paths.len());

    // Create the runtime
    let rt = Runtime::new().unwrap();

    // Get a handle from this runtime
    let handle = rt.handle();

    // Execute the future, blocking the current thread until completion
    let db = handle.block_on(async {
        if let Ok(conn) = connect_database(DB_CONNECTION_STRING).await {
            if initialize_schema(&conn).await.is_err() {
                panic!("init db schema failed");
            }

            let mut inserted = 0usize;
            let mut failed = 0usize;

            for (chunk_index, chunk) in json_paths.chunks(INGEST_CHUNK_SIZE).enumerate() {
                let mut jsons = Vec::with_capacity(chunk.len());
                let mut read_failed = 0usize;

                for json_path in chunk {
                    match storage.get_json(json_path) {
                        Ok(json) => jsons.push((json_path.clone(), json)),
                        Err(err) => {
                            read_failed += 1;
                            eprintln!("failed to read {json_path}: {err}");
                        }
                    }
                }

                let parsed = jsons
                    .into_par_iter()
                    .map(|(json_path, json)| {
                        let raw_record = parse_json_with_raw(json)
                            .map_err(|err| format!("failed to parse {json_path}: {err}"))?;
                        let models = CveActiveModels::from(raw_record);
                        if models.cve_id.is_empty() {
                            return Err(format!("missing cveMetadata.cveId in {json_path}"));
                        }
                        Ok(models)
                    })
                    .collect::<Vec<Result<CveActiveModels, String>>>();

                let mut models = Vec::new();
                let mut parse_failed = 0usize;
                for result in parsed {
                    match result {
                        Ok(model) => models.push(model),
                        Err(err) => {
                            parse_failed += 1;
                            eprintln!("{err}");
                        }
                    }
                }

                failed += read_failed + parse_failed;

                match upsert_cve_models(&conn, models).await {
                    Ok(count) => inserted += count,
                    Err(err) => {
                        failed += chunk.len();
                        eprintln!("failed to write chunk {chunk_index}: {err}");
                    }
                }

                println!(
                    "progress chunk={}, inserted={}, failed={}",
                    chunk_index, inserted, failed
                );
            }

            println!("inserted={inserted}, failed={failed}");

            conn
        } else {
            panic!("db connect failed");
        }
    });

    let _ = handle.block_on(async { db.close().await });
}

#[cfg(test)]
mod tests {
    use qanvuli_db::{
        CveActiveModels, connect_database, find_cve_by_id, get_all, initialize_schema,
        replace_cve_children, search_cves_by_cwe, search_cves_by_vendor_product, upsert_cve,
    };
    use qanvuli_models::parse_json_with_raw;

    const CNA_CVE_JSON: &str = r#"{
        "dataType": "CVE_RECORD",
        "dataVersion": "5.1.0",
        "cveMetadata": {
            "cveId": "CVE-2024-1000",
            "assignerOrgId": "00000000-0000-4000-8000-000000000000",
            "state": "PUBLISHED",
            "serial": 7,
            "datePublished": "2024-02-01T00:00:00Z",
            "dateUpdated": "2024-02-02T00:00:00Z"
        },
        "containers": {
            "cna": {
                "providerMetadata": {
                    "orgId": "00000000-0000-4000-8000-000000000000",
                    "shortName": "example-cna"
                },
                "title": "CNA sourced CVE",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "CNA description stored in DB."
                    }
                ],
                "affected": [
                    {
                        "vendor": "Example Vendor",
                        "product": "Example Product"
                    }
                ],
                "metrics": [
                    {
                        "cvssV3_1": {
                            "attackComplexity": "LOW",
                            "attackVector": "LOCAL",
                            "availabilityImpact": "HIGH",
                            "baseScore": 6,
                            "baseSeverity": "MEDIUM",
                            "confidentialityImpact": "HIGH",
                            "integrityImpact": "NONE",
                            "privilegesRequired": "HIGH",
                            "scope": "UNCHANGED",
                            "userInteraction": "NONE",
                            "vectorString": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:H",
                            "version": "3.1"
                        },
                        "format": "CVSS",
                        "scenarios": [
                            {
                                "lang": "en",
                                "value": "GENERAL"
                            }
                        ]
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "lang": "en",
                                "cweId": "CWE-79",
                                "description": "Cross-site Scripting"
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "https://example.com/advisory"
                    }
                ]
            }
        },
        "x_testRawField": {
            "kept": true
        }
    }"#;

    #[test]
    fn test_db() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        runtime.block_on(async {
            let db = connect_database("sqlite::memory:").await.unwrap();
            initialize_schema(&db).await.unwrap();

            let raw_record = parse_json_with_raw(CNA_CVE_JSON).unwrap();
            let expected_raw_json = raw_record.raw_json().clone();
            let models = CveActiveModels::from(raw_record);

            upsert_cve(&db, models.cve).await.unwrap();
            replace_cve_children(
                &db,
                "CVE-2024-1000",
                models.cvss_rows,
                models.affected_rows,
                models.cwe_rows,
            )
            .await
            .unwrap();

            let found = find_cve_by_id(&db, "CVE-2024-1000").await.unwrap().unwrap();
            assert_eq!(found.cve_id, "CVE-2024-1000");
            assert_eq!(found.state, "PUBLISHED");
            assert_eq!(found.published_at, "2024-02-01T00:00:00+00:00");
            assert_eq!(found.updated_at, "2024-02-02T00:00:00+00:00");
            assert_eq!(found.serial, 7);
            assert_eq!(found.title, "CNA sourced CVE");
            assert_eq!(
                found.description_en.as_deref(),
                Some("CNA description stored in DB.")
            );
            assert_eq!(found.raw_json, expected_raw_json);
            assert_eq!(
                found.raw_json["containers"]["cna"]["providerMetadata"]["shortName"],
                "example-cna"
            );
            assert_eq!(found.raw_json["x_testRawField"]["kept"], true);

            let all = get_all(&db).await.unwrap();
            assert_eq!(all.len(), 1);

            let by_product = search_cves_by_vendor_product(
                &db,
                Some("Example Vendor"),
                Some("Example Product"),
                10,
                0,
            )
            .await
            .unwrap();
            assert_eq!(by_product.len(), 1);

            let by_cwe = search_cves_by_cwe(&db, &["CWE-79".to_owned()], 10, 0)
                .await
                .unwrap();
            assert_eq!(by_cwe.len(), 1);
        });
    }
}
