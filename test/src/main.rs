use qanvuli_collector::providers::cve::CveRelease;
use qanvuli_db::{connect_database, get_all, initialize_schema, upsert_cve};
use qanvuli_models::{parse_json, parse_json_with_raw};
use qanvuli_utils::loader::{self, FileStorageTrait};
use tokio::runtime::Runtime;

const CVSS_POINTERS: [&str; 4] = [
    "/containers/cna/metrics/0/cvssV4_0",
    "/containers/cna/metrics/0/cvssV3_1",
    "/containers/cna/metrics/0/cvssV3_0",
    "/containers/cna/metrics/0/cvssV2_0",
];

fn main() {
    println!("Hello, world!");

    let mut cve = CveRelease::new();
    let _ = cve.get();

    println!("{:?}", cve.get_latest_all_file());
    println!("{:?}", cve.get_latest_delta_file());
    println!("{:?}", cve.get_latest_delta_midnight_file());

    let asset = if let Some(a) = cve.get_latest_delta_file() {
        a
    } else {
        panic!("no asset");
    };

    if asset.download_as_file().is_err() {
        panic!("download error");
    };

    let mut storage = loader::ZipStorage::new(format!("./{}", asset.name));
    let jsons = storage.enum_json_list();
    let json = storage
        .get_json(jsons.collect::<Vec<String>>().get(0).unwrap())
        .unwrap();

    println!("{:?}", parse_json(json.clone()));
    println!("================================================================================");
    let parsed = parse_json_with_raw(json.clone()).unwrap();
    if let Some(raw_cvss) = CVSS_POINTERS
        .iter()
        .find_map(|pointer| parsed.raw_json().pointer(pointer))
    {
        println!("{raw_cvss}");
    } else {
        println!("CVSS raw_json not found in first CNA metric");
    }

    // Create the runtime
    let rt = Runtime::new().unwrap();

    // Get a handle from this runtime
    let handle = rt.handle();

    // Execute the future, blocking the current thread until completion
    let _db = handle.block_on(async {
        if let Ok(conn) = connect_database("sqlite://./db.sqlite").await {
            if initialize_schema(&conn).await.is_err() {
                panic!("init db schema failed");
            }

            let cve = parse_json_with_raw(json).unwrap();
            let model = cve.into();

            if upsert_cve(&conn, model).await.is_err() {
                panic!("upsert failed");
            }

            println!("{:?}", get_all(&conn).await);

            conn
        } else {
            panic!("db connect failed");
        }
    });
}

#[cfg(test)]
mod tests {
    use qanvuli_db::{connect_database, find_cve_by_id, get_all, initialize_schema, upsert_cve};
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
            let model = raw_record.into();

            upsert_cve(&db, model).await.unwrap();

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

            println!("{}", all[0].raw_json);
            assert!(false);
        });
    }
}
