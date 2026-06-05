use md5::{Digest, Md5};
use qanvuli_collector::providers::cve::CveRelease;
use qanvuli_db::{CveActiveModels, CveDatabase, ReadJsonFileRecord};
use qanvuli_models::parse_json_with_raw;
use qanvuli_utils::loader::{self, FileStorageTrait};
use rayon::prelude::*;
use std::time::{Duration, Instant};
use tokio::runtime::Runtime;

const DEFAULT_DB_CONNECTION_STRING: &str = "sqlite://./db.sqlite?mode=rwc";
const INGEST_CHUNK_SIZE: usize = 10000;

fn main() {
    let max_chunks = std::env::args()
        .nth(1)
        .map(|value| value.parse::<usize>().expect("max chunks must be usize"));
    let db_connection_string =
        std::env::var("QANVULI_DB_URL").unwrap_or_else(|_| DEFAULT_DB_CONNECTION_STRING.to_owned());
    let mut cve = CveRelease::new();
    if let Err(err) = cve.get() {
        panic!("failed to fetch CVE release list: {err}");
    }

    println!("{:?}", cve.get_latest_all_file());
    println!("{:?}", cve.get_latest_delta_file());
    println!("{:?}", cve.get_latest_delta_midnight_file());

    let all_asset = if let Some(a) = cve.get_latest_all_file() {
        a
    } else {
        panic!("no all asset");
    };
    let delta_asset = if let Some(a) = cve.get_latest_delta_file() {
        a
    } else {
        panic!("no delta asset");
    };

    if let Err(err) = all_asset.download_as_file() {
        panic!("failed to download {}: {err}", all_asset.name);
    };
    if let Err(err) = delta_asset.download_as_file() {
        panic!("failed to download {}: {err}", delta_asset.name);
    };

    // Create the runtime
    let rt = Runtime::new().unwrap();

    // Get a handle from this runtime
    let handle = rt.handle();

    // Execute the future, blocking the current thread until completion
    let db = handle.block_on(async {
        if let Ok(db) = CveDatabase::connect(&db_connection_string).await {
            if db.initialize_schema().await.is_err() {
                panic!("init db schema failed");
            }

            ingest_zip(
                &db,
                "all",
                &all_asset.name,
                IngestMode::ReplaceAll,
                max_chunks,
            )
            .await;
            ingest_zip(
                &db,
                "delta",
                &delta_asset.name,
                IngestMode::Upsert,
                max_chunks,
            )
            .await;

            db
        } else {
            panic!("db connect failed");
        }
    });

    let _ = handle.block_on(async { db.close().await });
}

async fn ingest_zip(
    db: &CveDatabase,
    label: &str,
    asset_name: &str,
    mode: IngestMode,
    max_chunks: Option<usize>,
) {
    let total_start = Instant::now();
    let mut storage = loader::ZipStorage::new(format!("./{asset_name}"));
    let json_paths = storage.enum_json_list().collect::<Vec<String>>();
    println!(
        "{label}: asset={asset_name}, json_count={}",
        json_paths.len()
    );
    if matches!(mode, IngestMode::ReplaceAll) {
        let rebuild_start = Instant::now();
        if let Err(err) = db.rebuild_schema().await {
            panic!("{label}: failed to rebuild schema: {err}");
        }
        println!("{label}: rebuilt schema in {:?}", rebuild_start.elapsed());
    }

    let mut inserted = 0usize;
    let mut failed = 0usize;
    let mut timings = IngestTimings::default();

    for (chunk_index, chunk) in json_paths.chunks(INGEST_CHUNK_SIZE).enumerate() {
        if max_chunks.is_some_and(|max_chunks| chunk_index >= max_chunks) {
            println!("{label}: stopped after {chunk_index} chunks for profiling");
            break;
        }

        let chunk_start = Instant::now();
        let mut jsons = Vec::with_capacity(chunk.len());
        let mut read_failed = 0usize;

        let read_start = Instant::now();
        for json_path in chunk {
            match storage.get_json(json_path) {
                Ok(json) => jsons.push((json_path.clone(), json)),
                Err(err) => {
                    read_failed += 1;
                    eprintln!("{label}: failed to read {json_path}: {err}");
                }
            }
        }
        let read_elapsed = read_start.elapsed();
        timings.read += read_elapsed;

        let hash_start = Instant::now();
        let jsons = jsons
            .into_par_iter()
            .map(|(json_path, json)| {
                let md5hash = md5_hex(json.as_bytes());
                (json_path, json, md5hash)
            })
            .collect::<Vec<_>>();
        let hash_elapsed = hash_start.elapsed();
        timings.hash += hash_elapsed;

        let parse_start = Instant::now();
        let parsed = jsons
            .into_par_iter()
            .map(|(json_path, json, md5hash)| {
                let raw_record = parse_json_with_raw(json)
                    .map_err(|err| format!("{label}: failed to parse {json_path}: {err}"))?;
                let models = CveActiveModels::from(raw_record);
                if models.cve_id.is_empty() {
                    return Err(format!("{label}: missing cveMetadata.cveId in {json_path}"));
                }
                Ok((
                    models,
                    ReadJsonFileRecord {
                        filename: json_path,
                        md5hash,
                    },
                ))
            })
            .collect::<Vec<Result<(CveActiveModels, ReadJsonFileRecord), String>>>();
        let parse_elapsed = parse_start.elapsed();
        timings.parse += parse_elapsed;

        let mut models = Vec::new();
        let mut read_files = Vec::new();
        let mut parse_failed = 0usize;
        for result in parsed {
            match result {
                Ok((model, read_file)) => {
                    models.push(model);
                    read_files.push(read_file);
                }
                Err(err) => {
                    parse_failed += 1;
                    eprintln!("{err}");
                }
            }
        }

        failed += read_failed + parse_failed;

        let db_write_start = Instant::now();
        let result = match mode {
            IngestMode::ReplaceAll => db.insert_cve_models(models).await,
            IngestMode::Upsert => db.upsert_cve_models(models).await,
        };

        match result {
            Ok(count) => {
                inserted += count;
                let db_write_elapsed = db_write_start.elapsed();
                timings.db_write += db_write_elapsed;

                let mark_start = Instant::now();
                if let Err(err) = db.mark_json_files_read(read_files).await {
                    eprintln!(
                        "{label}: failed to mark read json files in chunk {chunk_index}: {err}"
                    );
                }
                let mark_elapsed = mark_start.elapsed();
                timings.mark_read += mark_elapsed;

                let chunk_elapsed = chunk_start.elapsed();
                println!(
                    "{label}: timings chunk={} read={:?}, hash={:?}, parse={:?}, db_write={:?}, mark_read={:?}, total={:?}",
                    chunk_index,
                    read_elapsed,
                    hash_elapsed,
                    parse_elapsed,
                    db_write_elapsed,
                    mark_elapsed,
                    chunk_elapsed
                );
            }
            Err(err) => {
                timings.db_write += db_write_start.elapsed();
                failed += chunk.len();
                eprintln!("{label}: failed to write chunk {chunk_index}: {err}");
            }
        }

        println!(
            "{label}: progress chunk={}, inserted={}, failed={}",
            chunk_index, inserted, failed
        );
    }

    println!(
        "{label}: inserted={inserted}, failed={failed}, elapsed={:?}, read={:?}, hash={:?}, parse={:?}, db_write={:?}, mark_read={:?}",
        total_start.elapsed(),
        timings.read,
        timings.hash,
        timings.parse,
        timings.db_write,
        timings.mark_read
    );
}

#[derive(Copy, Clone)]
enum IngestMode {
    ReplaceAll,
    Upsert,
}

#[derive(Default)]
struct IngestTimings {
    read: Duration,
    hash: Duration,
    parse: Duration,
    db_write: Duration,
    mark_read: Duration,
}

fn md5_hex(bytes: &[u8]) -> String {
    let mut hasher = Md5::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use qanvuli_db::{CveActiveModels, CveDatabase};
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
            let db = CveDatabase::connect("sqlite::memory:").await.unwrap();
            db.initialize_schema().await.unwrap();

            let raw_record = parse_json_with_raw(CNA_CVE_JSON).unwrap();
            let expected_raw_json = raw_record.raw_json().clone();
            let models = CveActiveModels::from(raw_record);

            db.upsert_cve(models.cve).await.unwrap();
            db.replace_cve_children(
                "CVE-2024-1000",
                models.cvss_rows,
                models.affected_rows,
                models.cwe_rows,
            )
            .await
            .unwrap();

            let found = db.find_cve_by_id("CVE-2024-1000").await.unwrap().unwrap();
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

            let all = db.get_all().await.unwrap();
            assert_eq!(all.len(), 1);

            let by_product = db
                .search_cves_by_vendor_product(
                    Some("Example Vendor"),
                    Some("Example Product"),
                    10,
                    0,
                )
                .await
                .unwrap();
            assert_eq!(by_product.len(), 1);

            let by_cwe = db
                .search_cves_by_cwe(&["CWE-79".to_owned()], 10, 0)
                .await
                .unwrap();
            assert_eq!(by_cwe.len(), 1);
        });
    }
}
