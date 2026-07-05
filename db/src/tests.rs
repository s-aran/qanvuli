use super::*;
use qanvuli_models::parse_json_with_raw;
use sea_orm::{PaginatorTrait, Set};
use serde_json::json;

const CVE_JSON: &str = r#"{
        "dataType": "CVE_RECORD",
        "dataVersion": "5.1.0",
        "cveMetadata": {
            "cveId": "CVE-2024-0001",
            "assignerOrgId": "00000000-0000-4000-8000-000000000000",
            "state": "PUBLISHED",
            "serial": 2,
            "datePublished": "2024-01-01T00:00:00Z",
            "dateUpdated": "2024-01-02T00:00:00Z"
        },
        "containers": {
            "cna": {
                "providerMetadata": {
                    "orgId": "00000000-0000-4000-8000-000000000000"
                },
                "title": "Example CVE",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "Example vulnerability."
                    }
                ],
                "affected": [
                    {
                        "vendor": "Example Vendor",
                        "product": "Example Product",
                        "defaultStatus": "affected"
                    }
                ],
                "metrics": [
                    {
                        "format": "CVSS",
                        "cvssV3_1": {
                            "version": "3.1",
                            "baseScore": 9.8,
                            "baseSeverity": "CRITICAL",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                        }
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
        "x_extraField": {
            "kept": true
        }
    }"#;

#[test]
fn raw_cve_record_converts_to_cve_active_model() {
    let raw_record = parse_json_with_raw(CVE_JSON).unwrap();
    let expected_raw_json = raw_record.raw_json().clone();
    let active_model = cve::ActiveModel::from(raw_record);

    assert_eq!(active_model.cve_id.unwrap(), "CVE-2024-0001");
    assert_eq!(active_model.state.unwrap(), PUBLISHED_STATE);
    assert_eq!(
        active_model.published_at.unwrap(),
        "2024-01-01T00:00:00+00:00"
    );
    assert_eq!(
        active_model.updated_at.unwrap(),
        "2024-01-02T00:00:00+00:00"
    );
    assert_eq!(active_model.serial.unwrap(), 2);
    assert_eq!(active_model.title.unwrap(), "Example CVE");
    assert_eq!(
        active_model.description_en.unwrap().as_deref(),
        Some("Example vulnerability.")
    );
    assert!(
        active_model
            .reference_text
            .unwrap()
            .contains("https://example.com/advisory")
    );
    assert_eq!(
        active_model.raw_json.unwrap(),
        expected_raw_json.to_string()
    );
}

#[test]
fn raw_cve_record_converts_to_all_active_models() {
    let raw_record = parse_json_with_raw(CVE_JSON).unwrap();
    let models = CveActiveModels::from(raw_record);

    assert_eq!(models.cve_id, "CVE-2024-0001");
    assert_eq!(models.cvss_rows.len(), 1);
    assert_eq!(models.affected_rows.len(), 1);
    assert_eq!(models.cwe_rows.len(), 1);

    let cvss = models.cvss_rows.into_iter().next().unwrap();
    assert_eq!(cvss.cve_db_id.unwrap(), 0);
    assert_eq!(cvss.version.unwrap(), "3.1");
    assert_eq!(cvss.base_score.unwrap(), Some(9.8));
    assert_eq!(cvss.base_severity.unwrap().as_deref(), Some("CRITICAL"));
    assert_eq!(
        cvss.vector_string.unwrap().as_deref(),
        Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    );
    assert_eq!(
        raw_json_value(&cvss.raw_json.unwrap()).unwrap()["version"],
        "3.1"
    );

    let affected = models.affected_rows.into_iter().next().unwrap();
    assert_eq!(affected.cve_db_id.unwrap(), 0);
    assert_eq!(affected.vendor.unwrap().as_deref(), Some("Example Vendor"));
    assert_eq!(
        affected.product.unwrap().as_deref(),
        Some("Example Product")
    );
    assert_eq!(
        affected.default_status.unwrap().as_deref(),
        Some("affected")
    );
    assert!(affected.version_text.unwrap().is_empty());
    assert_eq!(
        raw_json_value(&affected.raw_json.unwrap()).unwrap()["vendor"],
        "Example Vendor"
    );

    let cwe = models.cwe_rows.into_iter().next().unwrap();
    assert_eq!(cwe.cve_db_id.unwrap(), 0);
    assert_eq!(cwe.cwe_id.unwrap(), 79);
    assert!(models.cwe_master_rows.is_empty());
}

#[test]
fn dedupe_summaries_keeps_one_row_per_cve_id() {
    let cves = vec![
        test_summary("CVE-2024-1000", "first"),
        test_summary("CVE-2024-1000", "duplicate"),
        test_summary("CVE-2024-1001", "second"),
    ];

    let cves = dedupe_summaries_by_cve_id(cves);

    assert_eq!(cves.len(), 2);
    assert_eq!(cves[0].cve_id, "CVE-2024-1000");
    assert_eq!(cves[0].title, "first");
    assert_eq!(cves[1].cve_id, "CVE-2024-1001");
}

#[test]
fn affected_text_search_skips_short_cve_and_date_queries() {
    assert!(!should_search_affected_text("a"));
    assert!(!should_search_affected_text("CVE-2024-1000"));
    assert!(!should_search_affected_text("CWE-79"));
    assert!(!should_search_affected_text("2026-06-08"));
    assert!(should_search_affected_text("Cardinarity"));
}

#[test]
fn cve_id_prefix_query_accepts_cve_prefix_case_insensitively() {
    assert!(is_cve_id_prefix_query("CVE-2026"));
    assert!(is_cve_id_prefix_query("cve-2026"));
    assert!(!is_cve_id_prefix_query("CWE-79"));
    assert!(!is_cve_id_prefix_query("2026"));
}

#[test]
fn identifier_type_detection_handles_common_aliases() {
    assert_eq!(detect_identifier_type("cve-2099-0001"), "cve");
    assert_eq!(detect_identifier_type("GHSA-test-0001"), "ghsa");
    assert_eq!(detect_identifier_type("RUSTSEC-TEST-0001"), "rustsec");
    assert_eq!(detect_identifier_type("PYSEC-2099-1"), "pysec");
    assert_eq!(detect_identifier_type("GO-2099-0001"), "go");
    assert_eq!(detect_identifier_type("UNKNOWN-1"), "other");
}

#[test]
fn epss_csv_comment_header_parses() {
    let parsed = EpssCurrentCsv::parse(include_str!("../../fixtures/epss/epss-test.csv")).unwrap();
    assert_eq!(parsed.model_version.as_deref(), Some("v2099.01.01"));
    assert_eq!(parsed.score_date.as_deref(), Some("2099-01-04"));
    assert_eq!(parsed.rows.len(), 1);
    assert_eq!(parsed.rows[0].cve_id, "CVE-2099-0001");
    assert_eq!(parsed.rows[0].percentile, 0.98211);
}

#[test]
fn cwe_id_query_accepts_cwe_prefix_case_insensitively() {
    assert!(is_cwe_id_query("CWE-79"));
    assert!(is_cwe_id_query("cwe-79"));
    assert!(!is_cwe_id_query("CVE-2026"));
    assert!(!is_cwe_id_query("79"));
}

fn test_summary(cve_id: &str, title: &str) -> CveSummary {
    CveSummary {
        cve_id: cve_id.to_owned(),
        state: PUBLISHED_STATE,
        published_at: "2024-02-01T00:00:00+00:00".to_owned(),
        updated_at: "2024-02-02T00:00:00+00:00".to_owned(),
        title: title.to_owned(),
        description_en: None,
    }
}

#[test]
fn in_memory_sqlite_writes_and_reads_simple_cve() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    runtime.block_on(async {
        let db = connect_database("sqlite::memory:").await.unwrap();
        let cve_db = CveDatabase { db: db.clone() };
        cve_db.initialize_schema().await.unwrap();
        insert_test_cwe(&db).await;

        cve_db
            .upsert_cve(cve::ActiveModel {
                id: Default::default(),
                cve_id: Set("CVE-2026-0001".to_owned()),
                state: Set(PUBLISHED_STATE),
                published_at: Set("2026-01-01T00:00:00Z".to_owned()),
                updated_at: Set("2026-01-02T00:00:00Z".to_owned()),
                serial: Set(1),
                title: Set("example".to_owned()),
                description_en: Set(Some("description".to_owned())),
                reference_text: Set(String::new()),
                raw_json: Set(json!({"id": "CVE-2026-0001"}).to_string()),
            })
            .await
            .unwrap();

        cve_db
            .replace_cve_children(
                "CVE-2026-0001",
                vec![cve_cvss::ActiveModel {
                    cve_db_id: Set(0),
                    version: Set("3.1".to_owned()),
                    base_score: Set(Some(9.8)),
                    base_severity: Set(Some("CRITICAL".to_owned())),
                    vector_string: Set(Some("CVSS:3.1/...".to_owned())),
                    source: Set(Some("cna".to_owned())),
                    raw_json: Set(json!({"version": "3.1"}).to_string()),
                    ..Default::default()
                }],
                vec![cve_affected::ActiveModel {
                    cve_db_id: Set(0),
                    vendor: Set(Some("Example Vendor".to_owned())),
                    product: Set(Some("Example Product".to_owned())),
                    version_text: Set(String::new()),
                    raw_json: Set(json!({"vendor": "Example Vendor"}).to_string()),
                    ..Default::default()
                }],
                vec![cve_cwe::ActiveModel {
                    cve_db_id: Set(0),
                    cwe_id: Set(79),
                }],
            )
            .await
            .unwrap();

        let found = cve_db
            .find_cve_by_id("CVE-2026-0001")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.cve_id, "CVE-2026-0001");
        assert_eq!(found.state, PUBLISHED_STATE);
        assert_eq!(found.published_at, "2026-01-01T00:00:00Z");
        assert_eq!(found.updated_at, "2026-01-02T00:00:00Z");
        assert_eq!(found.serial, 1);
        assert_eq!(found.title, "example");
        assert_eq!(found.description_en.as_deref(), Some("description"));
        assert_eq!(
            raw_json_value(&found.raw_json).unwrap(),
            json!({"id": "CVE-2026-0001"})
        );

        let by_cwe = cve_db
            .search_cves_by_cwe(&["CWE-79".to_owned()], 10, 0)
            .await
            .unwrap();
        assert_eq!(by_cwe.len(), 1);

        let by_product = cve_db
            .search_cves_by_vendor_product(Some("Vendor"), Some("Product"), 10, 0)
            .await
            .unwrap();
        assert_eq!(by_product.len(), 1);

        let affected_count = cve_affected::Entity::find().count(&db).await.unwrap();
        assert_eq!(affected_count, 1);
    });
}

#[test]
fn cve_summary_search_defaults_to_published_only() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    runtime.block_on(async {
        let db = CveDatabase::connect("sqlite::memory:").await.unwrap();
        db.initialize_schema().await.unwrap();

        for (cve_id, state, state_label) in [
            ("CVE-2026-1000", PUBLISHED_STATE, "PUBLISHED"),
            ("CVE-2026-1001", REJECTED_STATE, "REJECTED"),
        ] {
            db.upsert_cve(cve::ActiveModel {
                id: Default::default(),
                cve_id: Set(cve_id.to_owned()),
                state: Set(state),
                published_at: Set("2026-01-01T00:00:00Z".to_owned()),
                updated_at: Set("2026-01-02T00:00:00Z".to_owned()),
                serial: Set(1),
                title: Set(format!("{state_label} example")),
                description_en: Set(Some("description".to_owned())),
                reference_text: Set(String::new()),
                raw_json: Set(json!({"id": cve_id, "state": state_label}).to_string()),
            })
            .await
            .unwrap();
        }
        rebuild_cve_summary_indexes(db.connection()).await.unwrap();

        let default = db
            .search_cve_summaries_by_cve_id_prefix("CVE-2026-100", 10, 0)
            .await
            .unwrap();
        assert_eq!(default.len(), 1);
        assert_eq!(default[0].state, PUBLISHED_STATE);

        let including_rejected = db
            .search_cve_summaries_by_cve_id_prefix_with_state_scope(
                "CVE-2026-100",
                CveStateScope::IncludeRejected,
                10,
                0,
            )
            .await
            .unwrap();
        assert_eq!(including_rejected.len(), 2);

        let default_count = db
            .count_cve_summaries_by_cve_id_prefix("CVE-2026-100")
            .await
            .unwrap();
        assert_eq!(default_count, 1);

        let including_rejected_count = db
            .count_cve_summaries_by_cve_id_prefix_with_state_scope(
                "CVE-2026-100",
                CveStateScope::IncludeRejected,
            )
            .await
            .unwrap();
        assert_eq!(including_rejected_count, 2);
    });
}

#[test]
fn upsert_cve_models_writes_parent_and_children() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    runtime.block_on(async {
        let db = connect_database("sqlite::memory:").await.unwrap();
        let cve_db = CveDatabase { db: db.clone() };
        cve_db.initialize_schema().await.unwrap();
        insert_test_cwe(&db).await;

        let models = CveActiveModels::from(parse_json_with_raw(CVE_JSON).unwrap());
        let inserted = cve_db.upsert_cve_models(vec![models]).await.unwrap();
        assert_eq!(inserted, 1);

        let found = cve_db
            .find_cve_by_id("CVE-2024-0001")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.cve_id, "CVE-2024-0001");

        let by_cwe = cve_db
            .search_cves_by_cwe(&["CWE-79".to_owned()], 10, 0)
            .await
            .unwrap();
        assert_eq!(by_cwe.len(), 1);

        let by_product = cve_db
            .search_cves_by_vendor_product(Some("Example Vendor"), Some("Product"), 10, 0)
            .await
            .unwrap();
        assert_eq!(by_product.len(), 1);

        let by_product_summary = cve_db
            .search_cve_summaries_by_vendor_product_with_state_scope(
                Some("Example Vendor"),
                Some("Product"),
                CveStateScope::PublishedOnly,
                10,
                0,
            )
            .await
            .unwrap();
        assert_eq!(by_product_summary.len(), 1);

        let by_product_count = cve_db
            .count_cve_summaries_by_vendor_product_with_state_scope(
                Some("Example Vendor"),
                Some("Product"),
                CveStateScope::PublishedOnly,
            )
            .await
            .unwrap();
        assert_eq!(by_product_count, 1);

        let by_exact_product = cve_db
            .search_cve_summaries_by_vendor_product_exact_with_state_scope(
                None,
                None,
                None,
                Some("Example Product"),
                CveStateScope::PublishedOnly,
                10,
                0,
            )
            .await
            .unwrap();
        assert_eq!(by_exact_product.len(), 1);

        let by_partial_as_exact = cve_db
            .search_cve_summaries_by_vendor_product_exact_with_state_scope(
                None,
                None,
                None,
                Some("Product"),
                CveStateScope::PublishedOnly,
                10,
                0,
            )
            .await
            .unwrap();
        assert!(by_partial_as_exact.is_empty());

        cve_db
            .replace_cve_children(
                "CVE-2024-0001",
                Vec::new(),
                Vec::new(),
                vec![cve_cwe::ActiveModel {
                    cve_db_id: Set(0),
                    cwe_id: Set(79),
                }],
            )
            .await
            .unwrap();

        let cwe = cwe::Entity::find_by_id(79).one(&db).await.unwrap().unwrap();
        assert_eq!(cwe.description.as_deref(), Some("Cross-site Scripting"));
    });
}

#[test]
fn enrichment_imports_and_queries_joined_sources() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    runtime.block_on(async {
        let db = CveDatabase::connect("sqlite::memory:").await.unwrap();
        db.initialize_schema().await.unwrap();
        db.upsert_cve(cve::ActiveModel {
            id: Default::default(),
            cve_id: Set("CVE-2099-0001".to_owned()),
            state: Set(PUBLISHED_STATE),
            published_at: Set("2099-01-01T00:00:00Z".to_owned()),
            updated_at: Set("2099-01-02T00:00:00Z".to_owned()),
            serial: Set(1),
            title: Set("fixture".to_owned()),
            description_en: Set(Some("fixture cve".to_owned())),
            reference_text: Set(String::new()),
            raw_json: Set(json!({"id": "CVE-2099-0001"}).to_string()),
        })
        .await
        .unwrap();
        rebuild_cve_summary_indexes(db.connection()).await.unwrap();

        db.import_osv_records(vec![
            OsvRawRecord {
                source_path: Some("RUSTSEC-TEST-0001.json".to_owned()),
                raw_json: include_str!("../../fixtures/osv/RUSTSEC-TEST-0001.json").to_owned(),
            },
            OsvRawRecord {
                source_path: Some("GHSA-TEST-0001.json".to_owned()),
                raw_json: include_str!("../../fixtures/osv/GHSA-TEST-0001.json").to_owned(),
            },
        ])
        .await
        .unwrap();
        let unchanged = db
            .import_osv_records(vec![OsvRawRecord {
                source_path: Some("RUSTSEC-TEST-0001.json".to_owned()),
                raw_json: include_str!("../../fixtures/osv/RUSTSEC-TEST-0001.json").to_owned(),
            }])
            .await
            .unwrap();
        assert_eq!(unchanged.imported, 0);
        assert_eq!(unchanged.skipped, 1);
        db.import_kev_json(include_str!("../../fixtures/kev/kev-test.json"))
            .await
            .unwrap();
        db.import_epss_csv(include_str!("../../fixtures/epss/epss-test.csv"))
            .await
            .unwrap();

        let resolution = db.resolve_identifier("RUSTSEC-TEST-0001").await.unwrap();
        assert!(
            resolution
                .related_cve_ids
                .contains(&"CVE-2099-0001".to_owned())
        );
        assert!(
            resolution
                .related_osv_ids
                .contains(&"RUSTSEC-TEST-0001".to_owned())
        );

        db.rebuild_identifier_graph().await.unwrap();
        let rebuilt_resolution = db.resolve_identifier("GHSA-TEST-0001").await.unwrap();
        assert!(
            rebuilt_resolution
                .related_cve_ids
                .contains(&"CVE-2099-0001".to_owned())
        );

        let enriched = db.get_enriched_cve("CVE-2099-0001").await.unwrap();
        assert!(enriched.kev.is_some());
        assert!(enriched.epss.is_some());
        assert!(
            enriched
                .osv_advisories
                .iter()
                .any(|row| row.osv_id == "RUSTSEC-TEST-0001")
        );
        let osv_text_hits = db
            .search_cve_summaries_free_text("foo", 10, 0)
            .await
            .unwrap();
        assert!(
            osv_text_hits
                .iter()
                .any(|row| row.cve_id == "CVE-2099-0001")
        );
        let osv_text_enrichment = db
            .enriched_cve_summaries(&["CVE-2099-0001".to_owned()])
            .await
            .unwrap();
        assert!(
            osv_text_enrichment
                .iter()
                .any(|row| row.osv_ids.contains("RUSTSEC-TEST-0001"))
        );

        let findings = db
            .query_package_enriched("crates.io", "foo", "1.2.3", None)
            .await
            .unwrap();
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!(finding.affected.status, "affected");
        assert_eq!(finding.priority_signals.suggested_priority, "urgent");
        assert!(finding.fixed_versions.contains(&"1.2.5".to_owned()));
        assert!(
            finding
                .evidence
                .iter()
                .any(|e| e.kind == "alias_resolution")
        );
        assert!(finding.evidence.iter().any(|e| e.kind == "kev_join"));
        assert!(finding.evidence.iter().any(|e| e.kind == "epss_join"));

        let unsupported = db
            .query_package_enriched("npm", "foo", "1.2.3", None)
            .await
            .unwrap();
        assert!(unsupported.is_empty());
    });
}

async fn insert_test_cwe(db: &DatabaseConnection) {
    cwe::Entity::insert(cwe::ActiveModel {
        id: Set(79),
        description: Set(Some("Cross-site Scripting".to_owned())),
        status: Set(Some("Stable".to_owned())),
        parent_id: Set(None),
    })
    .exec(db)
    .await
    .unwrap();
}

#[test]
fn mark_json_file_read_upserts_processed_file() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    runtime.block_on(async {
        let db = CveDatabase::connect("sqlite::memory:").await.unwrap();
        db.initialize_schema().await.unwrap();

        db.mark_json_file_read("cves/CVE-2024-0001.json", "0123456789abcdef")
            .await
            .unwrap();
        db.mark_json_file_read("cves/CVE-2024-0001.json", "0123456789abcdef")
            .await
            .unwrap();

        let found = db
            .find_read_json_file("cves/CVE-2024-0001.json", "0123456789abcdef")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.filename, "cves/CVE-2024-0001.json");
        assert_eq!(found.md5hash, "0123456789abcdef");
        assert!(!found.created_at.is_empty());
        assert!(!found.updated_at.is_empty());

        let count = read_json_file::Entity::find()
            .count(db.connection())
            .await
            .unwrap();
        assert_eq!(count, 1);
    });
}

#[test]
fn mark_json_files_read_splits_large_batches_under_sqlite_variable_limit() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    runtime.block_on(async {
        let db = CveDatabase::connect("sqlite::memory:").await.unwrap();
        db.initialize_schema().await.unwrap();

        let files = (0..20_000)
            .map(|index| ReadJsonFileRecord {
                filename: format!("cves/CVE-2024-{index:04}.json"),
                md5hash: format!("{index:032x}"),
            })
            .collect::<Vec<_>>();

        let marked = db.mark_json_files_read(files).await.unwrap();
        assert_eq!(marked, 20_000);

        let count = read_json_file::Entity::find()
            .count(db.connection())
            .await
            .unwrap();
        assert_eq!(count, 20_000);
    });
}
