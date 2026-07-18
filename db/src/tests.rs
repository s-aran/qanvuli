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
fn base_purl_removes_versions_and_qualifiers_without_altering_scoped_names() {
    assert_eq!(
        base_purl("pkg:pypi/django@1.5.8?repository_url=https://example.invalid#src"),
        "pkg:pypi/django"
    );
    assert_eq!(base_purl("pkg:npm/@scope/name"), "pkg:npm/@scope/name");
}

#[test]
fn raw_cve_json_string_storage_is_compact() {
    let models = CveActiveModels::from_raw_json_string(CVE_JSON.to_owned()).unwrap();
    let raw_json = models.cve.raw_json.unwrap();

    assert!(!raw_json.contains('\n'));
    assert!(!raw_json.contains("  "));
    assert_eq!(
        raw_json_value(&raw_json).unwrap()["cveMetadata"]["cveId"],
        "CVE-2024-0001"
    );
}

#[test]
fn raw_cve_json_string_rejects_malformed_json() {
    let Err(err) = CveActiveModels::from_raw_json_string(r#"{"id":"CVE-2099-0001}"#.to_owned())
    else {
        panic!("malformed JSON must fail to parse");
    };
    assert!(
        err.to_string().contains("failed to parse CVE JSON"),
        "{err}"
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
fn identifier_like_query_rejects_plain_search_terms() {
    assert!(is_identifier_like_query("GHSA-test-0001"));
    assert!(is_identifier_like_query("DSA-1234-1"));
    assert!(!is_identifier_like_query("openssl"));
    assert!(!is_identifier_like_query("remote code execution"));
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
fn advanced_summary_search_sorts_by_updated_at() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    runtime.block_on(async {
        let db = CveDatabase::connect("sqlite::memory:").await.unwrap();
        db.initialize_schema().await.unwrap();

        for (cve_id, published_at, updated_at) in [
            (
                "CVE-2026-2000",
                "2026-01-03T00:00:00Z",
                "2026-01-04T00:00:00Z",
            ),
            (
                "CVE-2026-2001",
                "2026-01-02T00:00:00Z",
                "2026-01-06T00:00:00Z",
            ),
            (
                "CVE-2026-2002",
                "2026-01-01T00:00:00Z",
                "2026-01-05T00:00:00Z",
            ),
        ] {
            db.upsert_cve(cve::ActiveModel {
                id: Default::default(),
                cve_id: Set(cve_id.to_owned()),
                state: Set(PUBLISHED_STATE),
                published_at: Set(published_at.to_owned()),
                updated_at: Set(updated_at.to_owned()),
                serial: Set(1),
                title: Set("updated sort fixture".to_owned()),
                description_en: Set(Some("description".to_owned())),
                reference_text: Set(String::new()),
                raw_json: Set(json!({"id": cve_id}).to_string()),
            })
            .await
            .unwrap();
        }
        rebuild_cve_summary_indexes(db.connection()).await.unwrap();

        let mut options = CveAdvancedSearch {
            sort_order: CveSummarySortOrder::UpdatedDesc,
            ..Default::default()
        };
        let desc = db
            .search_cve_summaries_advanced(&options, 10, 0)
            .await
            .unwrap();
        assert_eq!(
            desc.iter()
                .map(|summary| summary.cve_id.as_str())
                .collect::<Vec<_>>(),
            vec!["CVE-2026-2001", "CVE-2026-2002", "CVE-2026-2000"]
        );

        options.sort_order = CveSummarySortOrder::UpdatedAsc;
        let asc = db
            .search_cve_summaries_advanced(&options, 10, 0)
            .await
            .unwrap();
        assert_eq!(
            asc.iter()
                .map(|summary| summary.cve_id.as_str())
                .collect::<Vec<_>>(),
            vec!["CVE-2026-2000", "CVE-2026-2002", "CVE-2026-2001"]
        );
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

        let exact_cve_product_case_insensitive = cve_db
            .search_cves_by_vendor_product_exact_with_state_scope(
                None,
                None,
                None,
                Some("example product"),
                CveStateScope::PublishedOnly,
                10,
                0,
            )
            .await
            .unwrap();
        assert_eq!(exact_cve_product_case_insensitive.len(), 1);

        let exact_product_case_insensitive = cve_db
            .search_cve_summaries_advanced(
                &CveAdvancedSearch {
                    product_exact: Some("example product".to_owned()),
                    ..Default::default()
                },
                10,
                0,
            )
            .await
            .unwrap();
        assert_eq!(exact_product_case_insensitive.len(), 1);

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
        let cve_db_id = cve::Entity::find()
            .filter(cve::Column::CveId.eq("CVE-2099-0001"))
            .one(db.connection())
            .await
            .unwrap()
            .unwrap()
            .id;
        cve_affected::Entity::insert(cve_affected::ActiveModel {
            id: Default::default(),
            cve_db_id: Set(cve_db_id),
            vendor: Set(Some("Example Vendor".to_owned())),
            product: Set(Some("Django".to_owned())),
            package_name: Set(Some("django".to_owned())),
            collection_url: Set(None),
            default_status: Set(Some("affected".to_owned())),
            version_text: Set(String::new()),
            raw_json: Set("{}".to_owned()),
        })
        .exec(db.connection())
        .await
        .unwrap();
        cve_cvss::Entity::insert(cve_cvss::ActiveModel {
            id: Default::default(),
            cve_db_id: Set(cve_db_id),
            version: Set("3.1".to_owned()),
            base_score: Set(Some(9.8)),
            base_severity: Set(Some("CRITICAL".to_owned())),
            vector_string: Set(Some(
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_owned(),
            )),
            source: Set(Some("fixture".to_owned())),
            raw_json: Set("{}".to_owned()),
        })
        .exec(db.connection())
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
            OsvRawRecord {
                source_path: Some("GHSA-xpw3-9rhw-482x.json".to_owned()),
                raw_json: r#"{
                    "schema_version": "1.7.5",
                    "id": "GHSA-xpw3-9rhw-482x",
                    "modified": "2099-01-05T00:00:00Z",
                    "published": "2099-01-05T00:00:00Z",
                    "aliases": ["CVE-2099-0001"],
                    "summary": "Primary GHSA fixture",
                    "details": "Fixture advisory whose GHSA ID is the primary OSV ID.",
                    "affected": [],
                    "references": []
                }"#
                .to_owned(),
            },
        ])
        .await
        .unwrap();
        db.import_osv_records(vec![OsvRawRecord {
            source_path: Some("PYSEC-TEST-0001.json".to_owned()),
            raw_json: r#"{
                "schema_version": "1.7.5",
                "id": "PYSEC-TEST-0001",
                "modified": "2099-01-05T00:00:00Z",
                "published": "2099-01-05T00:00:00Z",
                "aliases": ["CVE-2099-0001"],
                "summary": "PyPI canonical-name fixture",
                "details": "Fixture advisory for PyPI normalization.",
                "affected": [{
                    "package": {"ecosystem": "PyPI", "name": "pillow-heif"},
                    "ranges": [{"type": "ECOSYSTEM", "events": [
                        {"introduced": "0"}, {"fixed": "1.2.0"}
                    ]}]
                }],
                "references": []
            }"#
            .to_owned(),
        }])
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

        let raw_rows = db.connection().query_all(Statement::from_string(
            DbBackend::Sqlite,
            "SELECT raw_json FROM osv_raw_records UNION ALL SELECT raw_json FROM kev_raw_records"
                .to_owned(),
        )).await.unwrap();
        assert!(!raw_rows.is_empty());
        for row in raw_rows {
            let raw_json = row.try_get::<String>("", "raw_json").unwrap();
            assert!(!raw_json.contains('\n'));
            raw_json_value(&raw_json).unwrap();
        }
        let epss_raw = db
            .connection()
            .query_one(Statement::from_string(
                DbBackend::Sqlite,
                "SELECT raw_csv FROM epss_raw_records".to_owned(),
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get::<String>("", "raw_csv")
            .unwrap();
        assert!(epss_raw.starts_with("#model_version:"));

        let raw_osv = db
            .find_osv_raw_json_by_id("RUSTSEC-TEST-0001")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(raw_osv["id"], "RUSTSEC-TEST-0001");

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
        let risk = db
            .cve_risk_summaries(&["CVE-2099-0001".to_owned()])
            .await
            .unwrap();
        assert_eq!(risk.len(), 1);
        assert!(risk[0].kev_listed);
        assert!(risk[0].epss.is_some());
        assert_eq!(risk[0].max_cvss_score, Some(9.8));
        let epss_hits = db
            .search_cve_risk_by_epss(Some(0.01), None, CveStateScope::PublishedOnly, 10, 0)
            .await
            .unwrap();
        assert!(epss_hits.iter().any(|row| row.cve_id == "CVE-2099-0001"));
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
        let osv_alias_hits = db
            .search_cve_summaries_free_text("GHSA-TEST-0001", 10, 0)
            .await
            .unwrap();
        assert!(
            osv_alias_hits
                .iter()
                .any(|row| row.cve_id == "CVE-2099-0001")
        );
        let osv_alias_count = db
            .count_cve_summaries_free_text("GHSA-TEST-0001")
            .await
            .unwrap();
        assert_eq!(osv_alias_count, 1);
        let osv_alias_prefix_hits = db
            .search_cve_summaries_free_text("GHSA-TEST", 10, 0)
            .await
            .unwrap();
        assert!(
            osv_alias_prefix_hits
                .iter()
                .any(|row| row.cve_id == "CVE-2099-0001")
        );
        let osv_alias_prefix_count = db.count_cve_summaries_free_text("GHSA-TEST").await.unwrap();
        assert_eq!(osv_alias_prefix_count, 1);
        let primary_ghsa_hits = db
            .search_cve_summaries_free_text("GHSA-xpw3-9rhw-482x", 10, 0)
            .await
            .unwrap();
        assert!(
            primary_ghsa_hits
                .iter()
                .any(|row| row.cve_id == "CVE-2099-0001")
        );
        let primary_ghsa_count = db
            .count_cve_summaries_free_text("GHSA-xpw3-9rhw-482x")
            .await
            .unwrap();
        assert_eq!(primary_ghsa_count, 1);
        let osv_text_enrichment = db
            .enriched_cve_summaries(&["CVE-2099-0001".to_owned()])
            .await
            .unwrap();
        assert!(
            osv_text_enrichment
                .iter()
                .any(|row| row.osv_ids.contains("RUSTSEC-TEST-0001"))
        );
        let overview = db
            .attach_cve_overview_details(vec![CveSummary {
                cve_id: "CVE-2099-0001".to_owned(),
                state: PUBLISHED_STATE,
                published_at: "2099-01-01T00:00:00Z".to_owned(),
                updated_at: "2099-01-02T00:00:00Z".to_owned(),
                title: "fixture".to_owned(),
                description_en: Some("fixture cve".to_owned()),
            }])
            .await
            .unwrap();
        assert!(overview[0].detail.affected.iter().any(|row| {
            row.vendor.as_deref() == Some("Example Vendor")
                && row.product.as_deref() == Some("Django")
        }));

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

        let findings_with_versioned_purl = db
            .query_package_enriched(
                "crates.io",
                "foo",
                "1.2.3",
                Some("pkg:cargo/foo@1.2.3?repository_url=https://example.invalid#src/lib.rs"),
            )
            .await
            .unwrap();
        assert_eq!(findings_with_versioned_purl.len(), 1);

        let canonical_pypi = db
            .query_package_enriched("PyPI", "pillow-heif", "1.1.1", None)
            .await
            .unwrap();
        assert_eq!(canonical_pypi.len(), 1);
        for package in ["pillow_heif", "Pillow_Heif", "pillow.heif"] {
            let findings = db
                .query_package_enriched("PyPI", package, "1.1.1", None)
                .await
                .unwrap();
            assert_eq!(findings.len(), canonical_pypi.len(), "{package}");
            assert_eq!(findings[0].cve_ids, canonical_pypi[0].cve_ids, "{package}");
        }

        let unsupported = db
            .query_package_enriched("npm", "foo", "1.2.3", None)
            .await
            .unwrap();
        assert!(unsupported.is_empty());

        assert!(is_git_commit_hash(
            "0123456789abcdef0123456789abcdef01234567"
        ));
        assert!(!is_git_commit_hash(
            "0123456789ABCDEF0123456789ABCDEF01234567"
        ));
        assert!(!is_git_commit_hash("1.2.3"));
    });
}

#[test]
fn deferred_osv_import_rebuilds_search_once_and_bulk_finish_restores_indexes() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    runtime.block_on(async {
        let db = CveDatabase::connect("sqlite::memory:").await.unwrap();
        db.initialize_schema().await.unwrap();

        db.prepare_bulk_osv_import().await.unwrap();
        let dropped_indexes = db
            .connection()
            .query_all(Statement::from_string(
                DbBackend::Sqlite,
                "SELECT name FROM sqlite_master WHERE type = 'index' AND name IN ('idx_osv_raw_records_content_hash', 'idx_osv_aliases_alias', 'idx_osv_cve_search_cve_id', 'idx_osv_affected_packages_lookup', 'idx_osv_ranges_package', 'idx_osv_range_events_range', 'idx_identifier_edges_to', 'idx_identifier_edges_from')".to_owned(),
            ))
            .await
            .unwrap();
        assert!(dropped_indexes.is_empty());
        db.finish_bulk_osv_import().await.unwrap();
        let restored_indexes = db
            .connection()
            .query_all(Statement::from_string(
                DbBackend::Sqlite,
                "SELECT name FROM sqlite_master WHERE type = 'index' AND name IN ('idx_osv_raw_records_content_hash', 'idx_osv_aliases_alias', 'idx_osv_cve_search_cve_id', 'idx_osv_affected_packages_lookup', 'idx_osv_ranges_package', 'idx_osv_range_events_range', 'idx_identifier_edges_to', 'idx_identifier_edges_from')".to_owned(),
            ))
            .await
            .unwrap();
        assert_eq!(restored_indexes.len(), OSV_BULK_LOAD_FINAL_INDEXES.len());

        let (summary, _) = db
            .import_osv_records_deferred_search_with_cursor_count_and_timings(
                vec![OsvRawRecord {
                    source_path: Some("GHSA-TEST-0001.json".to_owned()),
                    raw_json: include_str!("../../fixtures/osv/GHSA-TEST-0001.json").to_owned(),
                }],
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(summary.imported, 1);
        assert!(
            db.search_osv_summaries_free_text("duplicate fixture", 10, 0)
                .await
                .unwrap()
                .is_empty()
        );
        db.rebuild_osv_text_search().await.unwrap();
        assert_eq!(
            db.search_osv_summaries_free_text("duplicate fixture", 10, 0)
                .await
                .unwrap()
                .len(),
            1
        );
    });
}

#[test]
fn scoped_osv_search_uses_registered_families_and_ecosystems() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    runtime.block_on(async {
        let db = CveDatabase::connect("sqlite::memory:").await.unwrap();
        db.initialize_schema().await.unwrap();
        db.import_osv_records(vec![
            OsvRawRecord {
                source_path: Some("GHSA-TEST-0001.json".to_owned()),
                raw_json: include_str!("../../fixtures/osv/GHSA-TEST-0001.json").to_owned(),
            },
            OsvRawRecord {
                source_path: Some("RUSTSEC-TEST-0001.json".to_owned()),
                raw_json: include_str!("../../fixtures/osv/RUSTSEC-TEST-0001.json").to_owned(),
            },
        ])
        .await
        .unwrap();

        assert_eq!(
            db.osv_advisory_families().await.unwrap(),
            vec!["GHSA", "RUSTSEC"]
        );
        assert_eq!(db.osv_ecosystems().await.unwrap(), vec!["crates.io"]);

        let ghsa = db
            .search_osv_summaries_scoped(None, &["GHSA".to_owned()], None, 10, 0)
            .await
            .unwrap();
        assert_eq!(ghsa.len(), 1);
        assert!(ghsa[0].osv_id.starts_with("GHSA-"));

        let searched_ghsa = db
            .search_osv_summaries_scoped(Some("duplicate"), &["GHSA".to_owned()], None, 10, 0)
            .await
            .unwrap();
        assert_eq!(searched_ghsa.len(), 1);
        assert!(searched_ghsa[0].osv_id.starts_with("GHSA-"));

        assert_eq!(
            db.count_osv_summaries_scoped(
                None,
                &["GHSA".to_owned(), "RUSTSEC".to_owned()],
                Some(&[]),
            )
            .await
            .unwrap(),
            0
        );
        assert!(
            db.search_osv_summaries_scoped(
                None,
                &["GHSA".to_owned(), "RUSTSEC".to_owned()],
                Some(&[]),
                10,
                0,
            )
            .await
            .unwrap()
            .is_empty()
        );
    });
}

#[test]
fn osv_identifier_search_prioritizes_an_exact_advisory_id() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    runtime.block_on(async {
        let db = CveDatabase::connect("sqlite::memory:").await.unwrap();
        db.initialize_schema().await.unwrap();
        db.import_osv_records(vec![
            OsvRawRecord {
                source_path: Some("GHSA-EXACT-0001.json".to_owned()),
                raw_json: r#"{
                    "schema_version":"1.7.5",
                    "id":"GHSA-EXACT-0001",
                    "published":"2099-01-01T00:00:00Z",
                    "modified":"2099-01-01T00:00:00Z",
                    "summary":"exact"
                }"#
                .to_owned(),
            },
            OsvRawRecord {
                source_path: Some("GHSA-EXACT-0001-NEWER.json".to_owned()),
                raw_json: r#"{
                    "schema_version":"1.7.5",
                    "id":"GHSA-EXACT-0001-NEWER",
                    "published":"2099-02-01T00:00:00Z",
                    "modified":"2099-02-01T00:00:00Z",
                    "summary":"prefix"
                }"#
                .to_owned(),
            },
        ])
        .await
        .unwrap();

        let rows = db
            .search_osv_summaries_free_text("ghsa-exact-0001", 10, 0)
            .await
            .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].osv_id, "GHSA-EXACT-0001");
    });
}

#[test]
fn scoped_osv_exact_package_search_does_not_use_fts_prefix_matching() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    runtime.block_on(async {
        let db = CveDatabase::connect("sqlite::memory:").await.unwrap();
        db.initialize_schema().await.unwrap();
        db.import_osv_records(vec![
            OsvRawRecord {
                source_path: Some("PYSEC-DJANGO.json".to_owned()),
                raw_json: r#"{
                    "schema_version":"1.7.5", "id":"PYSEC-DJANGO",
                    "published":"2099-01-01T00:00:00Z", "modified":"2099-01-01T00:00:00Z",
                    "affected":[{"package":{"ecosystem":"PyPI","name":"Django"}}]
                }"#
                .to_owned(),
            },
            OsvRawRecord {
                source_path: Some("PYSEC-KOLIBRI.json".to_owned()),
                raw_json: r#"{
                    "schema_version":"1.7.5", "id":"PYSEC-KOLIBRI",
                    "published":"2099-02-01T00:00:00Z", "modified":"2099-02-01T00:00:00Z",
                    "affected":[{"package":{"ecosystem":"PyPI","name":"pypi/kolibri"}}]
                }"#
                .to_owned(),
            },
        ])
        .await
        .unwrap();

        let rows = db
            .search_osv_summaries_scoped_by_exact_package(None, &[], None, "django", 10, 0)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].osv_id, "PYSEC-DJANGO");
        assert_eq!(
            db.count_osv_summaries_scoped_by_exact_package(None, &[], None, "Django")
                .await
                .unwrap(),
            1
        );
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

#[test]
fn bulk_initialization_writes_20_000_cves_within_two_seconds() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    runtime.block_on(async {
        let db = CveDatabase::connect("sqlite::memory:").await.unwrap();
        db.initialize_schema().await.unwrap();

        let records = (0..20_000)
            .map(|index| CVE_JSON.replace("CVE-2024-0001", &format!("CVE-2024-{index:04}")))
            .collect::<Vec<_>>();
        let models = records
            .into_iter()
            .map(CveActiveModels::from_raw_json_string)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let session = db.begin_bulk_replace_all().await.unwrap();

        let started = std::time::Instant::now();
        let inserted = session.insert_cve_models(models).await.unwrap();
        session.finish_storage_only(&db).await.unwrap();
        let elapsed = started.elapsed();

        assert_eq!(inserted, 20_000);
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "bulk initialization wrote 20,000 CVEs in {elapsed:?}"
        );
    });
}
