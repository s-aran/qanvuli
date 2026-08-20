use super::*;

#[test]
fn database_handle_is_send_and_sync_for_spawned_command_tasks() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<SqlxDatabase>();
}

#[tokio::test]
async fn unfiltered_osv_date_orders_have_matching_indexes() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize_schema().await.unwrap();
    database
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::raw_sql(
                        "DROP INDEX idx_osv_published_asc; DROP INDEX idx_osv_published_desc; DROP INDEX idx_osv_modified_osv_id;",
                    )
                    .execute(connection)
                    .await?;
                    Ok(())
                })
            })
            .await
            .unwrap();
    database.ensure_osv_sort_indexes().await.unwrap();

    for (order_by, expected_index) in [
        (
            "published_at IS NULL ASC, published_at ASC, osv_id ASC",
            "idx_osv_published_asc",
        ),
        (
            "published_at IS NULL ASC, published_at DESC, osv_id DESC",
            "idx_osv_published_desc",
        ),
        ("modified_at DESC, osv_id DESC", "idx_osv_modified_osv_id"),
    ] {
        let statement = format!(
            "EXPLAIN QUERY PLAN SELECT osv_id FROM osv_advisories ORDER BY {order_by} LIMIT 31 OFFSET 300000"
        );
        let details = database
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query(sqlx::AssertSqlSafe(statement))
                        .fetch_all(connection)
                        .await
                })
            })
            .await
            .unwrap()
            .into_iter()
            .map(|row| row.get::<String, _>("detail"))
            .collect::<Vec<_>>();
        assert!(
            details.iter().any(|detail| detail.contains(expected_index)),
            "{order_by} did not use {expected_index}: {details:?}"
        );
        assert!(
            details.iter().all(|detail| !detail.contains("TEMP B-TREE")),
            "{order_by} required a temporary sort: {details:?}"
        );
    }
}

#[test]
fn cve_package_identity_uses_collection_url_host_boundaries() {
    for (ecosystem, collection_url) in [
        ("PyPI", "https://pypi.org/project/example"),
        ("PyPI", "https://files.PyPI.org/packages/example"),
        ("PyPI", "https://user:password@pypi.org/project/example"),
        ("PyPI", "https://pypi.org:443/project/example"),
        ("PyPI", "https://pypi.org./project/example"),
        ("npm", "https://www.npmjs.com/package/example"),
        ("Maven", "https://repo.maven.apache.org/maven2/example"),
    ] {
        assert!(
            cve_package_identity(ecosystem, None, None, Some(collection_url))
                == CvePackageIdentity::Confirmed,
            "expected collection host to match: {collection_url}"
        );
    }

    for collection_url in [
        "https://pypi.org.evil.invalid/project/example",
        "https://evilpypi.org/project/example",
        "https://evil.invalid/project/pypi.org",
        "https://pypi.org@evil.invalid/project/example",
        "https://evil.invalid?collection=https://pypi.org",
        "pypi.org/project/example",
        "https://pypi.org:not-a-port/project/example",
    ] {
        assert!(
            cve_package_identity("PyPI", None, None, Some(collection_url))
                == CvePackageIdentity::Excluded,
            "expected collection host not to match: {collection_url}"
        );
    }
}

#[tokio::test]
async fn initializes_and_checks_a_new_database_on_one_writer() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    assert!(database.check_search_integrity_quick().await.is_err());
    database.initialize().await.unwrap();
    database.check_search_integrity_quick().await.unwrap();
    database.rebuild_search().await.unwrap();
    database.check().await.unwrap();
    database.check_full_sqlite().await.unwrap();
    database.check_full_foreign_keys().await.unwrap();
    database.check_full_cve_search().await.unwrap();
    database.check_full_osv_search().await.unwrap();
    assert_eq!(SqlxDatabase::schema_version(), 11);
}

#[tokio::test]
async fn repeated_initialization_is_idempotent() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    database.initialize().await.unwrap();
    database.check().await.unwrap();
}

#[tokio::test]
async fn initialization_rejects_an_incompatible_existing_schema_without_stamping_it() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::raw_sql(
                        "CREATE TABLE schema_meta(version INTEGER NOT NULL); INSERT INTO schema_meta VALUES(6); CREATE TABLE cve(id INTEGER PRIMARY KEY);",
                    )
                    .execute(connection)
                    .await?;
                    Ok(())
                })
            })
            .await
            .unwrap();

    assert!(database.initialize().await.is_err());
    let version: i64 = database
        .writer
        .with_connection(|connection| {
            Box::pin(async move {
                sqlx::query_scalar("SELECT version FROM schema_meta")
                    .fetch_one(connection)
                    .await
            })
        })
        .await
        .unwrap();
    assert_eq!(version, 6);
}

#[tokio::test]
async fn quick_check_detects_disabled_foreign_keys() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    database
        .writer
        .with_connection(|connection| {
            Box::pin(async move {
                sqlx::query("PRAGMA foreign_keys=OFF")
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .await
        .unwrap();
    assert!(
        database
            .check()
            .await
            .unwrap_err()
            .to_string()
            .contains("disabled")
    );
}

#[tokio::test]
async fn quick_check_detects_and_rebuild_repairs_missing_fts_rows() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    database
            .import_cve_raw_jsons_bulk_init(vec![
                r#"{"cveMetadata":{"cveId":"CVE-2099-9901","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-01T00:00:00Z"},"containers":{"cna":{"title":"integrity fixture"}}}"#.to_owned(),
            ])
            .await
            .unwrap();
    database.rebuild_search().await.unwrap();
    database
        .writer
        .with_connection(|connection| {
            Box::pin(async move {
                sqlx::query("DELETE FROM cve_summary_fts WHERE cve_id='CVE-2099-9901'")
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .await
        .unwrap();
    assert!(database.check().await.is_err());
    database.rebuild_search().await.unwrap();
    database.check().await.unwrap();
}

#[tokio::test]
async fn quick_check_detects_extra_osv_fts_rows() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    database
        .writer
        .with_connection(|connection| {
            Box::pin(async move {
                sqlx::query(
                    "INSERT INTO osv_text_fts(osv_id, summary) VALUES('OSV-EXTRA', 'extra')",
                )
                .execute(connection)
                .await?;
                Ok(())
            })
        })
        .await
        .unwrap();
    assert!(database.check().await.is_err());
}

#[tokio::test]
async fn schema_check_detects_missing_required_index() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    database
        .writer
        .with_connection(|connection| {
            Box::pin(async move {
                sqlx::query("DROP INDEX idx_cve_updated_at_cve_id")
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .await
        .unwrap();
    assert!(database.check_search_integrity_quick().await.is_err());
    assert!(database.initialize().await.is_err());
}

#[tokio::test]
async fn current_version_does_not_hide_an_incompatible_table_shape() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    database
        .writer
        .with_connection(|connection| {
            Box::pin(async move {
                sqlx::query("ALTER TABLE cve DROP COLUMN serial")
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .await
        .unwrap();
    let error = database
        .check_search_integrity_quick()
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("cve.serial"));
    assert!(database.initialize().await.is_err());
}

#[tokio::test]
async fn schema_check_rejects_wrong_index_columns() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    database
        .writer
        .with_connection(|connection| {
            Box::pin(async move {
                sqlx::query("DROP INDEX idx_osv_ranges_package")
                    .execute(&mut *connection)
                    .await?;
                sqlx::query("CREATE INDEX idx_osv_ranges_package ON osv_ranges(range_type)")
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .await
        .unwrap();
    assert!(
        database
            .check_required_schema()
            .await
            .unwrap_err()
            .to_string()
            .contains("wrong columns")
    );
}

#[tokio::test]
async fn schema_check_rejects_missing_foreign_key() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    database.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query("DROP TABLE osv_aliases").execute(&mut *connection).await?;
            sqlx::query("CREATE TABLE osv_aliases (osv_id TEXT NOT NULL, alias_id TEXT NOT NULL, PRIMARY KEY(osv_id, alias_id))").execute(&mut *connection).await?;
            sqlx::query("CREATE INDEX idx_osv_aliases_alias ON osv_aliases(alias_id)").execute(connection).await?;
            Ok(())
        })).await.unwrap();
    assert!(
        database
            .check_required_schema()
            .await
            .unwrap_err()
            .to_string()
            .contains("foreign key")
    );
}

#[tokio::test]
async fn schema_check_rejects_normal_table_in_place_of_fts() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    database.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query("DROP TABLE osv_text_fts").execute(&mut *connection).await?;
            sqlx::query("CREATE TABLE osv_text_fts (osv_id TEXT, summary TEXT, details TEXT, aliases TEXT, packages TEXT)").execute(connection).await?;
            Ok(())
        })).await.unwrap();
    assert!(
        database
            .check_required_schema()
            .await
            .unwrap_err()
            .to_string()
            .contains("FTS5")
    );
}

#[tokio::test]
async fn schema_check_rejects_missing_unique_constraint() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    database.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query("DROP TABLE osv_versions").execute(&mut *connection).await?;
            sqlx::query("CREATE TABLE osv_versions (affected_package_id INTEGER NOT NULL REFERENCES osv_affected_packages(id) ON DELETE CASCADE, version TEXT NOT NULL)").execute(connection).await?;
            Ok(())
        })).await.unwrap();
    assert!(
        database
            .check_required_schema()
            .await
            .unwrap_err()
            .to_string()
            .contains("UNIQUE")
    );
}

#[tokio::test]
async fn bulk_cve_load_defers_search_and_restores_indexes_and_pragmas() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    database.prepare_cve_bulk_load().await.unwrap();
    database
            .import_cve_raw_jsons_bulk_init(vec![
                r#"{"cveMetadata":{"cveId":"CVE-2099-9001","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-01T00:00:00Z"},"containers":{"cna":{"title":"Deferred bulk search fixture"}}}"#.to_owned(),
            ])
            .await
            .unwrap();
    assert!(
            database
                .import_cve_raw_jsons_bulk_init(vec![
                    r#"{"cveMetadata":{"cveId":"CVE-2099-9001","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-01T00:00:00Z"},"containers":{"cna":{"title":"duplicate"}}}"#.to_owned(),
                ])
                .await
                .is_err()
        );

    assert!(
        database
            .search_cves("deferred", false, 10)
            .await
            .unwrap()
            .is_empty()
    );
    database.finish_cve_bulk_load().await.unwrap();
    assert_eq!(
        database
            .search_cves("deferred", false, 10)
            .await
            .unwrap()
            .len(),
        1
    );

    let (foreign_keys, index_exists): (i64, i64) = database
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    let foreign_keys = sqlx::query_scalar("PRAGMA foreign_keys")
                        .fetch_one(&mut *connection)
                        .await?;
                    let index_exists = sqlx::query_scalar("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_cve_updated_at_cve_id'")
                        .fetch_one(&mut *connection)
                        .await?;
                    Ok((foreign_keys, index_exists))
                })
            })
            .await
            .unwrap();
    assert_eq!(foreign_keys, 1);
    assert_eq!(index_exists, 1);
}

#[tokio::test]
async fn persists_update_metadata_without_exposing_database_ids() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    database
        .set_metadata_value("cve_asset:test", "applied")
        .await
        .unwrap();
    database
        .mark_cve_asset_applied("delta.zip", "local")
        .await
        .unwrap();
    assert_eq!(
        database.metadata_value("cve_asset:test").await.unwrap(),
        Some("applied".to_owned())
    );
    database.check().await.unwrap();
}

#[tokio::test]
async fn imports_osv_relations_ranges_and_repo_in_one_writer_transaction() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    database
        .import_osv_record(OsvRawRecord {
            source_path: None,
            raw_json: include_str!("../../../../fixtures/osv/GHSA-TEST-0001.json").to_owned(),
        })
        .await
        .unwrap();
    let relation_count: i64 = database
        .writer
        .with_connection(|connection| {
            Box::pin(async move {
                sqlx::query_scalar("SELECT COUNT(*) FROM osv_aliases")
                    .fetch_one(connection)
                    .await
            })
        })
        .await
        .unwrap();
    assert!(relation_count > 0);
    let indexed: i64 = database
        .writer
        .with_connection(|connection| {
            Box::pin(async move {
                sqlx::query_scalar("SELECT COUNT(*) FROM osv_text_fts")
                    .fetch_one(connection)
                    .await
            })
        })
        .await
        .unwrap();
    assert_eq!(indexed, 1);
    let matches = database.search_osv("fixture", 10).await.unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(
        matches[0].details.as_deref(),
        Some("Withdrawn records remain in the alias graph.")
    );
    let found = database
        .find_osv_summary("GHSA-TEST-0001")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.osv_id, "GHSA-TEST-0001");
    assert_eq!(found.details, matches[0].details);
}

#[tokio::test]
async fn loads_tui_enrichment_summaries_for_cve_results() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    database
            .import_cve_raw_json(
                r#"{"cveMetadata":{"cveId":"CVE-2099-7001","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-01T00:00:00Z"},"containers":{"cna":{"title":"TUI enrichment fixture"}}}"#.to_owned(),
            )
            .await
            .unwrap();

    let rows = database
        .enriched_cve_summaries(&["CVE-2099-7001".to_owned()])
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].cve_id, "CVE-2099-7001");
}

#[tokio::test]
async fn batches_tui_overview_details_and_preserves_result_order() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    database
            .import_cve_raw_jsons(vec![
                r#"{"cveMetadata":{"cveId":"CVE-2099-7101","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-01T00:00:00Z"},"containers":{"cna":{"title":"First overview fixture","affected":[{"vendor":"Acme","product":"widget","description":"Widget deployment is affected.","versions":[{"version":"1.0","status":"affected","versionType":"semver","lessThan":"2.0"}]}],"metrics":[{"cvssV3_1":{"version":"3.1","baseScore":9.8,"baseSeverity":"CRITICAL"}}],"problemTypes":[{"descriptions":[{"cweId":"CWE-79","description":"XSS"}]}]}}}"#.to_owned(),
                r#"{"cveMetadata":{"cveId":"CVE-2099-7102","state":"PUBLISHED","datePublished":"2099-01-02T00:00:00Z","dateUpdated":"2099-01-02T00:00:00Z"},"containers":{"cna":{"title":"Second overview fixture","affected":[{"vendor":"Example","product":"service","description":"Service deployment is affected."}],"metrics":[{"cvssV4_0":{"version":"4.0","baseScore":7.2,"baseSeverity":"HIGH"}}],"problemTypes":[{"descriptions":[{"cweId":"CWE-89","description":"SQL injection"}]}]}}}"#.to_owned(),
            ])
            .await
            .unwrap();

    let mut summaries = database
        .search_cve_summaries_by_cve_id_prefix_with_state_scope(
            "CVE-2099-71",
            CveStateScope::PublishedOnly,
            10,
            0,
        )
        .await
        .unwrap();
    summaries.reverse();
    let expected_order = summaries
        .iter()
        .map(|row| row.cve_id.clone())
        .collect::<Vec<_>>();
    let rows = database
        .attach_cve_overview_details(summaries)
        .await
        .unwrap();

    assert_eq!(
        rows.iter()
            .map(|row| row.summary.cve_id.clone())
            .collect::<Vec<_>>(),
        expected_order
    );
    assert!(rows.iter().all(|row| row.detail.cwes.len() == 1));
    assert!(rows.iter().all(|row| row.detail.cvss.len() == 1));
    assert!(rows.iter().all(|row| row.detail.affected.len() == 1));
    assert!(rows.iter().all(|row| {
        row.detail.affected[0]
            .description
            .as_deref()
            .is_some_and(|description| description.ends_with("deployment is affected."))
    }));
    assert_eq!(
        rows.iter()
            .find(|row| row.summary.cve_id == "CVE-2099-7101")
            .expect("first fixture")
            .detail
            .affected[0]
            .versions[0]
            .less_than
            .as_deref(),
        Some("2.0")
    );
}

#[tokio::test]
async fn imports_and_searches_cwe_catalog_statuses_and_tree_relationships() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../collector/src/cwec_v4.20.xml");
    let catalog = qanvuli_models::cwe::read_cwe_catalog_xml(path).unwrap();
    let imported = database.upsert_cwe_catalog(&catalog).await.unwrap();
    assert!(imported > 1_000);

    let populated: (i64, i64) = database
        .writer
        .with_connection(|connection| {
            Box::pin(async move {
                sqlx::query_as(
                    "SELECT COUNT(status), COUNT(parent_id) FROM cwe WHERE status IS NOT NULL",
                )
                .fetch_one(connection)
                .await
            })
        })
        .await
        .unwrap();
    assert!(populated.0 > 1_000);
    assert!(populated.1 > 0);

    let all_statuses = [
        "Stable",
        "Usable",
        "Draft",
        "Incomplete",
        "Obsolete",
        "Deprecated",
    ]
    .map(str::to_owned);
    let rows = database
        .search_cwe_entries("", 2_000, &all_statuses)
        .await
        .unwrap();
    assert!(rows.iter().all(|row| row.status.is_some()));
    assert!(rows.iter().any(|row| row.parent_count > 0));
    assert!(rows.iter().any(|row| row.child_count > 0));
    for row in rows.iter().filter(|row| row.parent_id.is_some()) {
        let parent = row.parent_id.unwrap();
        assert!(
            rows.iter().position(|entry| entry.id == parent)
                < rows.iter().position(|entry| entry.id == row.id)
        );
    }

    let stable = database
        .search_cwe_entries("", 2_000, &["Stable".to_owned()])
        .await
        .unwrap();
    assert!(!stable.is_empty());
    assert!(
        stable
            .iter()
            .all(|row| row.status.as_deref() == Some("Stable"))
    );
    assert!(
        database
            .search_cwe_entries("", 2_000, &[])
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn bulk_osv_init_uses_insert_only_while_updates_remain_idempotent() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    database.prepare_osv_bulk_load().await.unwrap();
    let record = OsvRawRecord {
        source_path: None,
        raw_json: include_str!("../../../../fixtures/osv/GHSA-TEST-0001.json").to_owned(),
    };

    assert_eq!(
        database
            .import_osv_records_bulk_init(vec![record.clone()])
            .await
            .unwrap(),
        1
    );
    assert!(
        database
            .import_osv_records_bulk_init(vec![record.clone()])
            .await
            .is_err()
    );
    database.finish_osv_bulk_load().await.unwrap();

    assert_eq!(
        database
            .import_osv_records_deferred_search(vec![record])
            .await
            .unwrap(),
        1
    );
    let advisory_count: i64 = database
        .writer
        .with_connection(|connection| {
            Box::pin(async move {
                sqlx::query_scalar("SELECT COUNT(*) FROM osv_advisories")
                    .fetch_one(connection)
                    .await
            })
        })
        .await
        .unwrap();
    assert_eq!(advisory_count, 1);
}

#[tokio::test]
async fn osv_child_batches_cross_conservative_sqlite_bind_limits() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    let versions = (0..1_001)
        .map(|index| format!("1.0.{index}"))
        .collect::<Vec<_>>();
    let references = (0..301)
        .map(|index| {
            serde_json::json!({
                "type": "WEB",
                "url": format!("https://example.invalid/{index}")
            })
        })
        .collect::<Vec<_>>();
    let events = (0..301)
        .map(|index| serde_json::json!({"introduced": format!("1.0.{index}")}))
        .collect::<Vec<_>>();
    let raw_json = serde_json::json!({
        "schema_version": "1.8.0",
        "id": "OSV-2099-large-children",
        "modified": "2099-01-01T00:00:00Z",
        "references": references,
        "affected": [{
            "package": {"ecosystem": "Go", "name": "example.invalid/large"},
            "ranges": [{"type": "SEMVER", "events": events}],
            "versions": versions
        }]
    })
    .to_string();
    database.prepare_osv_bulk_load().await.unwrap();
    database
        .import_osv_records_bulk_init(vec![OsvRawRecord {
            source_path: None,
            raw_json,
        }])
        .await
        .unwrap();
    database.finish_osv_bulk_load().await.unwrap();
    let counts: (i64, i64, i64) = database.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query_as("SELECT (SELECT COUNT(*) FROM osv_references), (SELECT COUNT(*) FROM osv_range_events), (SELECT COUNT(*) FROM osv_versions)")
                .fetch_one(connection).await
        })).await.unwrap();
    assert_eq!(counts, (301, 301, 1_001));
}

#[tokio::test]
async fn file_backed_osv_bulk_finish_restores_wal_without_locks() {
    let path = std::env::temp_dir().join(format!(
        "qanvuli-osv-bulk-finish-{}-{}.sqlite",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    let database_url = format!(
        "sqlite:///{}?mode=rwc",
        path.to_string_lossy().replace('\\', "/")
    );
    let database = SqlxDatabase::connect(&database_url).await.unwrap();
    database.initialize().await.unwrap();
    database.prepare_osv_bulk_load().await.unwrap();
    let records = (0..500)
            .map(|index| OsvRawRecord {
                source_path: None,
                raw_json: format!(
                    r#"{{"schema_version":"1.8.0","id":"OSV-2099-{index}","modified":"2099-01-01T00:00:00Z","aliases":["CVE-2099-{index}"],"affected":[{{"package":{{"ecosystem":"Go","name":"example/{index}"}},"ranges":[{{"type":"SEMVER","events":[{{"introduced":"0"}}]}}]}}]}}"#
                ),
            })
            .collect();
    assert_eq!(
        database
            .import_osv_records_bulk_init(records)
            .await
            .unwrap(),
        500
    );
    database.finish_osv_bulk_load().await.unwrap();
    let modes: (String, String, i64) = database
        .writer
        .with_connection(|connection| {
            Box::pin(async move {
                let journal: String = sqlx::query_scalar("PRAGMA journal_mode")
                    .fetch_one(&mut *connection)
                    .await?;
                let locking: String = sqlx::query_scalar("PRAGMA locking_mode")
                    .fetch_one(&mut *connection)
                    .await?;
                let foreign_keys: i64 = sqlx::query_scalar("PRAGMA foreign_keys")
                    .fetch_one(&mut *connection)
                    .await?;
                Ok((journal, locking, foreign_keys))
            })
        })
        .await
        .unwrap();
    assert_eq!(modes, ("wal".to_owned(), "normal".to_owned(), 1));
    database
        .set_metadata_value("osv_bulk_close_test", "written_after_wal_restore")
        .await
        .unwrap();
    database.close().await.unwrap();
    assert!(!path.with_extension("sqlite-wal").exists());
    assert!(!path.with_extension("sqlite-shm").exists());
    let reopened = SqlxDatabase::connect(&database_url).await.unwrap();
    assert_eq!(
        reopened
            .metadata_value("osv_bulk_close_test")
            .await
            .unwrap(),
        Some("written_after_wal_restore".to_owned())
    );
    reopened.close().await.unwrap();
    for candidate in [
        path.clone(),
        path.with_extension("sqlite-wal"),
        path.with_extension("sqlite-shm"),
    ] {
        let _ = std::fs::remove_file(candidate);
    }
}

#[tokio::test]
async fn independent_connection_keeps_in_memory_contents() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    database
        .set_metadata_value("independent_connection_test", "visible")
        .await
        .unwrap();

    let independent = database.independent_connection().await.unwrap();
    assert_eq!(
        independent
            .metadata_value("independent_connection_test")
            .await
            .unwrap(),
        Some("visible".to_owned())
    );
}

#[tokio::test]
async fn keeps_alias_upstream_and_related_as_distinct_graph_edges() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    database.import_osv_record(OsvRawRecord {
            source_path: None,
            raw_json: r#"{"schema_version":"1.8.0","id":"GHSA-2099-test","modified":"2099-01-01T00:00:00Z","aliases":["CVE-2099-1"],"upstream":["UPSTREAM-1"],"related":["RELATED-1"]}"#.to_owned(),
        }).await.unwrap();
    let edge_counts: Vec<(String, i64)> = database.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query_as("SELECT relation_type, COUNT(*) FROM vulnerability_identifier_edges GROUP BY relation_type ORDER BY relation_type")
                .fetch_all(connection).await
        })).await.unwrap();
    assert_eq!(
        edge_counts,
        vec![
            ("alias".to_owned(), 2),
            ("related".to_owned(), 2),
            ("upstream".to_owned(), 1),
        ]
    );
    let resolution = database.resolve_identifier("GHSA-2099-test").await.unwrap();
    assert_eq!(resolution.related_cve_ids, vec!["CVE-2099-1"]);
    assert!(
        !resolution
            .related_osv_ids
            .iter()
            .any(|id| id == "UPSTREAM-1" || id == "RELATED-1")
    );
    let edges = database.identifier_edges("GHSA-2099-test").await.unwrap();
    assert!(edges.iter().any(|edge| edge.relation_type == "alias"));
    assert!(edges.iter().any(|edge| edge.relation_type == "upstream"));
    database.rebuild_identifier_graph().await.unwrap();
    assert_eq!(
        database
            .identifier_edges("GHSA-2099-test")
            .await
            .unwrap()
            .len(),
        edges.len()
    );
}

#[tokio::test]
async fn repeated_osv_import_rebuilds_derived_edges_without_stale_duplicates() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    database.import_osv_records_deferred_search(vec![OsvRawRecord {
            source_path: None,
            raw_json: r#"{"schema_version":"1.8.0","id":"GHSA-2099-edge","modified":"2099-01-01T00:00:00Z","aliases":["CVE-2099-old"]}"#.to_owned(),
        }]).await.unwrap();
    database.import_osv_records_deferred_search(vec![OsvRawRecord {
            source_path: None,
            raw_json: r#"{"schema_version":"1.8.0","id":"GHSA-2099-edge","modified":"2099-01-02T00:00:00Z","aliases":["CVE-2099-new"]}"#.to_owned(),
        }]).await.unwrap();
    let edges: Vec<String> = database.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query_scalar("SELECT to_identifier FROM vulnerability_identifier_edges WHERE source='OSV' AND from_identifier='GHSA-2099-edge' ORDER BY to_identifier")
                .fetch_all(connection).await
        })).await.unwrap();
    assert_eq!(edges, vec!["CVE-2099-new".to_owned()]);
    let stale_reverse_edges: i64 = database.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query_scalar("SELECT COUNT(*) FROM vulnerability_identifier_edges WHERE source='OSV' AND from_identifier='CVE-2099-old' AND to_identifier='GHSA-2099-edge'")
                .fetch_one(connection).await
        })).await.unwrap();
    assert_eq!(stale_reverse_edges, 0);
}

#[tokio::test]
async fn unchanged_osv_batch_does_not_rewrite_normalized_rows() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    let record = OsvRawRecord {
            source_path: Some("Go/GO-2099-unchanged.json".to_owned()),
            raw_json: r#"{"schema_version":"1.8.0","id":"GO-2099-unchanged","modified":"2099-01-01T00:00:00Z","aliases":["CVE-2099-1"],"affected":[{"package":{"ecosystem":"Go","name":"example.invalid/package"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}],"versions":["1.0.0"]}]}"#.to_owned(),
        };
    database
        .import_osv_records_deferred_search_with_stats(vec![record.clone()])
        .await
        .unwrap();
    let changes_before: i64 = database
        .writer
        .with_connection(|connection| {
            Box::pin(async move {
                sqlx::query_scalar("SELECT total_changes()")
                    .fetch_one(connection)
                    .await
            })
        })
        .await
        .unwrap();
    let stats = database
        .import_osv_records_deferred_search_with_stats(vec![record])
        .await
        .unwrap();
    let changes_after: i64 = database
        .writer
        .with_connection(|connection| {
            Box::pin(async move {
                sqlx::query_scalar("SELECT total_changes()")
                    .fetch_one(connection)
                    .await
            })
        })
        .await
        .unwrap();
    assert_eq!(
        stats,
        OsvImportStats {
            examined: 1,
            inserted: 0,
            updated: 0,
            unchanged: 1
        }
    );
    assert_eq!(changes_after, changes_before);
}

#[tokio::test]
async fn incremental_osv_search_updates_only_changed_projection_and_matches_rebuild() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    let unchanged = OsvRawRecord {
        source_path: None,
        raw_json:
            r#"{"id":"GO-2099-unchanged","modified":"2099-01-01T00:00:00Z","summary":"untouched"}"#
                .to_owned(),
    };
    let original = OsvRawRecord {
            source_path: None,
            raw_json: r#"{"id":"GO-2099-changed","modified":"2099-01-01T00:00:00Z","aliases":["CVE-2099-old"],"affected":[{"package":{"ecosystem":"Go","name":"old.example/pkg","purl":"pkg:golang/old.example/pkg"}}]}"#.to_owned(),
        };
    database
        .import_osv_records_incremental_with_stats(vec![unchanged.clone(), original])
        .await
        .unwrap();
    let untouched_before: (i64, String) = database
        .writer
        .with_connection(|connection| {
            Box::pin(async move {
                sqlx::query_as(
                    "SELECT rowid, summary FROM osv_text_fts WHERE osv_id='GO-2099-unchanged'",
                )
                .fetch_one(connection)
                .await
            })
        })
        .await
        .unwrap();
    let changed = OsvRawRecord {
            source_path: None,
            raw_json: r#"{"id":"GO-2099-changed","modified":"2099-01-02T00:00:00Z","aliases":["CVE-2099-new"],"affected":[{"package":{"ecosystem":"Go","name":"new.example/pkg","purl":"pkg:golang/new.example/pkg"}}]}"#.to_owned(),
        };
    let stats = database
        .import_osv_records_incremental_with_stats(vec![unchanged, changed])
        .await
        .unwrap();
    assert_eq!(stats.updated, 1);
    assert_eq!(stats.unchanged, 1);

    let untouched_after: (i64, String) = database
        .writer
        .with_connection(|connection| {
            Box::pin(async move {
                sqlx::query_as(
                    "SELECT rowid, summary FROM osv_text_fts WHERE osv_id='GO-2099-unchanged'",
                )
                .fetch_one(connection)
                .await
            })
        })
        .await
        .unwrap();
    assert_eq!(untouched_after, untouched_before);
    let incremental_rows: Vec<(String, String, String)> = database
        .writer
        .with_connection(|connection| {
            Box::pin(async move {
                sqlx::query_as("SELECT osv_id, aliases, packages FROM osv_text_fts ORDER BY osv_id")
                    .fetch_all(connection)
                    .await
            })
        })
        .await
        .unwrap();
    assert!(incremental_rows.iter().any(|(id, aliases, packages)| {
        id == "GO-2099-changed"
            && aliases == "CVE-2099-new"
            && packages.contains("new.example/pkg")
            && packages.contains("pkg:golang/new.example/pkg")
            && !aliases.contains("old")
            && !packages.contains("old.example")
    }));
    let changed_rowids: (i64, i64) = database
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query_as(
                        "SELECT advisory.rowid, fts.rowid FROM osv_advisories advisory JOIN osv_text_fts fts USING(osv_id) WHERE advisory.osv_id='GO-2099-changed'",
                    )
                    .fetch_one(connection)
                    .await
                })
            })
            .await
            .unwrap();
    assert_eq!(changed_rowids.0, changed_rowids.1);
    database.check_search_integrity_quick().await.unwrap();
    database.rebuild_osv_search().await.unwrap();
    let rebuilt_rows: Vec<(String, String, String)> = database
        .writer
        .with_connection(|connection| {
            Box::pin(async move {
                sqlx::query_as("SELECT osv_id, aliases, packages FROM osv_text_fts ORDER BY osv_id")
                    .fetch_all(connection)
                    .await
            })
        })
        .await
        .unwrap();
    assert_eq!(incremental_rows, rebuilt_rows);
}

#[tokio::test]
async fn incremental_cve_search_refresh_matches_full_rebuild() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    database
            .import_cve_raw_jsons(vec![
                r#"{"cveMetadata":{"cveId":"CVE-2099-1001","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-01T00:00:00Z"},"containers":{"cna":{"title":"unchanged"}}}"#.to_owned(),
                r#"{"cveMetadata":{"cveId":"CVE-2099-1002","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-01T00:00:00Z"},"containers":{"cna":{"title":"old title"}}}"#.to_owned(),
            ])
            .await
            .unwrap();
    let (_, changed_ids) = database
            .import_cve_raw_jsons_deferred_search_with_ids(vec![
                r#"{"cveMetadata":{"cveId":"CVE-2099-1002","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-02T00:00:00Z"},"containers":{"cna":{"title":"new title"}}}"#.to_owned(),
            ])
            .await
            .unwrap();
    database
        .refresh_cve_search_for_ids(changed_ids)
        .await
        .unwrap();
    database.check_full_cve_search().await.unwrap();
    let aligned_rows: i64 = database
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query_scalar(
                        "SELECT COUNT(*) FROM cve_summary_index projection JOIN cve_summary_fts fts ON fts.rowid=projection.cve_db_id AND fts.cve_id=projection.cve_id",
                    )
                    .fetch_one(connection)
                    .await
                })
            })
            .await
            .unwrap();
    assert_eq!(aligned_rows, 2);
    let incremental_rows: Vec<(String, String)> = database
        .writer
        .with_connection(|connection| {
            Box::pin(async move {
                sqlx::query_as("SELECT cve_id, title FROM cve_summary_index ORDER BY cve_id")
                    .fetch_all(connection)
                    .await
            })
        })
        .await
        .unwrap();
    assert!(
        incremental_rows
            .iter()
            .any(|(id, title)| id == "CVE-2099-1002" && title == "new title")
    );
    database.rebuild_cve_search().await.unwrap();
    let rebuilt_rows: Vec<(String, String)> = database
        .writer
        .with_connection(|connection| {
            Box::pin(async move {
                sqlx::query_as("SELECT cve_id, title FROM cve_summary_index ORDER BY cve_id")
                    .fetch_all(connection)
                    .await
            })
        })
        .await
        .unwrap();
    assert_eq!(incremental_rows, rebuilt_rows);
}

/// Reproducible local micro-benchmark for the incremental OSV update hot path.
/// Run with: cargo test -p qanvuli-db benchmark_unchanged_osv_batch -- --ignored --nocapture
#[tokio::test]
#[ignore = "performance benchmark"]
async fn benchmark_unchanged_osv_batch() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    let records = (0..5_000)
            .map(|index| OsvRawRecord {
                source_path: Some(format!("Go/GO-2099-{index}.json")),
                raw_json: format!(
                    r#"{{"schema_version":"1.8.0","id":"GO-2099-{index}","modified":"2099-01-01T00:00:00Z","aliases":["CVE-2099-{index}"],"references":[{{"type":"WEB","url":"https://example.invalid/{index}"}}],"affected":[{{"package":{{"ecosystem":"Go","name":"example.invalid/package/{index}"}},"ranges":[{{"type":"SEMVER","events":[{{"introduced":"0"}},{{"fixed":"2.0.0"}}]}}],"versions":["1.0.0","1.1.0"]}}]}}"#
                ),
            })
            .collect::<Vec<_>>();
    database
        .import_osv_records_deferred_search(records.clone())
        .await
        .unwrap();
    let changes_before: i64 = database
        .writer
        .with_connection(|connection| {
            Box::pin(async move {
                sqlx::query_scalar("SELECT total_changes()")
                    .fetch_one(connection)
                    .await
            })
        })
        .await
        .unwrap();
    let started = std::time::Instant::now();
    database
        .import_osv_records_deferred_search(records)
        .await
        .unwrap();
    let elapsed = started.elapsed();
    let changes_after: i64 = database
        .writer
        .with_connection(|connection| {
            Box::pin(async move {
                sqlx::query_scalar("SELECT total_changes()")
                    .fetch_one(connection)
                    .await
            })
        })
        .await
        .unwrap();
    eprintln!(
        "unchanged OSV: records=5000 elapsed={elapsed:?} sqlite_changes={}",
        changes_after - changes_before
    );
}

/// Reproducible full-init benchmark including deferred index/search construction.
#[tokio::test]
#[ignore = "performance benchmark"]
async fn benchmark_osv_full_init() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    let records = (0..5_000)
            .map(|index| OsvRawRecord {
                source_path: Some(format!("Go/GO-2099-{index}.json")),
                raw_json: format!(
                    r#"{{"schema_version":"1.8.0","id":"GO-2099-{index}","modified":"2099-01-01T00:00:00Z","aliases":["CVE-2099-{index}"],"references":[{{"type":"WEB","url":"https://example.invalid/{index}"}}],"affected":[{{"package":{{"ecosystem":"Go","name":"example.invalid/package/{index}"}},"ranges":[{{"type":"SEMVER","events":[{{"introduced":"0"}},{{"fixed":"2.0.0"}}]}}],"versions":["1.0.0","1.1.0"]}}]}}"#
                ),
            })
            .collect::<Vec<_>>();
    database.prepare_osv_bulk_load().await.unwrap();
    let write_started = std::time::Instant::now();
    database
        .import_osv_records_bulk_init(records)
        .await
        .unwrap();
    let write_elapsed = write_started.elapsed();
    let index_started = std::time::Instant::now();
    database.finish_osv_bulk_load().await.unwrap();
    let index_elapsed = index_started.elapsed();
    eprintln!(
        "full OSV: records=5000 write={write_elapsed:?} index={index_elapsed:?} total={:?}",
        write_elapsed + index_elapsed
    );
}

/// Measures connection, strong schema validation, first lookup, and warmed repeated lookup
/// against QANVULI_BENCH_DB_URL or the workspace's db.sqlite.
#[tokio::test]
#[ignore = "requires a realistic local database"]
async fn benchmark_schema_and_lookup_latency() {
    let url = std::env::var("QANVULI_BENCH_DB_URL").unwrap_or_else(|_| {
        let current = std::env::current_dir().unwrap();
        let path = current
            .ancestors()
            .map(|directory| directory.join("db.sqlite"))
            .find(|candidate| candidate.exists())
            .expect("set QANVULI_BENCH_DB_URL or place db.sqlite in a parent directory");
        format!(
            "sqlite:///{}?mode=rw",
            path.display().to_string().replace('\\', "/")
        )
    });
    let started = std::time::Instant::now();
    let database = SqlxDatabase::connect(&url).await.unwrap();
    let connection_elapsed = started.elapsed();
    let cve_id: String = database
        .writer
        .with_connection(|connection| {
            Box::pin(async move {
                sqlx::query_scalar("SELECT cve_id FROM cve ORDER BY cve_id LIMIT 1")
                    .fetch_one(connection)
                    .await
            })
        })
        .await
        .unwrap();
    let started = std::time::Instant::now();
    database.check_required_schema().await.unwrap();
    let schema_elapsed = started.elapsed();
    let started = std::time::Instant::now();
    assert!(database.find_cve_summary(&cve_id).await.unwrap().is_some());
    let first_lookup_elapsed = started.elapsed();
    let started = std::time::Instant::now();
    for _ in 0..100 {
        assert!(database.find_cve_summary(&cve_id).await.unwrap().is_some());
    }
    let repeated_elapsed = started.elapsed();
    eprintln!(
        "schema/search benchmark: cve_id={cve_id} connection={connection_elapsed:?} schema={schema_elapsed:?} first_lookup={first_lookup_elapsed:?} repeated_100={repeated_elapsed:?} repeated_average={:?}",
        repeated_elapsed / 100
    );
    database.close().await.unwrap();
}

/// Reproducible incremental FTS benchmark for zero, one, and one hundred changes.
#[tokio::test]
#[ignore = "performance benchmark"]
async fn benchmark_incremental_osv_change_counts() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    let records = (0..100)
            .map(|index| OsvRawRecord {
                source_path: None,
                raw_json: format!(
                    r#"{{"id":"GO-2099-{index:04}","modified":"2099-01-01T00:00:00Z","summary":"original {index}","aliases":["CVE-2099-{index:04}"],"affected":[{{"package":{{"ecosystem":"Go","name":"example.invalid/pkg/{index}","purl":"pkg:golang/example.invalid/pkg/{index}@1.0.0"}}}}]}}"#
                ),
            })
            .collect::<Vec<_>>();
    database
        .import_osv_records_incremental_with_stats(records.clone())
        .await
        .unwrap();
    for changed_count in [0_usize, 1, 100] {
        let input = records
            .iter()
            .enumerate()
            .map(|(index, record)| {
                if index < changed_count {
                    let modified_date = if changed_count == 100 {
                        "2099-01-03"
                    } else {
                        "2099-01-02"
                    };
                    OsvRawRecord {
                        source_path: None,
                        raw_json: record
                            .raw_json
                            .replace("2099-01-01", modified_date)
                            .replace("original", "changed"),
                    }
                } else {
                    record.clone()
                }
            })
            .collect();
        let writes_before: i64 = database
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query_scalar("SELECT total_changes()")
                        .fetch_one(connection)
                        .await
                })
            })
            .await
            .unwrap();
        let started = std::time::Instant::now();
        let stats = database
            .import_osv_records_incremental_with_stats(input)
            .await
            .unwrap();
        let elapsed = started.elapsed();
        let writes_after: i64 = database
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query_scalar("SELECT total_changes()")
                        .fetch_one(connection)
                        .await
                })
            })
            .await
            .unwrap();
        eprintln!(
            "incremental OSV: requested_changes={changed_count} actual_changes={} elapsed={elapsed:?} sqlite_row_changes={}",
            stats.changed(),
            writes_after - writes_before
        );
    }
    for changed_count in [1_usize, 100] {
        let baseline = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        baseline.initialize().await.unwrap();
        baseline
            .import_osv_records_deferred_search(records.clone())
            .await
            .unwrap();
        baseline.rebuild_osv_search().await.unwrap();
        let input = records
            .iter()
            .enumerate()
            .map(|(index, record)| {
                if index < changed_count {
                    OsvRawRecord {
                        source_path: None,
                        raw_json: record
                            .raw_json
                            .replace("2099-01-01", "2099-01-04")
                            .replace("original", "baseline-changed"),
                    }
                } else {
                    record.clone()
                }
            })
            .collect();
        let writes_before: i64 = baseline
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query_scalar("SELECT total_changes()")
                        .fetch_one(connection)
                        .await
                })
            })
            .await
            .unwrap();
        let started = std::time::Instant::now();
        baseline
            .import_osv_records_deferred_search(input)
            .await
            .unwrap();
        baseline.rebuild_osv_search().await.unwrap();
        let elapsed = started.elapsed();
        let writes_after: i64 = baseline
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query_scalar("SELECT total_changes()")
                        .fetch_one(connection)
                        .await
                })
            })
            .await
            .unwrap();
        eprintln!(
            "baseline global OSV FTS rebuild: requested_changes={changed_count} elapsed={elapsed:?} sqlite_row_changes={}",
            writes_after - writes_before
        );
        baseline.close().await.unwrap();
    }
}

#[tokio::test]
async fn imports_cve_with_stable_fts_rowid() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    database.import_cve_raw_json(r#"{"cveMetadata":{"cveId":"CVE-2099-1","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-01T00:00:00Z"},"containers":{"cna":{"title":"Example CVE","affected":[{"vendor":"Acme","product":"widget","collectionURL":"https://pypi.org/project/widget","description":"Affected widget description.","versions":[{"version":"1.0","status":"affected","versionType":"python","lessThan":"2.0"}]}],"metrics":[{"cvssV3_1":{"version":"3.1","baseScore":9.8,"baseSeverity":"CRITICAL","vectorString":"CVSS:3.1/AV:N"}}],"problemTypes":[{"descriptions":[{"cweId":"CWE-79","description":"XSS"}]}]}}}"#.to_owned()).await.unwrap();
    let rowid: i64 = database
        .writer
        .with_connection(|connection| {
            Box::pin(async move {
                sqlx::query_scalar(
                    "SELECT rowid FROM cve_summary_fts WHERE cve_summary_fts MATCH 'example'",
                )
                .fetch_one(connection)
                .await
            })
        })
        .await
        .unwrap();
    assert_eq!(rowid, 1);
    let affected: i64 = database
        .writer
        .with_connection(|connection| {
            Box::pin(async move {
                sqlx::query_scalar("SELECT COUNT(*) FROM cve_affected")
                    .fetch_one(connection)
                    .await
            })
        })
        .await
        .unwrap();
    assert_eq!(affected, 1);
    let normalized: (i64, i64) = database
        .writer
        .with_connection(|connection| {
            Box::pin(async move {
                sqlx::query_as(
                    "SELECT (SELECT COUNT(*) FROM cve_cvss), (SELECT COUNT(*) FROM cve_cwe)",
                )
                .fetch_one(connection)
                .await
            })
        })
        .await
        .unwrap();
    assert_eq!(normalized, (1, 1));
    let identifier: String = database
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query_scalar("SELECT identifier FROM vulnerability_identifiers WHERE identifier='CVE-2099-1'")
                        .fetch_one(connection)
                        .await
                })
            })
            .await
            .unwrap();
    assert_eq!(identifier, "CVE-2099-1");
    let found = database
        .find_cve_summary("CVE-2099-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.cve_id, "CVE-2099-1");
    assert!(database.cve_raw_json("CVE-2099-1").await.unwrap().is_some());
    assert_eq!(
        database
            .search_cves_by_id_prefix("CVE-2099", false, 10, 0)
            .await
            .unwrap()
            .len(),
        1
    );
    let search = database.search_cves("example", false, 10).await.unwrap();
    assert_eq!(search.len(), 1);
    let detail = database.cve_detail("CVE-2099-1").await.unwrap().unwrap();
    assert_eq!(
        database
            .cve_summary_with_detail("CVE-2099-1")
            .await
            .unwrap()
            .unwrap()
            .summary
            .cve_id,
        "CVE-2099-1"
    );
    assert_eq!(detail.cvss.len(), 1);
    let package_findings = database
        .query_package_matches("PyPI", "widget", "1.0", None)
        .await
        .unwrap();
    assert_eq!(package_findings.len(), 1);
    assert_eq!(package_findings[0].source, "cve-list");
    assert_eq!(package_findings[0].primary_id, "CVE-2099-1");
    assert_eq!(package_findings[0].affected.status, "affected");
    assert_eq!(package_findings[0].fixed_versions, vec!["2.0"]);
    assert_eq!(
        detail.affected[0].description.as_deref(),
        Some("Affected widget description.")
    );
    assert_eq!(
        detail.affected[0].versions[0].less_than.as_deref(),
        Some("2.0")
    );
    assert_eq!(
        detail.cwes,
        vec![SqlxCwe {
            id: 79,
            description: Some("XSS".to_owned())
        }]
    );
    assert_eq!(
        database
            .search_cves_by_cwes(&["CWE-79".to_owned()], false, 10, 0)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        database.search_cwes(Some("CWE-79"), 10).await.unwrap(),
        vec![SqlxCwe {
            id: 79,
            description: Some("XSS".to_owned())
        }]
    );
    assert_eq!(database.find_cwe(79).await.unwrap().unwrap().id, 79);
    assert_eq!(
        database
            .search_cves_by_affected(
                Some("Acme".to_owned()),
                Some("widget".to_owned()),
                true,
                false,
                false,
                10,
                0,
            )
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        database
            .search_cves_by_cvss(
                SqlxCvssSearch {
                    min_score: Some(9.0),
                    max_score: None,
                    severity: Some("critical".to_owned()),
                    version: Some("3.1".to_owned()),
                },
                false,
                10,
                0,
            )
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        database
            .cve_details(&[
                "missing".to_owned(),
                "CVE-2099-1".to_owned(),
                "CVE-2099-1".to_owned(),
            ])
            .await
            .unwrap(),
        vec![None, Some(detail.clone()), Some(detail)]
    );
}

#[tokio::test]
async fn cve_list_package_supplement_requires_ecosystem_identity_for_confirmed_findings() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    database
            .import_cve_raw_jsons(vec![
                r#"{"cveMetadata":{"cveId":"CVE-2099-wordpress","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-01T00:00:00Z"},"containers":{"cna":{"title":"theme","affected":[{"vendor":"rascals","product":"Pendulum","packageName":"pendulum","collectionURL":"https://themeforest.net","versions":[{"version":"0","status":"affected","lessThan":"4.0.0"}]}]}}}"#.to_owned(),
                r#"{"cveMetadata":{"cveId":"CVE-2099-redis-server","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-01T00:00:00Z"},"containers":{"cna":{"title":"server","affected":[{"vendor":"Redis","product":"Redis","versions":[{"version":"0","status":"affected","lessThan":"8.0.0"}]}]}}}"#.to_owned(),
                r#"{"cveMetadata":{"cveId":"CVE-2099-elasticsearch-server","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-01T00:00:00Z"},"containers":{"cna":{"title":"server","affected":[{"vendor":"Elastic","product":"Elasticsearch","versions":[{"version":"0","status":"affected","lessThan":"9.0.0"}]}]}}}"#.to_owned(),
                r#"{"cveMetadata":{"cveId":"CVE-2099-pypi","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-01T00:00:00Z"},"containers":{"cna":{"title":"library","affected":[{"vendor":"example","product":"example","packageName":"example","collectionURL":"https://pypi.org/project/example","versions":[{"version":"0","status":"affected","versionType":"python","lessThan":"2.0.0"}]}]}}}"#.to_owned(),
                r#"{"cveMetadata":{"cveId":"CVE-2099-httplib2","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-01T00:00:00Z"},"containers":{"cna":{"title":"library","affected":[{"vendor":"httplib2","product":"httplib2","versions":[{"version":"0","status":"affected","lessThan":"2.0.0"}]}]}}}"#.to_owned(),
            ])
            .await
            .unwrap();

    assert!(
        database
            .query_package_matches("PyPI", "pendulum", "3.0.0", None)
            .await
            .unwrap()
            .is_empty()
    );
    let redis = database
        .query_package_matches("PyPI", "redis", "4.6.0", None)
        .await
        .unwrap();
    assert_eq!(redis[0].affected.status, "unknown");
    assert_eq!(redis[0].affected.confidence, "low");
    let elasticsearch = database
        .query_package_matches("PyPI", "elasticsearch", "8.15.0", None)
        .await
        .unwrap();
    assert_eq!(elasticsearch[0].affected.status, "unknown");
    assert_eq!(elasticsearch[0].affected.confidence, "low");
    let confirmed = database
        .query_package_matches("PyPI", "example", "1.0.0", None)
        .await
        .unwrap();
    assert_eq!(confirmed[0].affected.status, "affected");
    let httplib2 = database
        .query_package_matches("PyPI", "httplib2", "1.0.0", None)
        .await
        .unwrap();
    assert_eq!(httplib2[0].affected.status, "unknown");
}

#[tokio::test]
async fn cve_package_supplement_preserves_and_sorts_status_changes() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    database
            .import_cve_raw_json(
                r#"{"cveMetadata":{"cveId":"CVE-2099-changes","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-01T00:00:00Z"},"containers":{"cna":{"title":"changes","affected":[{"vendor":"example","product":"example","packageName":"example","collectionURL":"https://pypi.org/project/example","defaultStatus":"unaffected","versions":[{"version":"1.0","status":"unaffected","versionType":"python","lessThan":"4.0","changes":[{"at":"3.0","status":"unaffected"},{"at":"2.0","status":"affected"}]}]}]}}}"#
                    .to_owned(),
            )
            .await
            .unwrap();

    let affected = database
        .query_package_matches("PyPI", "example", "2.5", None)
        .await
        .unwrap();
    assert_eq!(affected.len(), 1);
    assert_eq!(affected[0].affected.status, "affected");
    assert!(
        database
            .query_package_matches("PyPI", "example", "3.5", None)
            .await
            .unwrap()
            .is_empty()
    );

    let stored: String = database
        .writer
        .with_connection(|connection| {
            Box::pin(async move {
                sqlx::query_scalar("SELECT raw_json FROM cve_affected LIMIT 1")
                    .fetch_one(connection)
                    .await
            })
        })
        .await
        .unwrap();
    let stored = cve_stored_versions(&stored).unwrap();
    assert_eq!(stored[0].changes.len(), 2);
}

#[tokio::test]
async fn cve_batch_import_is_atomic_when_a_later_record_is_invalid() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    let result = database
            .import_cve_raw_jsons(vec![
                r#"{"cveMetadata":{"cveId":"CVE-2099-batch","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-01T00:00:00Z"},"containers":{"cna":{"title":"valid"}}}"#.to_owned(),
                "{invalid JSON}".to_owned(),
            ])
            .await;
    assert!(result.is_err());
    assert!(
        database
            .find_cve_summary("CVE-2099-batch")
            .await
            .unwrap()
            .is_none()
    );
    database.close().await.unwrap();
}

#[tokio::test]
async fn cve_bulk_raw_and_identifier_upserts_cross_the_sqlite_bind_boundary() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    let records = (0..5_001)
            .map(|index| {
                format!(
                    r#"{{"cveMetadata":{{"cveId":"CVE-2099-{index:04}","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-01T00:00:00Z"}},"containers":{{"cna":{{"title":"bulk"}}}}}}"#
                )
            })
            .collect();
    assert_eq!(database.import_cve_raw_jsons(records).await.unwrap(), 5_001);
    let counts: (i64, i64) = database
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    sqlx::query_as(
                        "SELECT (SELECT COUNT(*) FROM cve), (SELECT COUNT(*) FROM vulnerability_identifiers WHERE identifier_type='cve')",
                    )
                    .fetch_one(connection)
                    .await
                })
            })
            .await
            .unwrap();
    assert_eq!(counts, (5_001, 5_001));
    database.close().await.unwrap();
}

#[tokio::test]
async fn fts_indexes_cve_description_references_and_osv_details() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    database.import_cve_raw_json(r#"{"cveMetadata":{"cveId":"CVE-2099-fts","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-01T00:00:00Z"},"containers":{"cna":{"title":"Title","descriptions":[{"lang":"en","value":"needle-description"}],"references":[{"url":"https://example.invalid/needle-reference","tags":["patch"]}]}}}"#.to_owned()).await.unwrap();
    database.import_osv_record(OsvRawRecord { source_path: None, raw_json: r#"{"schema_version":"1.8.0","id":"GHSA-2099-fts","modified":"2099-01-01T00:00:00Z","summary":"Summary","details":"needle-osv-details","aliases":["CVE-2099-fts"],"affected":[{"package":{"ecosystem":"crates.io","name":"needle-package"}}]}"#.to_owned() }).await.unwrap();
    assert_eq!(
        database
            .search_cves("needle-description", false, 10)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        database
            .search_cves("needle-reference", false, 10)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        database
            .search_cves_by_reference_text("needle-reference", false, 10, 0)
            .await
            .unwrap()
            .len(),
        1
    );
    let references = database
        .cve_detail("CVE-2099-fts")
        .await
        .unwrap()
        .unwrap()
        .references;
    assert_eq!(references.len(), 1);
    assert_eq!(
        references[0].url,
        "https://example.invalid/needle-reference"
    );
    assert_eq!(references[0].tags_json, r#"["patch"]"#);
    assert_eq!(
        database
            .search_osv("needle-osv-details", 10)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        database
            .search_osv("needle-package", 10)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn combined_search_joins_cwe_affected_and_cvss_filters_with_and() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    database
            .import_cve_raw_jsons(vec![
                r#"{"cveMetadata":{"cveId":"CVE-2099-advanced","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-02T00:00:00Z"},"containers":{"cna":{"title":"Advanced Example","affected":[{"vendor":"Acme","product":"widget"}],"metrics":[{"cvssV3_1":{"version":"3.1","baseScore":9.8,"baseSeverity":"CRITICAL"}}],"problemTypes":[{"descriptions":[{"cweId":"CWE-79"}]}]}}}"#.to_owned(),
                r#"{"cveMetadata":{"cveId":"CVE-2099-wrong-text","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-02T00:00:00Z"},"containers":{"cna":{"title":"Unrelated Example","affected":[{"vendor":"Acme","product":"widget"}],"metrics":[{"cvssV3_1":{"version":"3.1","baseScore":9.8,"baseSeverity":"CRITICAL"}}],"problemTypes":[{"descriptions":[{"cweId":"CWE-79"}]}]}}}"#.to_owned(),
                r#"{"cveMetadata":{"cveId":"CVE-2099-wrong-cwe","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-02T00:00:00Z"},"containers":{"cna":{"title":"Advanced Example","affected":[{"vendor":"Acme","product":"widget"}],"metrics":[{"cvssV3_1":{"version":"3.1","baseScore":9.8,"baseSeverity":"CRITICAL"}}],"problemTypes":[{"descriptions":[{"cweId":"CWE-89"}]}]}}}"#.to_owned(),
                r#"{"cveMetadata":{"cveId":"CVE-2099-wrong-vendor","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-02T00:00:00Z"},"containers":{"cna":{"title":"Advanced Example","affected":[{"vendor":"Other","product":"widget"}],"metrics":[{"cvssV3_1":{"version":"3.1","baseScore":9.8,"baseSeverity":"CRITICAL"}}],"problemTypes":[{"descriptions":[{"cweId":"CWE-79"}]}]}}}"#.to_owned(),
                r#"{"cveMetadata":{"cveId":"CVE-2099-wrong-product","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-02T00:00:00Z"},"containers":{"cna":{"title":"Advanced Example","affected":[{"vendor":"Acme","product":"gadget"}],"metrics":[{"cvssV3_1":{"version":"3.1","baseScore":9.8,"baseSeverity":"CRITICAL"}}],"problemTypes":[{"descriptions":[{"cweId":"CWE-79"}]}]}}}"#.to_owned(),
                r#"{"cveMetadata":{"cveId":"CVE-2099-low-score","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-02T00:00:00Z"},"containers":{"cna":{"title":"Advanced Example","affected":[{"vendor":"Acme","product":"widget"}],"metrics":[{"cvssV3_1":{"version":"3.1","baseScore":5.0,"baseSeverity":"MEDIUM"}}],"problemTypes":[{"descriptions":[{"cweId":"CWE-79"}]}]}}}"#.to_owned(),
            ])
            .await
            .unwrap();
    let filters = SqlxCveSearch {
        text: Some("advanced".to_owned()),
        cwe_ids: vec!["CWE-79".to_owned()],
        vendor_like: Some("%Acme%".to_owned()),
        product_like: Some("%widget%".to_owned()),
        cvss: SqlxCvssSearch {
            min_score: Some(9.0),
            severity: Some("critical".to_owned()),
            ..SqlxCvssSearch::default()
        },
        ..SqlxCveSearch::default()
    };
    let matches = database
        .search_cves_advanced(filters.clone(), false, 10, 0)
        .await
        .unwrap();
    assert_eq!(
        matches
            .iter()
            .map(|row| row.cve_id.as_str())
            .collect::<Vec<_>>(),
        vec!["CVE-2099-advanced"]
    );
    assert_eq!(
        database
            .count_cves_advanced_with_kev(filters, false, false)
            .await
            .unwrap(),
        1
    );

    let no_match_filters = SqlxCveSearch {
        product_exact: Some("other".to_owned()),
        ..SqlxCveSearch::default()
    };
    let no_match = database
        .search_cves_advanced(no_match_filters.clone(), false, 10, 0)
        .await
        .unwrap();
    assert!(no_match.is_empty());
    assert_eq!(
        database
            .count_cves_advanced_with_kev(no_match_filters, false, false)
            .await
            .unwrap(),
        0
    );

    let outside_range_filters = SqlxCveSearch {
        published_until: Some("2098-12-31T23:59:59Z".to_owned()),
        ..SqlxCveSearch::default()
    };
    let outside_range = database
        .search_cves_advanced(outside_range_filters.clone(), false, 10, 0)
        .await
        .unwrap();
    assert!(outside_range.is_empty());
    assert_eq!(
        database
            .count_cves_advanced_with_kev(outside_range_filters, false, false)
            .await
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn advanced_search_honors_every_cve_sort_order() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    database
            .import_cve_raw_jsons(vec![
                r#"{"cveMetadata":{"cveId":"CVE-2099-0001","state":"PUBLISHED","datePublished":"2099-02-01T00:00:00Z","dateUpdated":"2099-01-01T00:00:00Z"},"containers":{"cna":{"title":"newer published","metrics":[{"cvssV3_1":{"version":"3.1","baseScore":5.0,"baseSeverity":"MEDIUM"}}]}}}"#.to_owned(),
                r#"{"cveMetadata":{"cveId":"CVE-2099-0002","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-03-01T00:00:00Z"},"containers":{"cna":{"title":"newer updated","metrics":[{"cvssV3_1":{"version":"3.1","baseScore":9.0,"baseSeverity":"CRITICAL"}}]}}}"#.to_owned(),
            ])
            .await
            .unwrap();
    let published = database
        .search_cves_advanced(SqlxCveSearch::default(), false, 10, 0)
        .await
        .unwrap();
    assert_eq!(published[0].cve_id, "CVE-2099-0001");
    for (sort_order, expected) in [
        (CveSummarySortOrder::PublishedAsc, "CVE-2099-0002"),
        (CveSummarySortOrder::UpdatedAsc, "CVE-2099-0001"),
        (CveSummarySortOrder::UpdatedDesc, "CVE-2099-0002"),
        (CveSummarySortOrder::CveIdAsc, "CVE-2099-0001"),
        (CveSummarySortOrder::CveIdDesc, "CVE-2099-0002"),
        (CveSummarySortOrder::ScoreAsc, "CVE-2099-0001"),
        (CveSummarySortOrder::ScoreDesc, "CVE-2099-0002"),
    ] {
        let rows = database
            .search_cves_advanced(
                SqlxCveSearch {
                    sort_order,
                    ..SqlxCveSearch::default()
                },
                false,
                10,
                0,
            )
            .await
            .unwrap();
        assert_eq!(rows[0].cve_id, expected, "unexpected {sort_order:?} order");
    }

    let cve_prefix = database
        .search_cve_summaries_advanced(
            &crate::CveAdvancedSearch {
                query: Some("CVE-2099".to_owned()),
                query_mode: Some(crate::CveAdvancedQueryMode::Cve),
                sort_order: CveSummarySortOrder::PublishedDesc,
                ..Default::default()
            },
            10,
            0,
        )
        .await
        .unwrap();
    assert_eq!(cve_prefix[0].cve_id, "CVE-2099-0001");

    let ranked = database
        .cves_by_ids_sorted(
            &["CVE-2099-0002".to_owned(), "CVE-2099-0001".to_owned()],
            CveStateScope::PublishedOnly,
            CveSummarySortOrder::RelationRankAsc,
            10,
            0,
        )
        .await
        .unwrap();
    assert_eq!(ranked[0].cve_id, "CVE-2099-0002");
}

#[tokio::test]
async fn cvss_search_orders_each_cve_by_its_highest_matching_score() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    database
            .import_cve_raw_jsons(vec![
                r#"{"cveMetadata":{"cveId":"CVE-2099-1001","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-01T00:00:00Z"},"containers":{"cna":{"title":"multiple CVSS metrics","metrics":[{"cvssV3_1":{"version":"3.1","baseScore":2.0,"baseSeverity":"LOW"}},{"cvssV3_1":{"version":"3.1","baseScore":9.8,"baseSeverity":"CRITICAL"}}]}}}"#.to_owned(),
                r#"{"cveMetadata":{"cveId":"CVE-2099-1002","state":"PUBLISHED","datePublished":"2099-02-01T00:00:00Z","dateUpdated":"2099-02-01T00:00:00Z"},"containers":{"cna":{"title":"single CVSS metric","metrics":[{"cvssV3_1":{"version":"3.1","baseScore":8.0,"baseSeverity":"HIGH"}}]}}}"#.to_owned(),
            ])
            .await
            .unwrap();

    let rows = database
        .search_cve_summaries_by_cvss_with_state_scope(
            None,
            None,
            None,
            None,
            CveStateScope::PublishedOnly,
            10,
            0,
        )
        .await
        .unwrap();
    assert_eq!(
        rows.iter()
            .map(|row| row.cve_id.as_str())
            .collect::<Vec<_>>(),
        vec!["CVE-2099-1001", "CVE-2099-1002"]
    );
}

#[tokio::test]
async fn product_cvss_search_uses_score_order_instead_of_publication_order() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    database
            .import_cve_raw_jsons(vec![
                r#"{"cveMetadata":{"cveId":"CVE-2099-2001","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-01T00:00:00Z"},"containers":{"cna":{"title":"older critical issue","affected":[{"vendor":"Acme","product":"widget"}],"metrics":[{"cvssV3_1":{"version":"3.1","baseScore":9.8,"baseSeverity":"CRITICAL"}}]}}}"#.to_owned(),
                r#"{"cveMetadata":{"cveId":"CVE-2099-2002","state":"PUBLISHED","datePublished":"2099-02-01T00:00:00Z","dateUpdated":"2099-02-01T00:00:00Z"},"containers":{"cna":{"title":"newer medium issue","affected":[{"vendor":"Acme","product":"widget"}],"metrics":[{"cvssV3_1":{"version":"3.1","baseScore":5.0,"baseSeverity":"MEDIUM"}}]}}}"#.to_owned(),
            ])
            .await
            .unwrap();

    let rows = database
        .search_cve_summaries_by_product_cvss_exact_with_state_scope(
            None,
            None,
            Some("Acme"),
            Some("widget"),
            None,
            None,
            None,
            None,
            CveStateScope::PublishedOnly,
            10,
            0,
        )
        .await
        .unwrap();
    assert_eq!(
        rows.iter()
            .map(|row| row.cve_id.as_str())
            .collect::<Vec<_>>(),
        vec!["CVE-2099-2001", "CVE-2099-2002"]
    );
}

#[tokio::test]
async fn osv_publication_sort_keeps_missing_dates_last_in_both_directions() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    database
            .import_osv_records(vec![
                OsvRawRecord {
                    source_path: None,
                    raw_json: r#"{"schema_version":"1.7.5","id":"GHSA-SORT-0001","modified":"2099-01-03T00:00:00Z","published":"2099-01-01T00:00:00Z","summary":"publication sorting fixture older","affected":[],"references":[]}"#.to_owned(),
                },
                OsvRawRecord {
                    source_path: None,
                    raw_json: r#"{"schema_version":"1.7.5","id":"GHSA-SORT-0002","modified":"2099-01-01T00:00:00Z","published":"2099-01-02T00:00:00Z","summary":"publication sorting fixture newer","affected":[],"references":[]}"#.to_owned(),
                },
                OsvRawRecord {
                    source_path: None,
                    raw_json: r#"{"schema_version":"1.7.5","id":"GHSA-SORT-0003","modified":"2099-01-02T00:00:00Z","summary":"publication sorting fixture undated","affected":[],"references":[]}"#.to_owned(),
                },
            ])
            .await
            .unwrap();

    for (sort_order, expected) in [
        (
            CveSummarySortOrder::PublishedAsc,
            vec!["GHSA-SORT-0001", "GHSA-SORT-0002", "GHSA-SORT-0003"],
        ),
        (
            CveSummarySortOrder::PublishedDesc,
            vec!["GHSA-SORT-0002", "GHSA-SORT-0001", "GHSA-SORT-0003"],
        ),
    ] {
        let rows = database
            .search_osv_summaries_free_text_sorted("publication sorting", sort_order, 10, 0)
            .await
            .unwrap();
        assert_eq!(
            rows.iter()
                .map(|row| row.osv_id.as_str())
                .collect::<Vec<_>>(),
            expected,
            "unexpected {sort_order:?} order"
        );
    }

    let ids = vec![
        "GHSA-SORT-0003".to_owned(),
        "GHSA-SORT-0001".to_owned(),
        "GHSA-SORT-0002".to_owned(),
    ];
    for (sort_order, expected) in [
        (
            CveSummarySortOrder::UpdatedAsc,
            vec!["GHSA-SORT-0002", "GHSA-SORT-0003", "GHSA-SORT-0001"],
        ),
        (
            CveSummarySortOrder::UpdatedDesc,
            vec!["GHSA-SORT-0001", "GHSA-SORT-0003", "GHSA-SORT-0002"],
        ),
        (
            CveSummarySortOrder::CveIdAsc,
            vec!["GHSA-SORT-0001", "GHSA-SORT-0002", "GHSA-SORT-0003"],
        ),
        (
            CveSummarySortOrder::CveIdDesc,
            vec!["GHSA-SORT-0003", "GHSA-SORT-0002", "GHSA-SORT-0001"],
        ),
    ] {
        let rows = database
            .osv_summaries_by_ids_sorted(&ids, sort_order, 10, 0)
            .await
            .unwrap();
        assert_eq!(
            rows.iter()
                .map(|row| row.osv_id.as_str())
                .collect::<Vec<_>>(),
            expected,
            "unexpected explicit OSV ID {sort_order:?} order"
        );
    }
}

#[tokio::test]
async fn published_sort_has_stable_non_overlapping_pages_for_ties() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    for id in ["CVE-2099-3001", "CVE-2099-3002", "CVE-2099-3003"] {
        database
                .import_cve_raw_json(format!(
                    r#"{{"cveMetadata":{{"cveId":"{id}","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-01T00:00:00Z"}},"containers":{{"cna":{{"title":"stable pagination fixture"}}}}}}"#
                ))
                .await
                .unwrap();
    }

    let mut ids = Vec::new();
    for offset in 0..3 {
        let rows = database
            .search_cve_summaries_advanced(&crate::CveAdvancedSearch::default(), 1, offset)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        ids.push(rows[0].cve_id.clone());
    }
    assert_eq!(ids, vec!["CVE-2099-3003", "CVE-2099-3002", "CVE-2099-3001"]);
}

#[tokio::test]
async fn kev_filter_is_applied_before_search_pagination() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    database.import_cve_raw_json(r#"{"cveMetadata":{"cveId":"CVE-2099-0001","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-02T00:00:00Z"},"containers":{"cna":{"title":"Windows KEV vulnerability"}}}"#.to_owned()).await.unwrap();
    database.import_cve_raw_json(r#"{"cveMetadata":{"cveId":"CVE-2099-0002","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-03T00:00:00Z"},"containers":{"cna":{"title":"Windows non-KEV vulnerability"}}}"#.to_owned()).await.unwrap();
    database
        .import_kev_json(include_str!("../../../../fixtures/kev/kev-test.json").to_owned())
        .await
        .unwrap();

    let options = crate::CveAdvancedSearch {
        query: Some("windows".to_owned()),
        query_mode: Some(crate::CveAdvancedQueryMode::FreeText),
        kev_only: true,
        ..Default::default()
    };
    let rows = database
        .search_cve_summaries_advanced(&options, 1, 0)
        .await
        .unwrap();
    assert_eq!(
        rows.iter()
            .map(|row| row.cve_id.as_str())
            .collect::<Vec<_>>(),
        vec!["CVE-2099-0001"]
    );
    assert_eq!(
        database
            .count_cve_summaries_advanced(&options)
            .await
            .unwrap(),
        1
    );
}

#[tokio::test]
async fn imports_epss_for_existing_cves_with_checked_scores() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    database.import_cve_raw_json(r#"{"cveMetadata":{"cveId":"CVE-2099-0001","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-01T00:00:00Z"},"containers":{"cna":{"title":"Example CVE"}}}"#.to_owned()).await.unwrap();
    database
        .import_epss_csv(include_str!("../../../../fixtures/epss/epss-test.csv").to_owned())
        .await
        .unwrap();
    let (_, changed) = database
        .import_epss_csv_with_status(
            include_str!("../../../../fixtures/epss/epss-test.csv").to_owned(),
            false,
        )
        .await
        .unwrap();
    assert!(!changed);
    let count: i64 = database
        .writer
        .with_connection(|connection| {
            Box::pin(async move {
                sqlx::query_scalar("SELECT COUNT(*) FROM epss_current")
                    .fetch_one(connection)
                    .await
            })
        })
        .await
        .unwrap();
    assert_eq!(count, 1);
    let risks = database
        .search_epss_risk(Some(0.1), Some(0.1), false, 10, 0)
        .await
        .unwrap();
    assert_eq!(risks.len(), 1);
    assert_eq!(risks[0].cve_id, "CVE-2099-0001");
    assert!(!risks[0].kev_listed);
}

#[tokio::test]
async fn epss_snapshot_is_deduplicated_replaced_and_atomic() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    for id in ["CVE-2099-0001", "CVE-2099-0002"] {
        database.import_cve_raw_json(format!(r#"{{"cveMetadata":{{"cveId":"{id}","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-01T00:00:00Z"}},"containers":{{"cna":{{"title":"EPSS fixture"}}}}}}"#)).await.unwrap();
    }
    database.import_epss_csv("#model_version:v1,score_date:2099-01-01\ncve,epss,percentile\nCVE-2099-0001,0.1,0.2\nCVE-2099-0002,0.3,0.4\nCVE-2099-missing,0.5,0.6\nCVE-2099-0001,0.7,0.8\n".to_owned()).await.unwrap();
    let first: Vec<(String, f64)> = database
        .writer
        .with_connection(|connection| {
            Box::pin(async move {
                sqlx::query_as("SELECT cve_id, epss FROM epss_current ORDER BY cve_id")
                    .fetch_all(connection)
                    .await
            })
        })
        .await
        .unwrap();
    assert_eq!(
        first,
        vec![
            ("CVE-2099-0001".to_owned(), 0.7),
            ("CVE-2099-0002".to_owned(), 0.3)
        ]
    );

    database.import_epss_csv("#model_version:v2,score_date:2099-01-02\ncve,epss,percentile\nCVE-2099-0002,0.9,0.95\n".to_owned()).await.unwrap();
    let replaced: Vec<(String, f64)> = database
        .writer
        .with_connection(|connection| {
            Box::pin(async move {
                sqlx::query_as("SELECT cve_id, epss FROM epss_current ORDER BY cve_id")
                    .fetch_all(connection)
                    .await
            })
        })
        .await
        .unwrap();
    assert_eq!(replaced, vec![("CVE-2099-0002".to_owned(), 0.9)]);

    let failing_csv =
        "#model_version:v3,score_date:2099-01-04\ncve,epss,percentile\nCVE-2099-0001,0.2,0.3\n"
            .to_owned();
    let conflicting_hash = Md5::digest(failing_csv.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    database.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query("INSERT INTO epss_raw_records(score_date,fetched_at,content_hash,raw_csv) VALUES ('2099-01-03','2099-01-03T00:00:00Z',?,'conflict')")
                .bind(conflicting_hash).execute(connection).await.map(|_| ())
        })).await.unwrap();
    assert!(database.import_epss_csv(failing_csv).await.is_err());
    let after_error: Vec<(String, f64)> = database
        .writer
        .with_connection(|connection| {
            Box::pin(async move {
                sqlx::query_as("SELECT cve_id, epss FROM epss_current ORDER BY cve_id")
                    .fetch_all(connection)
                    .await
            })
        })
        .await
        .unwrap();
    assert_eq!(after_error, replaced);
}

/// Reproducible local micro-benchmark for a realistic EPSS current snapshot.
/// Run with: cargo test -p qanvuli-db benchmark_epss_snapshot -- --ignored --nocapture
#[tokio::test]
#[ignore = "performance benchmark"]
async fn benchmark_epss_snapshot() {
    const ROWS: usize = 50_000;
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    database
            .writer
            .with_connection(|connection| {
                Box::pin(async move {
                    let mut transaction = connection.begin().await?;
                    for start in (0..ROWS).step_by(100) {
                        let mut query = QueryBuilder::<Sqlite>::new(
                    "INSERT INTO cve(cve_id,state,published_at,updated_at,title,serial,reference_text,raw_json) ",
                        );
                        query.push_values(start..(start + 100).min(ROWS), |mut row, index| {
                            row.push_bind(format!("CVE-2099-{index:05}"))
                                .push_bind(0_i64)
                                .push_bind("2099-01-01T00:00:00Z")
                                .push_bind("2099-01-01T00:00:00Z")
                        .push_bind("")
                        .push_bind(i64::try_from(index).unwrap())
                        .push_bind("")
                        .push_bind("{}");
                        });
                        query.build().execute(&mut *transaction).await?;
                    }
                    transaction.commit().await
                })
            })
            .await
            .unwrap();
    let mut csv =
        String::from("#model_version:v2099.01.01,score_date:2099-01-01\ncve,epss,percentile\n");
    for index in 0..ROWS {
        use std::fmt::Write as _;
        writeln!(&mut csv, "CVE-2099-{index:05},0.123,0.456").unwrap();
    }
    let started = std::time::Instant::now();
    let imported = database.import_epss_csv(csv).await.unwrap();
    eprintln!("EPSS: records={imported} elapsed={:?}", started.elapsed());
}

#[tokio::test]
async fn full_detail_includes_epss_kev_and_related_osv() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    database.import_cve_raw_json(r#"{"cveMetadata":{"cveId":"CVE-2099-0001","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-01T00:00:00Z"},"containers":{"cna":{"title":"Enriched fixture"}}}"#.to_owned()).await.unwrap();
    database.import_osv_record(OsvRawRecord {
            source_path: None,
            raw_json: r#"{"schema_version":"1.8.0","id":"GHSA-2099-enriched","modified":"2099-01-01T00:00:00Z","aliases":["CVE-2099-0001"]}"#.to_owned(),
        }).await.unwrap();
    database
        .import_epss_csv(include_str!("../../../../fixtures/epss/epss-test.csv").to_owned())
        .await
        .unwrap();
    database
        .import_kev_json(include_str!("../../../../fixtures/kev/kev-test.json").to_owned())
        .await
        .unwrap();
    let detail = database.cve_detail("CVE-2099-0001").await.unwrap().unwrap();
    assert!(detail.epss.is_some());
    assert!(detail.kev.is_some());
    assert_eq!(
        detail
            .osv_advisories
            .iter()
            .map(|advisory| advisory.osv_id.as_str())
            .collect::<Vec<_>>(),
        vec!["GHSA-2099-enriched"]
    );
}

#[tokio::test]
async fn package_query_requires_a_verified_range_for_confirmed_status() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    database
            .import_osv_record(OsvRawRecord {
                source_path: None,
                raw_json: r#"{"schema_version":"1.8.0","id":"GHSA-2099-package","modified":"2099-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"crates.io","name":"example"},"versions":["3.0.0"],"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"2.0.0"}]}]}]}"#.to_owned(),
            })
            .await
            .unwrap();
    assert_eq!(
        database
            .query_osv_package("crates.io", "example", "1.5.0")
            .await
            .unwrap()[0]
            .status,
        "affected"
    );
    assert_eq!(
        database
            .query_osv_package("crates.io", "example", "2.0.0")
            .await
            .unwrap()[0]
            .status,
        "not_affected"
    );
    assert_eq!(
        database
            .query_osv_package("crates.io", "example", "3.0.0")
            .await
            .unwrap()[0]
            .status,
        "affected"
    );
    assert!(
        database
            .query_osv_package("npm", "example", "1.5.0")
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn package_query_evaluates_npm_and_pypi_ranges_and_normalizes_names() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    database
            .import_osv_record(OsvRawRecord {
                source_path: None,
                raw_json: r#"{"schema_version":"1.8.0","id":"GHSA-2099-npm","modified":"2099-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"jquery"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]}]}"#.to_owned(),
            })
            .await
            .unwrap();
    database
            .import_osv_record(OsvRawRecord {
                source_path: None,
                raw_json: r#"{"schema_version":"1.8.0","id":"PYSEC-2099-name","modified":"2099-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"PyPI","name":"pillow-heif"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.0.post1"}]}]}]}"#.to_owned(),
            })
            .await
            .unwrap();
    database
            .import_osv_record(OsvRawRecord {
                source_path: None,
                raw_json: r#"{"schema_version":"1.8.0","id":"GHSA-2099-name-separator","modified":"2099-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"node-forge"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.0.0"}]}]}]}"#.to_owned(),
            })
            .await
            .unwrap();
    database
            .import_osv_record(OsvRawRecord {
                source_path: None,
                raw_json: r#"{"schema_version":"1.8.0","id":"PYSEC-2099-explicit","modified":"2099-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"PyPI","name":"friendly-._-._-._-bard"},"versions":["1.0.0"]}]}"#.to_owned(),
            })
            .await
            .unwrap();

    let npm = database
        .query_package_matches("npm", "jquery", "1.10.2", None)
        .await
        .unwrap();
    assert_eq!(npm.len(), 1);
    assert_eq!(npm[0].affected.status, "affected");

    let pypi = database
        .query_package_matches("PyPI", "pillow_heif", "1.0", None)
        .await
        .unwrap();
    assert_eq!(pypi.len(), 1);
    assert_eq!(pypi[0].affected.status, "affected");
    assert!(
        database
            .has_osv_package_advisory("PyPI", "pillow_heif", None)
            .await
            .unwrap()
    );

    assert!(
        database
            .query_package_matches("npm", "node_forge", "0.9.0", None)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        database
            .query_package_matches("npm", "node-forge", "0.9.0", None)
            .await
            .unwrap()
            .len(),
        1
    );

    let explicit_pypi = database
        .query_package_matches("PyPI", "Friendly-._-Bard", "1.0", None)
        .await
        .unwrap();
    assert_eq!(explicit_pypi.len(), 1);
    assert_eq!(explicit_pypi[0].affected.status, "affected");
    assert!(
        database
            .query_package_matches("PyPI", "friendly-bard", "2.0", None)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        database
            .query_osv_package("PyPI", "friendly-bard", "2.0")
            .await
            .unwrap()[0]
            .status,
        "not_affected"
    );
}

#[tokio::test]
async fn package_query_accepts_purl_without_confirming_an_unverified_name_match() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    database
            .import_osv_record(OsvRawRecord {
                source_path: None,
                raw_json: r#"{"schema_version":"1.8.0","id":"GHSA-2099-purl","modified":"2099-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"crates.io","name":"different-name","purl":"pkg:cargo/example"}}]}"#.to_owned(),
            })
            .await
            .unwrap();
    let findings = database
        .query_osv_package_with_purl(
            "crates.io",
            "example",
            "1.5.0",
            Some("pkg:cargo/example@1.5.0"),
        )
        .await
        .unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].status, "unknown");
    assert_eq!(findings[0].confidence, "low");
}

#[tokio::test]
async fn package_query_rejects_conflicting_name_and_purl_identity() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();

    let error = database
        .query_osv_package_with_purl(
            "crates.io",
            "safe-package",
            "1.0.0",
            Some("pkg:cargo/vulnerable-package@1.0.0"),
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("conflicts with purl"));

    let error = database
        .query_package_matches_batch(&[PackageQuery {
            ecosystem: "npm".to_owned(),
            package: "safe-package".to_owned(),
            version: "1.0.0".to_owned(),
            purl: Some("pkg:pypi/safe-package@1.0.0".to_owned()),
        }])
        .await
        .unwrap_err();
    assert!(error.to_string().contains("conflicts with purl"));
}

#[tokio::test]
async fn purl_qualifiers_disambiguate_same_named_package_variants() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    for (id, platform) in [("ruby", "ruby"), ("java", "java")] {
        database
                .import_osv_record(OsvRawRecord {
                    source_path: None,
                    raw_json: format!(
                        r#"{{"schema_version":"1.8.0","id":"GHSA-2099-{id}-variant","modified":"2099-01-01T00:00:00Z","affected":[{{"package":{{"ecosystem":"RubyGems","name":"example","purl":"pkg:gem/example?platform={platform}"}},"versions":["1.0.0"]}}]}}"#
                    ),
                })
                .await
                .unwrap();
    }

    let ruby = database
        .query_package_matches(
            "RubyGems",
            "example",
            "1.0",
            Some("pkg:gem/example@1.0?platform=ruby"),
        )
        .await
        .unwrap();
    assert_eq!(ruby.len(), 1);
    assert_eq!(ruby[0].primary_id, "GHSA-2099-ruby-variant");

    let all = database
        .query_package_matches("RubyGems", "example", "1.0", None)
        .await
        .unwrap();
    assert_eq!(all.len(), 2);
}

#[tokio::test]
async fn unqualified_advisory_purl_applies_to_a_qualified_package_variant() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    database
            .import_osv_record(OsvRawRecord {
                source_path: None,
                raw_json: r#"{"schema_version":"1.8.0","id":"GHSA-2099-generic-variant","modified":"2099-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"RubyGems","name":"example","purl":"pkg:gem/example"},"versions":["1.0.0"]}]}"#.to_owned(),
            })
            .await
            .unwrap();

    let qualified = PackageQuery {
        ecosystem: "RubyGems".to_owned(),
        package: "example".to_owned(),
        version: "1.0".to_owned(),
        purl: Some("pkg:gem/example@1.0?platform=ruby".to_owned()),
    };
    let findings = database
        .query_package_matches_batch(std::slice::from_ref(&qualified))
        .await
        .unwrap();
    assert_eq!(findings[0].len(), 1);
    assert_eq!(findings[0][0].primary_id, "GHSA-2099-generic-variant");
    assert_eq!(
        database
            .has_osv_package_advisories_batch(std::slice::from_ref(&qualified))
            .await
            .unwrap(),
        vec![true]
    );
    assert!(
        database
            .has_osv_package_advisory(
                "RubyGems",
                "example",
                Some("pkg:gem/example@1.0?platform=ruby"),
            )
            .await
            .unwrap()
    );
    assert_eq!(
        database
            .query_osv_package_with_purl(
                "RubyGems",
                "example",
                "1.0",
                Some("pkg:gem/example@1.0?platform=ruby"),
            )
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn canonical_purl_spelling_matches_and_invalid_feed_purl_falls_back_to_name() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    database
            .import_osv_record(OsvRawRecord {
                source_path: None,
                raw_json: r#"{"schema_version":"1.8.0","id":"GHSA-2099-canonical-purl","modified":"2099-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"NuGet","name":"Example.Core","purl":"pkg:NuGet/Example.Core"},"versions":["1.0.0"]}]}"#.to_owned(),
            })
            .await
            .unwrap();
    database
            .import_osv_record(OsvRawRecord {
                source_path: None,
                raw_json: r#"{"schema_version":"1.8.0","id":"GHSA-2099-invalid-purl","modified":"2099-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"npm","name":"example","purl":"pkg:npm/ex%ZZample"},"versions":["1.0.0"]}]}"#.to_owned(),
            })
            .await
            .unwrap();

    let canonical = database
        .query_package_matches(
            "nuget",
            "example.core",
            "1",
            Some("PKG://NUGET/example.core@1.0.0"),
        )
        .await
        .unwrap();
    assert_eq!(canonical.len(), 1);
    assert_eq!(canonical[0].primary_id, "GHSA-2099-canonical-purl");

    let invalid_fallback = database
        .query_package_matches("npm", "example", "1.0.0", Some("pkg:npm/example@1.0.0"))
        .await
        .unwrap();
    assert_eq!(invalid_fallback.len(), 1);
    assert_eq!(invalid_fallback[0].primary_id, "GHSA-2099-invalid-purl");
}

#[tokio::test]
async fn package_query_normalizes_github_actions_and_pub_names() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    for (id, ecosystem, name) in [
        ("github", "GitHub Actions", "Owner/Repository"),
        ("pub", "Pub", "Friendly-Package"),
    ] {
        database
                .import_osv_record(OsvRawRecord {
                    source_path: None,
                    raw_json: format!(
                        r#"{{"schema_version":"1.8.0","id":"GHSA-2099-{id}-name","modified":"2099-01-01T00:00:00Z","affected":[{{"package":{{"ecosystem":"{ecosystem}","name":"{name}"}},"versions":["1.0.0"]}}]}}"#
                    ),
                })
                .await
                .unwrap();
    }

    assert_eq!(
        database
            .query_package_matches("GitHub Actions", "owner/repository", "1.0.0", None)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        database
            .query_package_matches("Pub", "friendly_package", "1.0.0", None)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn exact_package_search_uses_each_ecosystems_name_rules() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    for (id, ecosystem, name) in [
        ("npm-case", "npm", "CaseSensitive"),
        ("pypi-name", "PyPI", "friendly-bard"),
        ("pub-name", "Pub", "friendly_package"),
    ] {
        database
                .import_osv_record(OsvRawRecord {
                    source_path: None,
                    raw_json: format!(
                        r#"{{"schema_version":"1.8.0","id":"GHSA-2099-{id}","modified":"2099-01-01T00:00:00Z","affected":[{{"package":{{"ecosystem":"{ecosystem}","name":"{name}"}},"versions":["1.0.0"]}}]}}"#
                    ),
                })
                .await
                .unwrap();
    }

    assert!(
        database
            .search_osv_summaries_by_package("casesensitive", 10, 0)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        database
            .search_osv_summaries_by_package("CaseSensitive", 10, 0)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        database
            .search_osv_summaries_by_package("Friendly_Bard", 10, 0)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        database
            .search_osv_summaries_by_package("friendly-package", 10, 0)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        database
            .count_osv_summaries_by_package("Friendly.Bard")
            .await
            .unwrap(),
        1
    );
}

#[tokio::test]
async fn maven_repository_identity_normalizes_central_and_preserves_path_case() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    database
            .import_osv_record(OsvRawRecord {
                source_path: None,
                raw_json: r#"{"schema_version":"1.8.0","id":"GHSA-2099-custom-repository","modified":"2099-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"Maven","name":"org.example:custom","purl":"pkg:maven/org.example/custom?repository_url=https%3A%2F%2FRepo.Example%2FCasePath%2F"},"versions":["1.0.0"]}]}"#.to_owned(),
            })
            .await
            .unwrap();
    database
            .import_osv_record(OsvRawRecord {
                source_path: None,
                raw_json: r#"{"schema_version":"1.8.0","id":"GHSA-2099-central-repository","modified":"2099-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"Maven:https://repo.maven.apache.org/maven2/","name":"org.example:central","purl":"pkg:maven/org.example/central?repository_url=https%3A%2F%2Frepo.maven.apache.org%2Fmaven2%2F"},"versions":["1.0.0"]}]}"#.to_owned(),
            })
            .await
            .unwrap();

    assert_eq!(
        database
            .query_package_matches(
                "Maven:https://repo.example/CasePath",
                "org.example:custom",
                "1.0.0",
                None,
            )
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(
        database
            .query_package_matches(
                "Maven:https://repo.example/casepath",
                "org.example:custom",
                "1.0.0",
                None,
            )
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        database
            .query_package_matches("Maven", "org.example:custom", "1.0.0", None)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
            database
                .query_package_matches(
                    "Maven:https://repo.maven.apache.org/maven2/",
                    "org.example:central",
                    "1.0.0",
                    Some(
                        "PKG://MAVEN/org.example/central@1.0.0?repository_url=https%3A%2F%2Frepo.maven.apache.org%2Fmaven2%2F",
                    ),
                )
                .await
                .unwrap()
                .len(),
            1
        );
}

#[tokio::test]
async fn duplicate_affected_entries_are_consolidated_per_advisory() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    database
            .import_osv_record(OsvRawRecord {
                source_path: None,
                raw_json: r#"{"schema_version":"1.8.0","id":"GHSA-2099-split-ranges","modified":"2099-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"crates.io","name":"example"},"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"2.0.0"}]}]},{"package":{"ecosystem":"crates.io","name":"example"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"3.0-final"}]}]}]}"#.to_owned(),
            })
            .await
            .unwrap();

    let affected = database
        .query_package_matches("crates.io", "example", "1.5.0", None)
        .await
        .unwrap();
    assert_eq!(affected.len(), 1);
    assert_eq!(affected[0].affected.status, "affected");

    let review = database
        .query_package_matches("crates.io", "example", "3.0.0", None)
        .await
        .unwrap();
    assert_eq!(review.len(), 1);
    assert_eq!(review[0].affected.status, "unknown");
}

#[tokio::test]
async fn package_matching_preserves_order_across_query_batch_boundaries() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    database
            .import_osv_record(OsvRawRecord {
                source_path: None,
                raw_json: r#"{"schema_version":"1.8.0","id":"GHSA-2099-batched-package","modified":"2099-01-01T00:00:00Z","aliases":["CVE-2099-9999"],"affected":[{"package":{"ecosystem":"crates.io","name":"example"},"versions":["1.0.0"],"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]}]}"#.to_owned(),
            })
            .await
            .unwrap();
    let queries = (0..=PACKAGE_QUERY_BATCH_SIZE)
        .map(|_| PackageQuery {
            ecosystem: "crates.io".to_owned(),
            package: "example".to_owned(),
            version: "1.0.0".to_owned(),
            purl: None,
        })
        .collect::<Vec<_>>();
    let findings = database
        .query_package_matches_batch(&queries)
        .await
        .unwrap();
    let coverage = database
        .has_osv_package_advisories_batch(&queries)
        .await
        .unwrap();
    assert_eq!(findings.len(), PACKAGE_QUERY_BATCH_SIZE + 1);
    assert_eq!(coverage, vec![true; PACKAGE_QUERY_BATCH_SIZE + 1]);
    assert!(findings.iter().all(|rows| {
        rows.len() == 1
            && rows[0].primary_id == "GHSA-2099-batched-package"
            && rows[0].cve_ids == ["CVE-2099-9999"]
            && rows[0].fixed_versions == ["2.0.0"]
    }));
}

#[tokio::test]
async fn osv_date_batch_preserves_order_across_id_batch_boundaries() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    let ids = (0..=OSV_DATE_BATCH_SIZE)
        .map(|index| format!("OSV-MISSING-{index}"))
        .collect::<Vec<_>>();
    let dates = database.osv_advisory_dates_batch(&ids).await.unwrap();
    assert_eq!(dates.len(), OSV_DATE_BATCH_SIZE + 1);
    assert!(dates.iter().all(Option::is_none));
}

#[tokio::test]
async fn cve_detail_batch_preserves_order_across_id_batch_boundaries() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    let ids = (0..=2_000)
        .map(|index| format!("CVE-2099-{index:04}"))
        .collect::<Vec<_>>();
    let details = database
        .cve_summaries_with_details_batch(&ids, CveStateScope::PublishedOnly)
        .await
        .unwrap();
    assert_eq!(details.len(), 2_001);
    assert!(details.iter().all(Option::is_none));
}

#[tokio::test]
async fn imports_kev_through_integer_cve_foreign_keys_idempotently() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    database.import_cve_raw_json(r#"{"cveMetadata":{"cveId":"CVE-2099-0001","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-01T00:00:00Z"},"containers":{"cna":{"title":"Example CVE"}}}"#.to_owned()).await.unwrap();
    let fixture = include_str!("../../../../fixtures/kev/kev-test.json").to_owned();
    assert_eq!(database.import_kev_json(fixture.clone()).await.unwrap(), 1);
    assert_eq!(
        database
            .import_kev_json_with_status(fixture, false)
            .await
            .unwrap(),
        (1, false)
    );
    let row: (String, String) = database.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query_as("SELECT kev_entries.cve_id, cve.cve_id FROM kev_entries JOIN cve ON cve.cve_id = kev_entries.cve_id")
                .fetch_one(connection).await
        })).await.unwrap();
    assert_eq!(
        row,
        ("CVE-2099-0001".to_owned(), "CVE-2099-0001".to_owned())
    );
    assert_eq!(
        database
            .kev_entries(Some("CVE-2099-0001"), 10, 0)
            .await
            .unwrap()
            .into_iter()
            .map(|entry| entry.cve_id)
            .collect::<Vec<_>>(),
        vec!["CVE-2099-0001"]
    );
}

#[tokio::test]
async fn osv_cursor_advances_only_after_a_complete_retryable_sync() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    assert_eq!(database.begin_osv_sync().await.unwrap(), None);
    let valid = OsvRawRecord {
        source_path: None,
        raw_json:
            r#"{"schema_version":"1.8.0","id":"GHSA-2099-retry","modified":"2099-01-01T00:00:00Z"}"#
                .to_owned(),
    };
    let invalid = OsvRawRecord {
        source_path: None,
        raw_json: r#"{"schema_version":"1.7.3","id":"GHSA-2099-invalid"}"#.to_owned(),
    };
    assert!(
        database
            .import_osv_records(vec![valid.clone(), invalid])
            .await
            .is_err()
    );
    let imported_after_failed_batch: i64 = database
        .writer
        .with_connection(|connection| {
            Box::pin(async move {
                sqlx::query_scalar("SELECT COUNT(*) FROM osv_advisories")
                    .fetch_one(connection)
                    .await
            })
        })
        .await
        .unwrap();
    assert_eq!(imported_after_failed_batch, 0);
    database.fail_osv_sync("later batch failed").await.unwrap();
    let failed: (String, Option<String>) = database
        .writer
        .with_connection(|connection| {
            Box::pin(async move {
                sqlx::query_as(
                    "SELECT status, last_cursor FROM source_sync_state WHERE source='OSV'",
                )
                .fetch_one(connection)
                .await
            })
        })
        .await
        .unwrap();
    assert_eq!(failed, ("failed".to_owned(), None));
    assert_eq!(database.begin_osv_sync().await.unwrap(), None);
    database.import_osv_records(vec![valid]).await.unwrap();
    database.rebuild_search().await.unwrap();
    database.check().await.unwrap();
    database
        .complete_osv_sync("2099-01-02T00:00:00Z")
        .await
        .unwrap();
    let sync_state = database.source_sync_states().await.unwrap().pop().unwrap();
    let attempted_at = sync_state.last_attempt_at.as_deref().unwrap();
    let succeeded_at = sync_state.last_success_at.as_deref().unwrap();
    assert!(chrono::DateTime::parse_from_rfc3339(attempted_at).is_ok());
    assert!(chrono::DateTime::parse_from_rfc3339(succeeded_at).is_ok());
    assert!(succeeded_at >= attempted_at);
    let completed: (String, String, i64) = database.writer.with_connection(|connection| Box::pin(async move {
            sqlx::query_as("SELECT status, last_cursor, (SELECT COUNT(*) FROM osv_advisories) FROM source_sync_state WHERE source='OSV'").fetch_one(connection).await
        })).await.unwrap();
    assert_eq!(
        completed,
        ("success".to_owned(), "2099-01-02T00:00:00Z".to_owned(), 1)
    );
}

#[tokio::test]
async fn ssvc_is_extracted_from_cve_adp_updated_and_searchable() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    assert_eq!(
        database
            .import_cve_raw_jsons(vec![
                r#"{"cveMetadata":{"cveId":"CVE-2099-0001","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-03T00:00:00Z"},"containers":{"cna":{"title":"CVE-2099-0001"},"adp":[{"providerMetadata":{"shortName":"CISA-ADP"},"metrics":[{"other":{"type":"ssvc","content":{"id":"CVE-2099-0001","role":"CISA Coordinator","version":"2.0.3","timestamp":"2099-01-03T00:00:00Z","options":[{"Exploitation":"active"},{"Automatable":"yes"},{"Technical Impact":"total"}]}}}]}]}}"#.to_owned(),
                r#"{"cveMetadata":{"cveId":"CVE-2099-0002","state":"PUBLISHED","datePublished":"2099-01-02T00:00:00Z","dateUpdated":"2099-01-02T00:00:00Z"},"containers":{"cna":{"title":"CVE-2099-0002"}}}"#.to_owned(),
            ])
            .await
            .unwrap(),
        2
    );

    let stored = database.ssvc_assessments("CVE-2099-0001").await.unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(
        stored[0].exploitation,
        Some(crate::SsvcExploitation::Active)
    );
    assert_eq!(
        database
            .cve_detail("CVE-2099-0001")
            .await
            .unwrap()
            .unwrap()
            .ssvc,
        stored
    );

    let filters = SqlxCveSearch {
        ssvc: crate::SsvcSearch {
            exploitation: Some(crate::SsvcExploitation::Active),
            automatable: Some(crate::SsvcAutomatable::Yes),
            technical_impact: Some(crate::SsvcTechnicalImpact::Total),
        },
        ..Default::default()
    };
    let rows = database
        .search_cves_advanced(filters.clone(), false, 25, 0)
        .await
        .unwrap();
    assert_eq!(
        rows.iter()
            .map(|row| row.cve_id.as_str())
            .collect::<Vec<_>>(),
        ["CVE-2099-0001"]
    );
    assert_eq!(
        database
            .count_cves_advanced_with_kev(filters, false, false)
            .await
            .unwrap(),
        1
    );

    database
        .import_cve_raw_json(
            r#"{"cveMetadata":{"cveId":"CVE-2099-0001","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-04T00:00:00Z"},"containers":{"cna":{"title":"updated without SSVC"}}}"#.to_owned(),
        )
        .await
        .unwrap();
    assert_eq!(database.ssvc_assessment_count().await.unwrap(), 0);
}

#[tokio::test]
async fn bulk_cve_initialization_extracts_ssvc_without_a_separate_feed() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    database.prepare_cve_bulk_load().await.unwrap();
    assert_eq!(
        database
            .import_cve_raw_jsons_bulk_init(vec![
                r#"{"cveMetadata":{"cveId":"CVE-2099-0100","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-01T00:00:00Z"},"containers":{"cna":{"title":"bulk SSVC fixture"},"adp":[{"providerMetadata":{"shortName":"CISA-ADP"},"metrics":[{"other":{"type":"ssvc","content":{"id":"CVE-2099-0100","role":"CISA Coordinator","version":"2.0.3","timestamp":"2099-01-01T00:00:00Z","options":[{"Exploitation":"poc"},{"Automatable":"no"},{"Technical Impact":"partial"}]}}}]}]}}"#.to_owned(),
            ])
            .await
            .unwrap(),
        1
    );
    let stored = database.ssvc_assessments("CVE-2099-0100").await.unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(
        stored[0].exploitation,
        Some(crate::SsvcExploitation::PublicPoc)
    );
}
