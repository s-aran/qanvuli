use super::*;

#[test]
fn ingest_progress_uses_bounded_chunk_count() {
    assert_eq!(ingest_chunk_count(0, None), 0);
    assert_eq!(ingest_chunk_count(INGEST_CHUNK_SIZE, None), 1);
    assert_eq!(ingest_chunk_count(INGEST_CHUNK_SIZE + 1, None), 2);
    assert_eq!(ingest_chunk_count(INGEST_CHUNK_SIZE * 10, Some(3)), 3);
}

#[test]
fn full_cve_filename_provides_a_safe_delta_cursor() {
    assert_eq!(
        cve_full_asset_cursor(Path::new("2026-07-18_all_CVEs_at_midnight.zip.zip"))
            .unwrap()
            .to_rfc3339(),
        "2026-07-18T00:00:00+00:00"
    );
    assert!(cve_full_asset_cursor(Path::new("delta.zip")).is_none());
}

#[test]
fn cve_remote_update_kind_uses_hourly_through_exactly_24_hours() {
    let cursor = DateTime::parse_from_rfc3339("2026-07-01T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc);

    assert_eq!(
        cve_remote_update_kind(cursor, cursor + TimeDelta::hours(24)),
        CveRemoteUpdateKind::Hourly
    );
    assert_eq!(
        cve_remote_update_kind(
            cursor,
            cursor + TimeDelta::hours(24) + TimeDelta::seconds(1)
        ),
        CveRemoteUpdateKind::DailyThenHourly
    );
}

#[test]
fn cve_remote_update_kind_uses_full_at_two_weeks() {
    let cursor = DateTime::parse_from_rfc3339("2026-07-01T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc);

    assert_eq!(
        cve_remote_update_kind(cursor, cursor + TimeDelta::days(14) - TimeDelta::seconds(1)),
        CveRemoteUpdateKind::DailyThenHourly
    );
    assert_eq!(
        cve_remote_update_kind(cursor, cursor + TimeDelta::days(14)),
        CveRemoteUpdateKind::Full
    );
}

#[test]
fn cve_archive_cleanup_respects_ownership_and_keep() {
    let directory = std::env::temp_dir().join(format!(
        "qanvuli-cve-archive-ownership-{}-{}",
        std::process::id(),
        Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    std::fs::create_dir_all(&directory).unwrap();

    let local = directory.join("local.zip");
    std::fs::write(&local, b"local").unwrap();
    cleanup_processed_cve_archive(&local, CveArchiveOwnership::UserSupplied, false).unwrap();
    assert!(local.exists());

    let kept_download = directory.join("kept.zip");
    std::fs::write(&kept_download, b"download").unwrap();
    cleanup_processed_cve_archive(&kept_download, CveArchiveOwnership::Downloaded, true).unwrap();
    assert!(kept_download.exists());

    let removed_download = directory.join("removed.zip");
    std::fs::write(&removed_download, b"download").unwrap();
    cleanup_processed_cve_archive(&removed_download, CveArchiveOwnership::Downloaded, false)
        .unwrap();
    assert!(!removed_download.exists());

    let _ = std::fs::remove_dir_all(directory);
}

#[tokio::test]
async fn remote_delta_update_requires_a_cursor_from_full_init() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();

    let error = apply_delta_updates(&database, None, None)
        .await
        .unwrap_err();

    assert!(error.contains("CVE delta cursor is missing"));
}

#[test]
fn downloaded_osv_selection_removes_temporary_zips_when_dropped() {
    let path = std::env::temp_dir().join(format!(
        "qanvuli-osv-prefetch-{}-{}.zip",
        std::process::id(),
        Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    std::fs::write(&path, b"temporary").unwrap();
    let download = DownloadedOsvSelection {
        label: "test".to_owned(),
        selection: OsvImportSelection::default_init(false, &[]),
        cursor: Utc::now().to_rfc3339(),
        target_osv_ids: None,
        zip_paths: vec![path.clone()],
        download_elapsed: Duration::ZERO,
        ready_at: Instant::now(),
    };

    drop(download);

    assert!(!path.exists());
}

#[test]
fn default_database_is_in_current_working_directory() {
    let db_url = default_db_connection_string().unwrap();
    let db_path = database::sqlite_file_path(&db_url).unwrap();

    assert_eq!(db_path, std::env::current_dir().unwrap().join("db.sqlite"));
}

#[test]
fn zip_download_capacity_includes_safety_margin() {
    let payload = 556_000_000;
    assert_eq!(
        zip_download_required_bytes(payload),
        payload + ZIP_DOWNLOAD_FREE_SPACE_MARGIN_BYTES
    );
    assert!(zip_download_required_bytes(payload) > 722_000_000);
    assert_eq!(zip_download_required_bytes(u64::MAX), u64::MAX);
}

#[test]
fn temporary_storage_selection_checks_known_fallback_capacity() {
    assert_eq!(
        choose_temporary_storage(Some(100), Some(200), Some(50)),
        Ok(TemporaryStorageChoice::Primary)
    );
    assert_eq!(
        choose_temporary_storage(Some(100), Some(50), Some(200)),
        Ok(TemporaryStorageChoice::Fallback)
    );
    assert_eq!(
        choose_temporary_storage(Some(100), Some(50), None),
        Ok(TemporaryStorageChoice::Fallback)
    );
    assert_eq!(
        choose_temporary_storage(Some(100), None, Some(50)),
        Ok(TemporaryStorageChoice::Primary)
    );
    assert_eq!(
        choose_temporary_storage(Some(100), Some(50), Some(75)),
        Err((100, 50, 75))
    );
}

#[test]
fn redact_database_url_removes_embedded_credentials() {
    let redacted = redact_database_url("postgres://alice:super-secret@example.test/qanvuli");

    assert_eq!(redacted, "postgres://REDACTED@example.test/qanvuli");
    assert!(!redacted.contains("super-secret"));
    assert!(!redacted.contains("alice"));
}

#[test]
fn remove_processed_zip_deletes_existing_file() {
    let path = std::env::temp_dir().join(format!(
        "qanvuli-processed-zip-{}-{}.zip",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    std::fs::write(&path, b"zip").unwrap();

    remove_processed_zip(&path).unwrap();

    assert!(!path.exists());
}

#[test]
fn osv_selection_resolves_gcs_database_dirs_from_modified_paths() {
    let selection =
        OsvImportSelection::default_init(false, &["ghsa".to_owned(), "pysec".to_owned()]);
    let rows = vec![
        OsvModifiedId {
            modified_at: "2026-07-07T00:00:00Z".to_owned(),
            object_path: "PyPI/GHSA-73jc-5mrq-prw7.json".to_owned(),
        },
        OsvModifiedId {
            modified_at: "2026-07-07T00:00:00Z".to_owned(),
            object_path: "RubyGems/GHSA-8p34-64r3-mwg8.json".to_owned(),
        },
        OsvModifiedId {
            modified_at: "2026-07-07T00:00:00Z".to_owned(),
            object_path: "PyPI/PYSEC-2026-1.json".to_owned(),
        },
        OsvModifiedId {
            modified_at: "2026-07-07T00:00:00Z".to_owned(),
            object_path: "crates.io/RUSTSEC-2026-1.json".to_owned(),
        },
        OsvModifiedId {
            modified_at: "2026-07-07T00:00:00Z".to_owned(),
            object_path: "[EMPTY]/GHSA-empty.json".to_owned(),
        },
        OsvModifiedId {
            modified_at: "2026-07-07T00:00:00Z".to_owned(),
            object_path: "empty/GHSA-lowercase-empty.json".to_owned(),
        },
    ];

    let database_dirs = osv_database_dirs_for_selection(&selection, &rows);

    assert_eq!(
        database_dirs.get("PyPI"),
        Some(&BTreeSet::from(["GHSA".to_owned(), "PYSEC".to_owned()]))
    );
    assert_eq!(
        database_dirs.get("RubyGems"),
        Some(&BTreeSet::from(["GHSA".to_owned()]))
    );
    assert_eq!(
        database_dirs.get("[EMPTY]"),
        Some(&BTreeSet::from(["GHSA".to_owned()]))
    );
    assert!(!database_dirs.contains_key("crates.io"));
    assert!(!database_dirs.contains_key("empty"));
}

#[test]
fn osv_cursor_selects_only_newer_matching_object_paths() {
    let selection = OsvImportSelection::default_init(false, &["pysec".to_owned()]);
    let rows = vec![
        OsvModifiedId {
            modified_at: "2026-07-06T23:59:59Z".to_owned(),
            object_path: "PyPI/PYSEC-2026-old.json".to_owned(),
        },
        OsvModifiedId {
            modified_at: "2026-07-07T00:00:00Z".to_owned(),
            object_path: "PyPI/GHSA-equal.json".to_owned(),
        },
        OsvModifiedId {
            modified_at: "2026-07-07T00:00:01+00:00".to_owned(),
            object_path: "PyPI/PYSEC-2026-new.json".to_owned(),
        },
        OsvModifiedId {
            modified_at: "2026-07-08T00:00:00Z".to_owned(),
            object_path: "crates.io/RUSTSEC-2026-new.json".to_owned(),
        },
    ];

    assert_eq!(
        osv_target_paths_since(&selection, &rows, "2026-07-07T00:00:00Z"),
        AHashSet::from(["PyPI/PYSEC-2026-new.json".to_owned()])
    );
}

#[test]
fn osv_and_ghsa_are_always_included_in_osv_selection() {
    let selection = OsvImportSelection::default_init(false, &["pysec".to_owned()]);
    assert!(selection.matches_id("OSV-2024-1"));
    assert!(selection.matches_id("GHSA-aaaa-bbbb-cccc"));
    assert!(selection.matches_id("PYSEC-2024-1"));

    let restored = OsvImportSelection::from_metadata(Some("OSV")).unwrap();
    assert!(restored.matches_id("GHSA-aaaa-bbbb-cccc"));

    assert!(!metadata_includes_required_osv_prefixes("OSV"));
    assert!(metadata_includes_required_osv_prefixes("OSV,GHSA"));
    assert!(metadata_includes_required_osv_prefixes("all"));
}

#[test]
fn osv_zip_reader_skips_seen_and_duplicate_osv_ids() {
    use std::io::Write;

    let zip_path = std::env::temp_dir().join(format!(
        "qanvuli-osv-reader-dedupe-{}-{}.zip",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    let file = std::fs::File::create(&zip_path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options = zip::write::SimpleFileOptions::default();
    for (name, raw_json) in [
        ("GHSA-skip.json", r#"{"id":"GHSA-skip"}"#),
        ("GHSA-keep.json", r#"{"id":"GHSA-keep"}"#),
        ("nested/GHSA-keep.json", r#"{"id":"GHSA-keep"}"#),
    ] {
        zip.start_file(name, options).unwrap();
        zip.write_all(raw_json.as_bytes()).unwrap();
    }
    zip.finish().unwrap();

    let selection = OsvImportSelection::default_init(false, &["ghsa".to_owned()]);
    let skip_osv_ids = AHashSet::from(["GHSA-SKIP".to_owned()]);
    let (batch_tx, mut batch_rx) = mpsc::channel(8);
    read_osv_zip_batches(
        &zip_path,
        None,
        Some(&selection),
        Some(&skip_osv_ids),
        batch_tx,
    )
    .unwrap();
    let mut batches = Vec::new();
    while let Ok(batch) = batch_rx.try_recv() {
        batches.push(batch.unwrap());
    }

    assert_eq!(
        batches
            .iter()
            .map(|batch| batch.records.len())
            .sum::<usize>(),
        1
    );

    let _ = std::fs::remove_file(zip_path);
}

#[tokio::test]
async fn sqlx_zip_ingest_imports_cve_and_builds_stable_search() {
    use qanvuli_core::database::SqlxDatabase;
    use std::io::Write;

    let zip_path = std::env::temp_dir().join(format!(
        "qanvuli-sqlx-ingest-{}-{}.zip",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    let file = std::fs::File::create(&zip_path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    zip.start_file(
        "CVE-2099-0001.json",
        zip::write::SimpleFileOptions::default(),
    )
    .unwrap();
    zip.write_all(br#"{"cveMetadata":{"cveId":"CVE-2099-0001","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-01T00:00:00Z"},"containers":{"cna":{"title":"SQLx fixture"},"adp":[{"providerMetadata":{"shortName":"CISA-ADP"},"metrics":[{"other":{"type":"ssvc","content":{"id":"CVE-2099-0001","role":"CISA Coordinator","version":"2.0.3","timestamp":"2099-01-01T00:00:00Z","options":[{"Exploitation":"poc"},{"Automatable":"yes"},{"Technical Impact":"total"}]}}}]}]}}"#)
            .unwrap();
    zip.finish().unwrap();
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    assert_eq!(
        import_cve_zip(database.clone(), "test", &zip_path, None)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        database
            .search_cves("fixture", false, 10)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(database.ssvc_assessment_count().await.unwrap(), 1);
    database.close().await.unwrap();
    let _ = std::fs::remove_file(zip_path);
}

#[tokio::test]
async fn osv_zip_import_advances_cursor_after_validation() {
    use qanvuli_core::database::SqlxDatabase;
    use std::io::Write;

    let zip_path = std::env::temp_dir().join(format!(
        "qanvuli-sqlx-osv-{}-{}.zip",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    let file = std::fs::File::create(&zip_path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    zip.start_file(
        "GHSA-TEST-0001.json",
        zip::write::SimpleFileOptions::default(),
    )
    .unwrap();
    zip.write_all(include_bytes!(
        "../../../../../fixtures/osv/GHSA-TEST-0001.json"
    ))
    .unwrap();
    zip.finish().unwrap();
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    assert_eq!(
        import_osv_zip(database.clone(), &zip_path, None, "2099-01-02T00:00:00Z")
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        database.begin_osv_sync().await.unwrap(),
        Some("2099-01-02T00:00:00Z".to_owned())
    );
    database.close().await.unwrap();
    let _ = std::fs::remove_file(zip_path);
}

#[tokio::test]
async fn eager_cleanup_removes_each_imported_osv_zip() {
    use qanvuli_core::database::SqlxDatabase;
    use std::io::Write;

    let zip_path = std::env::temp_dir().join(format!(
        "qanvuli-sqlx-osv-eager-cleanup-{}-{}.zip",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    let file = std::fs::File::create(&zip_path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    zip.start_file(
        "GHSA-TEST-0001.json",
        zip::write::SimpleFileOptions::default(),
    )
    .unwrap();
    zip.write_all(include_bytes!(
        "../../../../../fixtures/osv/GHSA-TEST-0001.json"
    ))
    .unwrap();
    zip.finish().unwrap();

    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    let paths = [zip_path.clone()];
    assert_eq!(
        import_osv_zips(
            database.clone(),
            &paths,
            None,
            None,
            "2099-01-02T00:00:00Z",
            OsvImportMode::IncrementalUpdate,
            true,
        )
        .await
        .unwrap(),
        1
    );
    assert!(!zip_path.exists());
    database.close().await.unwrap();
}

#[tokio::test]
async fn normal_osv_update_uses_incremental_upsert_for_changed_and_new_records() {
    use qanvuli_core::database::SqlxDatabase;
    use std::io::Write;

    let nonce = format!(
        "{}-{}",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    );
    let initial_zip = std::env::temp_dir().join(format!("qanvuli-osv-initial-{nonce}.zip"));
    let update_zip = std::env::temp_dir().join(format!("qanvuli-osv-update-{nonce}.zip"));
    let options = zip::write::SimpleFileOptions::default();
    let mut zip = zip::ZipWriter::new(std::fs::File::create(&initial_zip).unwrap());
    zip.start_file("GHSA-2099-existing.json", options).unwrap();
    zip.write_all(br#"{"schema_version":"1.8.0","id":"GHSA-2099-existing","modified":"2099-01-01T00:00:00Z","summary":"before"}"#).unwrap();
    zip.finish().unwrap();

    let mut zip = zip::ZipWriter::new(std::fs::File::create(&update_zip).unwrap());
    zip.start_file("GHSA-2099-existing.json", options).unwrap();
    zip.write_all(br#"{"schema_version":"1.8.0","id":"GHSA-2099-existing","modified":"2099-01-02T00:00:00Z","summary":"after"}"#).unwrap();
    zip.start_file("GHSA-2099-new.json", options).unwrap();
    zip.write_all(br#"{"schema_version":"1.8.0","id":"GHSA-2099-new","modified":"2099-01-02T00:00:00Z","summary":"new"}"#).unwrap();
    zip.finish().unwrap();

    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    import_osv_zip(database.clone(), &initial_zip, None, "2099-01-01T00:00:00Z")
        .await
        .unwrap();
    assert_eq!(
        import_osv_zip(database.clone(), &update_zip, None, "2099-01-02T00:00:00Z")
            .await
            .unwrap(),
        2
    );
    assert_eq!(
        database
            .find_osv_summary("GHSA-2099-existing")
            .await
            .unwrap()
            .unwrap()
            .summary
            .as_deref(),
        Some("after")
    );
    assert!(
        database
            .find_osv_summary("GHSA-2099-new")
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        database.begin_osv_sync().await.unwrap().as_deref(),
        Some("2099-01-02T00:00:00Z")
    );
    database.close().await.unwrap();
    let _ = std::fs::remove_file(initial_zip);
    let _ = std::fs::remove_file(update_zip);
}

#[tokio::test]
async fn sqlx_osv_zip_failure_keeps_cursor_and_retry_is_idempotent() {
    use qanvuli_core::database::SqlxDatabase;
    use std::io::Write;

    let directory = std::env::temp_dir();
    let nonce = format!(
        "{}-{}",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    );
    let failing_zip = directory.join(format!("qanvuli-osv-failing-{nonce}.zip"));
    let retry_zip = directory.join(format!("qanvuli-osv-retry-{nonce}.zip"));
    let mut zip = zip::ZipWriter::new(std::fs::File::create(&failing_zip).unwrap());
    let options = zip::write::SimpleFileOptions::default();
    for index in 0..OSV_IMPORT_BATCH_SIZE {
        let id = format!("GHSA-2099-retry-{index:04}");
        zip.start_file(format!("{id}.json"), options).unwrap();
        zip.write_all(
            format!(
                r#"{{"schema_version":"1.8.0","id":"{id}","modified":"2099-01-01T00:00:00Z"}}"#
            )
            .as_bytes(),
        )
        .unwrap();
    }
    zip.start_file("GHSA-2099-invalid.json", options).unwrap();
    zip.write_all(br#"{"schema_version":"1.7.3","id":"GHSA-2099-invalid"}"#)
        .unwrap();
    zip.finish().unwrap();

    let mut zip = zip::ZipWriter::new(std::fs::File::create(&retry_zip).unwrap());
    zip.start_file("GHSA-2099-retry-0000.json", options)
        .unwrap();
    zip.write_all(
            br#"{"schema_version":"1.8.0","id":"GHSA-2099-retry-0000","modified":"2099-01-01T00:00:00Z"}"#,
        )
        .unwrap();
    zip.finish().unwrap();

    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    assert!(
        import_osv_zip(database.clone(), &failing_zip, None, "2099-01-02T00:00:00Z")
            .await
            .is_err()
    );
    let state = database.source_sync_states().await.unwrap().pop().unwrap();
    assert_eq!(state.status, "failed");
    assert_eq!(state.last_cursor, None);

    assert_eq!(
        import_osv_zip(database.clone(), &retry_zip, None, "2099-01-02T00:00:00Z")
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        database.begin_osv_sync().await.unwrap(),
        Some("2099-01-02T00:00:00Z".to_owned())
    );
    assert!(
        database
            .find_osv_summary("GHSA-2099-retry-0000")
            .await
            .unwrap()
            .is_some()
    );
    database.close().await.unwrap();
    let _ = std::fs::remove_file(failing_zip);
    let _ = std::fs::remove_file(retry_zip);
}
