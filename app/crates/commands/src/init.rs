use super::common::{
    CVE_DELTA_CURSOR_METADATA_KEY, IngestProgress, IngestProgressCallback, OSV_SOURCE_PREFIX_HELP,
    OsvImportMode, OsvImportSelection, ReleaseAssetKind, connect_sqlx_db, cve_full_asset_cursor,
    download_latest_asset_with_source, download_osv_selection_from_gcs,
    import_downloaded_osv_selection, ingest_zip_sqlx_bulk_with_index_signal, redact_database_url,
    remove_processed_zip, sync_capec_catalog_sqlx, sync_cwe_catalog_sqlx,
    sync_kev_epss_snapshots_sqlx,
};
use qanvuli_core::database::{
    DatabaseReplacement, RecoveryAction, candidate_database_path, recover_interrupted_replacement,
    remove_sqlite_database_files,
};
use std::path::PathBuf;
use std::time::Instant;

/// CLI arguments for `qanvuli init`.
#[derive(Debug, Default, clap::Args)]
#[command(after_help = OSV_SOURCE_PREFIX_HELP)]
pub struct Args {
    #[arg(long, value_name = "PATH")]
    zip: Option<PathBuf>,
    #[arg(long, value_name = "N")]
    max_chunks: Option<usize>,
    #[arg(long)]
    keep: bool,
    /// Remove the existing database before building the replacement.
    /// This reduces peak disk usage, but no usable database remains if initialization fails.
    #[arg(short = 'r', long, verbatim_doc_comment)]
    remove_existing_first: bool,
    #[arg(long)]
    osv_all: bool,
    #[arg(long = "osv-source", value_name = "PREFIX", hide = true)]
    osv_prefixes: Vec<String>,
}

/// Builds and installs a complete replacement vulnerability database.
pub async fn run(db_url: &str, args: Args) -> Result<(), String> {
    run_with_progress(db_url, args, None).await
}

async fn run_with_progress(
    db_url: &str,
    args: Args,
    progress: Option<IngestProgressCallback>,
) -> Result<(), String> {
    let target = super::common::database::sqlite_file_path(db_url).ok_or_else(|| {
        "full database replacement requires a file-backed SQLite database".to_owned()
    })?;
    for action in recover_interrupted_replacement(&target)
        .map_err(|error| format!("failed to inspect interrupted database replacements: {error}"))?
    {
        match action {
            RecoveryAction::RestoredBackup(path) => eprintln!(
                "init: restored interrupted replacement backup {} to {}",
                path.display(),
                target.display()
            ),
            RecoveryAction::StaleBackup(path) => eprintln!(
                "init: warning: active database is present; leaving stale replacement backup {}",
                path.display()
            ),
        }
    }
    if args.remove_existing_first {
        eprintln!("init: removing the existing database before replacement construction");
        eprintln!(
            "init: this reduces peak disk usage but leaves no usable database if initialization fails"
        );
        remove_sqlite_database_files(&target)
            .map_err(|error| format!("failed to remove existing database before init: {error}"))?;
    }

    let (asset_path, cve_delta_cursor) = if let Some(zip) = args.zip {
        emit_init_progress(&progress, &zip.display().to_string(), "using local zip");
        let cursor = cve_full_asset_cursor(&zip);
        (zip, cursor)
    } else {
        emit_init_progress(&progress, "-", "downloading");
        let asset = download_latest_asset_with_source(ReleaseAssetKind::All).await?;
        let cursor = asset
            .published_at
            .or_else(|| cve_full_asset_cursor(&asset.path));
        (asset.path, cursor)
    };

    let candidate_path = candidate_database_path(&target)
        .map_err(|error| format!("failed to create replacement path: {error}"))?;
    let candidate_url = format!("sqlite://{}?mode=rwc", candidate_path.display());
    emit_init_progress(
        &progress,
        &asset_path.display().to_string(),
        "building replacement database",
    );
    eprintln!(
        "init: building replacement database beside {}",
        redact_database_url(db_url)
    );
    let db = match connect_sqlx_db(&candidate_url).await {
        Ok(db) => db,
        Err(error) => {
            return Err(with_candidate_cleanup(error, &candidate_path));
        }
    };
    let osv_selection = OsvImportSelection::default_init(args.osv_all, &args.osv_prefixes);
    let db_for_build = db.clone();
    let asset_for_build = asset_path.clone();
    let progress_for_build = progress.clone();
    let max_chunks = args.max_chunks;
    let build_result = async move {
        emit_init_progress(
            &progress_for_build,
            &asset_for_build.display().to_string(),
            "importing",
        );
        db_for_build
            .initialize()
            .await
            .map_err(|error| format!("failed to initialize replacement schema: {error}"))?;
        let (index_started_tx, index_started_rx) = tokio::sync::oneshot::channel();
        let osv_download_task = tokio::spawn(async move {
            index_started_rx.await.map_err(|_| {
                "CVE import ended before index construction; OSV download was not started"
                    .to_owned()
            })?;
            eprintln!("init: CVE index construction started; beginning OSV prefetch");
            download_osv_selection_from_gcs("init", osv_selection, None).await
        });
        let cve_result = ingest_zip_sqlx_bulk_with_index_signal(
            db_for_build.clone(),
            "all",
            &asset_for_build,
            max_chunks,
            index_started_tx,
        )
        .await;
        let osv_download_result = osv_download_task
            .await
            .map_err(|error| format!("OSV download task failed: {error}"))?;
        cve_result?;
        if max_chunks.is_none() {
            let cve_delta_cursor = cve_delta_cursor.ok_or_else(|| {
                "cannot determine the full CVE archive timestamp from its release or filename"
                    .to_owned()
            })?;
            db_for_build
                .set_metadata_value(
                    CVE_DELTA_CURSOR_METADATA_KEY,
                    &cve_delta_cursor.to_rfc3339(),
                )
                .await
                .map_err(|error| format!("failed to store CVE delta cursor: {error}"))?;
        }
        sync_cwe_catalog_sqlx(db_for_build.clone()).await?;
        sync_capec_catalog_sqlx(db_for_build.clone()).await?;
        import_downloaded_osv_selection(
            db_for_build.clone(),
            osv_download_result?,
            OsvImportMode::InitialReplacement,
        )
        .await?;
        sync_kev_epss_snapshots_sqlx(db_for_build.clone(), "init", false).await?;
        validate_replacement_database(&db_for_build).await
    }
    .await;
    let close_result = db
        .close()
        .await
        .map_err(|error| format!("failed to close replacement database: {error}"));
    if let Err(error) = build_result.and(close_result) {
        return Err(with_candidate_cleanup(error, &candidate_path));
    }
    eprintln!("init: replacement database built successfully");
    emit_init_progress(
        &progress,
        &asset_path.display().to_string(),
        "installing replacement",
    );
    let had_target = target.exists();
    let mut replacement = DatabaseReplacement::new(target.clone(), candidate_path)
        .map_err(|error| format!("failed to prepare database replacement: {error}"))?;
    if had_target {
        eprintln!(
            "init: moving the active database to {}",
            replacement.backup_path().display()
        );
    }
    eprintln!("init: installing replacement database");
    replacement
        .install()
        .map_err(|error| format!("failed to install validated replacement database: {error}"))?;
    eprintln!("init: replacement installed successfully");
    if had_target {
        eprintln!("init: removing previous database backup");
    }
    if let Err(error) = replacement.commit() {
        eprintln!(
            "init: warning: replacement is active, but previous database cleanup failed: {error}"
        );
    }
    if !args.keep
        && let Err(error) = remove_processed_zip(&asset_path)
    {
        eprintln!(
            "init: replacement installed, but failed to remove processed archive {}: {error}",
            asset_path.display()
        );
    }
    Ok(())
}

fn with_candidate_cleanup(error: String, candidate: &std::path::Path) -> String {
    match remove_sqlite_database_files(candidate) {
        Ok(()) => error,
        Err(cleanup_error) => format!(
            "{error}; additionally failed to remove replacement candidate {} and its sidecars: {cleanup_error}",
            candidate.display()
        ),
    }
}

async fn validate_replacement_database(
    db: &qanvuli_core::database::SqlxDatabase,
) -> Result<(), String> {
    let validation_started = Instant::now();
    eprintln!("init: checking replacement schema and search sentinels");
    // Every build/index SQL statement has already completed successfully at this point. Keep
    // init's final check bounded: this verifies the required schema plus fixed first/last search
    // projection sentinels without rescanning the newly written database. Full SQLite, foreign-key,
    // FTS5, and projection scans remain available through `db check --scan` and `db check --full`.
    db.check_search_integrity_quick().await.map_err(|error| {
        format!("replacement database schema/search validation failed: {error}")
    })?;
    eprintln!(
        "init: replacement schema/search validation completed in {:?}",
        validation_started.elapsed()
    );
    Ok(())
}

fn emit_init_progress(progress: &Option<IngestProgressCallback>, asset: &str, phase: &'static str) {
    if let Some(progress) = progress {
        progress(IngestProgress {
            label: "init".to_owned(),
            asset: asset.to_owned(),
            phase: phase.to_owned(),
            total_files: 0,
            written_files: 0,
            failed_files: 0,
        });
    }
}

/// Runs initialization with default CLI arguments.
pub async fn run_default(db_url: &str) -> Result<(), String> {
    run(db_url, Args::default()).await
}

/// Runs default initialization and reports progress through the callback.
pub async fn run_default_with_progress(
    db_url: &str,
    progress: IngestProgressCallback,
) -> Result<(), String> {
    run_with_progress(db_url, Args::default(), Some(progress)).await
}

/// Runs default initialization with progress and optional archive retention.
pub async fn run_default_with_progress_and_keep(
    db_url: &str,
    progress: IngestProgressCallback,
    keep: bool,
) -> Result<(), String> {
    run_with_progress(
        db_url,
        Args {
            keep,
            ..Args::default()
        },
        Some(progress),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use qanvuli_core::database::{OsvRawRecord, SqlxDatabase};
    use sqlx::{Connection, Executor};
    use std::io::Write;

    fn test_database_path(label: &str) -> (PathBuf, String) {
        let path = std::env::temp_dir().join(format!(
            "qanvuli-init-{label}-{}-{}.sqlite",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let url = format!("sqlite://{}?mode=rwc", path.display());
        (path, url)
    }

    async fn initialized_database(label: &str) -> (PathBuf, String, SqlxDatabase) {
        let (path, url) = test_database_path(label);
        let database = SqlxDatabase::connect(&url).await.unwrap();
        database.initialize().await.unwrap();
        (path, url, database)
    }

    #[tokio::test]
    async fn replacement_validation_accepts_a_consistent_database() {
        let (path, _, database) = initialized_database("valid-replacement").await;
        validate_replacement_database(&database).await.unwrap();
        database.close().await.unwrap();
        remove_sqlite_database_files(&path).unwrap();
    }

    #[tokio::test]
    async fn replacement_validation_rejects_a_missing_osv_fts_row() {
        let (path, url, database) = initialized_database("missing-osv-fts").await;
        database
            .import_osv_record(OsvRawRecord {
                source_path: Some("fixture.json".to_owned()),
                raw_json:
                    r#"{"id":"OSV-TEST-1","modified":"2026-01-01T00:00:00Z","summary":"fixture"}"#
                        .to_owned(),
            })
            .await
            .unwrap();
        database.close().await.unwrap();
        let mut connection = sqlx::SqliteConnection::connect(&url).await.unwrap();
        connection
            .execute("DELETE FROM osv_text_fts WHERE osv_id='OSV-TEST-1'")
            .await
            .unwrap();
        connection.close().await.unwrap();
        let database = SqlxDatabase::connect(&url).await.unwrap();
        let error = validate_replacement_database(&database).await.unwrap_err();
        assert!(error.contains("OSV text FTS"));
        database.close().await.unwrap();
        remove_sqlite_database_files(&path).unwrap();
    }

    #[tokio::test]
    async fn replacement_validation_rejects_a_missing_cve_fts_row() {
        let (path, url, database) = initialized_database("missing-cve-fts").await;
        database
            .import_cve_raw_json(
                r#"{"cveMetadata":{"cveId":"CVE-2099-0001","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-01T00:00:00Z"},"containers":{"cna":{"title":"fixture"}}}"#.to_owned(),
            )
            .await
            .unwrap();
        database.close().await.unwrap();
        let mut connection = sqlx::SqliteConnection::connect(&url).await.unwrap();
        connection
            .execute("DELETE FROM cve_summary_fts WHERE cve_id='CVE-2099-0001'")
            .await
            .unwrap();
        connection.close().await.unwrap();
        let database = SqlxDatabase::connect(&url).await.unwrap();
        let error = validate_replacement_database(&database).await.unwrap_err();
        assert!(error.contains("CVE summary FTS"));
        database.close().await.unwrap();
        remove_sqlite_database_files(&path).unwrap();
    }

    #[tokio::test]
    async fn failed_full_init_preserves_the_existing_database_by_default() {
        let directory = std::env::temp_dir().join(format!(
            "qanvuli-init-replacement-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let database_path = directory.join("database.sqlite");
        let archive_path = directory.join("broken.zip");
        std::fs::write(&database_path, b"last known good database bytes").unwrap();
        let archive_file = std::fs::File::create(&archive_path).unwrap();
        let mut archive = zip::ZipWriter::new(archive_file);
        archive
            .start_file(
                "cves/2099/CVE-2099-0001.json",
                zip::write::SimpleFileOptions::default(),
            )
            .unwrap();
        archive.write_all(b"{not valid JSON").unwrap();
        archive.finish().unwrap();
        let url = format!("sqlite://{}?mode=rwc", database_path.display());
        let error = run_with_progress(
            &url,
            Args {
                zip: Some(archive_path.clone()),
                ..Args::default()
            },
            None,
        )
        .await
        .unwrap_err();
        assert!(error.contains("failed") || error.contains("invalid"));
        assert_eq!(
            std::fs::read(&database_path).unwrap(),
            b"last known good database bytes"
        );
        assert!(archive_path.exists());
        assert!(std::fs::read_dir(&directory).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".qanvuli-new-")
        }));
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test]
    async fn failed_destructive_init_removes_the_existing_database() {
        let directory = std::env::temp_dir().join(format!(
            "qanvuli-init-preserved-replacement-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let database_path = directory.join("database.sqlite");
        let archive_path = directory.join("broken.zip");
        std::fs::write(&database_path, b"last known good database bytes").unwrap();
        let archive_file = std::fs::File::create(&archive_path).unwrap();
        let mut archive = zip::ZipWriter::new(archive_file);
        archive
            .start_file(
                "cves/2099/CVE-2099-0001.json",
                zip::write::SimpleFileOptions::default(),
            )
            .unwrap();
        archive.write_all(b"{not valid JSON").unwrap();
        archive.finish().unwrap();
        let url = format!("sqlite://{}?mode=rwc", database_path.display());
        run_with_progress(
            &url,
            Args {
                zip: Some(archive_path),
                keep: true,
                remove_existing_first: true,
                ..Args::default()
            },
            None,
        )
        .await
        .unwrap_err();
        assert!(!database_path.exists());
        assert!(std::fs::read_dir(&directory).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".qanvuli-new-")
        }));
        let _ = std::fs::remove_dir_all(directory);
    }
}
