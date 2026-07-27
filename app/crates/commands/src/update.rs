use super::common::{
    IngestProgress, IngestProgressCallback, OSV_SOURCE_PREFIX_HELP, OsvImportSelection,
    apply_delta_updates, apply_delta_updates_with_progress, connect_database, import_cve_zip,
    import_cve_zip_with_progress, sync_capec_catalog, sync_cwe_catalog, sync_osv_with_refresh,
    sync_risk_feeds,
};
use std::path::PathBuf;

/// CLI arguments for `qanvuli update`.
#[derive(Debug, Default, clap::Args)]
#[command(after_help = OSV_SOURCE_PREFIX_HELP)]
pub struct Args {
    /// Use the traditional detailed log output instead of a progress bar.
    #[arg(long)]
    no_progress: bool,
    #[arg(long, value_name = "PATH")]
    zip: Option<PathBuf>,
    #[arg(long, value_name = "N")]
    max_chunks: Option<usize>,
    #[arg(long)]
    keep: bool,
    #[arg(long)]
    osv_all: bool,
    #[arg(long = "osv-source", value_name = "PREFIX", hide = true)]
    osv_prefixes: Vec<String>,
    /// Ignore the OSV cursor, redownload selected snapshots, and upsert all records.
    /// Missing snapshot entries are not treated as deletions.
    #[arg(long)]
    osv_refresh_all: bool,
}

impl Args {
    /// Returns whether the CLI should render modern progress output.
    pub fn use_progress(&self) -> bool {
        !self.no_progress
    }

    /// Returns the remote resources fetched during this update.
    pub fn download_targets(&self) -> Vec<String> {
        if self.zip.is_some() {
            return OsvImportSelection::update_additions(self.osv_all, &self.osv_prefixes)
                .map(|selection| vec![format!("OSV snapshots ({})", selection.description())])
                .unwrap_or_default();
        }

        vec![
            "CVE delta archives".to_owned(),
            "CWE catalog".to_owned(),
            "CAPEC catalog".to_owned(),
            "configured OSV snapshots".to_owned(),
            "CISA KEV feed".to_owned(),
            "FIRST EPSS feed".to_owned(),
        ]
    }
}

/// Applies CVE deltas, refreshes enrichment sources, and rebuilds the graph.
pub async fn run(db_url: &str, args: Args) -> Result<(), String> {
    run_with_progress(db_url, args, None).await
}

/// Applies updates while reporting progress.
pub async fn run_with_cli_progress(
    db_url: &str,
    args: Args,
    progress: IngestProgressCallback,
) -> Result<(), String> {
    run_with_progress(db_url, args, Some(progress)).await
}

/// Runs an update from pre-parsed integration arguments.
pub async fn run_update(
    db_url: &str,
    zip: Option<PathBuf>,
    max_chunks: Option<usize>,
    keep: bool,
    osv_all: bool,
    osv_prefixes: Vec<String>,
) -> Result<(), String> {
    run(
        db_url,
        Args {
            no_progress: false,
            zip,
            max_chunks,
            keep,
            osv_all,
            osv_prefixes,
            osv_refresh_all: false,
        },
    )
    .await
}

async fn run_with_progress(
    db_url: &str,
    args: Args,
    progress: Option<IngestProgressCallback>,
) -> Result<(), String> {
    if let Some(zip) = args.zip {
        emit_update_progress(
            &progress,
            &zip.display().to_string(),
            "applying local CVE delta",
        );
        eprintln!("update: applying local CVE delta {}", zip.display());
        let db = connect_database(db_url).await?;
        db.check_required_schema()
            .await
            .map_err(|error| format!("database rebuild required or check failed: {error}"))?;
        let imported = if let Some(progress) = progress.clone() {
            import_cve_zip_with_progress(db.clone(), "update", &zip, args.max_chunks, progress)
                .await?
        } else {
            import_cve_zip(db.clone(), "update", &zip, args.max_chunks).await?
        };
        db.mark_cve_asset_applied(
            zip.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("local-cve.zip"),
            "local",
        )
        .await
        .map_err(|error| format!("failed to record local delta asset: {error}"))?;
        if let Some(additions) =
            OsvImportSelection::update_additions(args.osv_all, &args.osv_prefixes)
        {
            emit_update_progress(&progress, "-", "synchronizing OSV advisories");
            let stored = db
                .metadata_value(super::common::OSV_IMPORT_ID_PREFIXES_METADATA_KEY)
                .await
                .map_err(|error| format!("failed to read OSV selection: {error}"))?;
            let current = OsvImportSelection::from_metadata(stored.as_deref())
                .unwrap_or_else(|| OsvImportSelection::default_init(false, &[]));
            sync_osv_with_refresh(
                db.clone(),
                "update",
                current.merged_with(&additions),
                args.osv_refresh_all,
            )
            .await?;
        }
        emit_update_progress(&progress, "-", "validating database");
        db.check_search_integrity_quick()
            .await
            .map_err(|error| format!("post-update database check failed: {error}"))?;
        db.close()
            .await
            .map_err(|error| format!("failed to close database: {error}"))?;
        eprintln!(
            "update: imported {imported} CVE record(s) from {}",
            zip.display()
        );
        return Ok(());
    }
    let sqlx_db = connect_database(db_url).await?;
    if sqlx_db.check_required_schema().await.is_ok() {
        emit_update_progress(&progress, "-", "applying CVE delta archives");
        eprintln!("update: applying CVE delta archives");
        let applied_paths = if progress.is_some() {
            apply_delta_updates_with_progress(&sqlx_db, None, args.max_chunks, progress.clone())
                .await?
        } else {
            apply_delta_updates(&sqlx_db, None, args.max_chunks).await?
        };
        let cve_changed = !applied_paths.is_empty();
        emit_update_progress(&progress, "-", "synchronizing CWE catalog");
        sync_cwe_catalog(sqlx_db.clone()).await?;
        emit_update_progress(&progress, "-", "synchronizing CAPEC catalog");
        sync_capec_catalog(sqlx_db.clone()).await?;
        let saved_selection = sqlx_db
            .metadata_value(super::common::OSV_IMPORT_ID_PREFIXES_METADATA_KEY)
            .await
            .map_err(|error| format!("failed to read OSV selection: {error}"))?;
        let selection = OsvImportSelection::from_metadata(saved_selection.as_deref())
            .unwrap_or_else(|| OsvImportSelection::default_init(args.osv_all, &args.osv_prefixes));
        let additions = OsvImportSelection::update_additions(args.osv_all, &args.osv_prefixes);
        let selection = additions.map_or(selection.clone(), |additions| {
            selection.merged_with(&additions)
        });
        emit_update_progress(&progress, "-", "synchronizing OSV advisories");
        sync_osv_with_refresh(sqlx_db.clone(), "update", selection, args.osv_refresh_all).await?;
        emit_update_progress(&progress, "-", "synchronizing risk feeds");
        sync_risk_feeds(sqlx_db.clone(), "update", cve_changed).await?;
        emit_update_progress(&progress, "-", "validating database");
        sqlx_db
            .check_search_integrity_quick()
            .await
            .map_err(|error| format!("post-update database check failed: {error}"))?;
        sqlx_db
            .close()
            .await
            .map_err(|error| format!("failed to close database: {error}"))?;
        if !args.keep {
            for path in applied_paths {
                super::common::remove_processed_zip(&path)?;
            }
        }
        return Ok(());
    }
    let error = sqlx_db.check_required_schema().await.unwrap_err();
    let _ = sqlx_db.close().await;
    Err(format!("database rebuild required before update: {error}"))
}

fn emit_update_progress(
    progress: &Option<IngestProgressCallback>,
    asset: &str,
    phase: &'static str,
) {
    if let Some(progress) = progress {
        progress(IngestProgress {
            label: "update".to_owned(),
            asset: asset.to_owned(),
            phase: phase.to_owned(),
            total_files: 0,
            written_files: 0,
            failed_files: 0,
        });
    }
}

/// Runs update with default CLI arguments.
pub async fn run_default(db_url: &str) -> Result<(), String> {
    run(db_url, Args::default()).await
}

/// Runs default update and reports progress through the callback.
pub async fn run_default_with_progress(
    db_url: &str,
    progress: IngestProgressCallback,
) -> Result<(), String> {
    run_with_progress(db_url, Args::default(), Some(progress)).await
}

/// Runs default update with progress and optional archive retention.
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
    use qanvuli_core::database::SqlxDatabase;
    use sqlx::Connection;
    use std::io::Write;

    #[test]
    fn only_no_progress_disables_modern_progress() {
        assert!(Args::default().use_progress());
        assert!(
            Args {
                osv_refresh_all: true,
                ..Args::default()
            }
            .use_progress()
        );
        assert!(
            !Args {
                no_progress: true,
                ..Args::default()
            }
            .use_progress()
        );
    }

    #[test]
    fn download_targets_omit_remote_cve_for_a_local_archive() {
        assert!(
            Args::default()
                .download_targets()
                .iter()
                .any(|target| target == "CVE delta archives")
        );

        let local_targets = Args {
            zip: Some(PathBuf::from("delta.zip")),
            ..Args::default()
        }
        .download_targets();
        assert!(local_targets.is_empty());
    }

    #[tokio::test]
    async fn local_zip_update_does_not_use_network() {
        let directory = std::env::temp_dir().join(format!(
            "qanvuli-sqlx-update-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let database_path = directory.join("database.sqlite");
        let zip_path = directory.join("delta.zip");
        let url = format!("sqlite://{}?mode=rwc", database_path.display());
        let database = SqlxDatabase::connect(&url).await.unwrap();
        database.initialize().await.unwrap();
        database.close().await.unwrap();
        let file = std::fs::File::create(&zip_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        zip.start_file(
            "CVE-2099-0002.json",
            zip::write::SimpleFileOptions::default(),
        )
        .unwrap();
        zip.write_all(br#"{"cveMetadata":{"cveId":"CVE-2099-0002","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-01T00:00:00Z"},"containers":{"cna":{"title":"delta fixture"}}}"#).unwrap();
        zip.finish().unwrap();
        run(
            &url,
            Args {
                zip: Some(zip_path.clone()),
                ..Args::default()
            },
        )
        .await
        .unwrap();
        let database = SqlxDatabase::connect(&url).await.unwrap();
        assert!(
            database
                .find_cve_summary("CVE-2099-0002")
                .await
                .unwrap()
                .is_some()
        );
        database.close().await.unwrap();
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test]
    async fn old_schema_update_requires_rebuild_before_network_work() {
        let path = std::env::temp_dir().join(format!(
            "qanvuli-old-update-{}-{}.sqlite",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let url = format!("sqlite://{}?mode=rwc", path.display());
        let mut connection = sqlx::SqliteConnection::connect(&url).await.unwrap();
        sqlx::query("CREATE TABLE cve (id INTEGER PRIMARY KEY, cve_id TEXT) STRICT")
            .execute(&mut connection)
            .await
            .unwrap();
        connection.close().await.unwrap();
        let error = run(&url, Args::default()).await.unwrap_err();
        assert!(error.contains("database rebuild required"));
        let _ = std::fs::remove_file(path);
    }
}
