use super::common::{
    IngestProgressCallback, OSV_SOURCE_PREFIX_HELP, OsvImportSelection, apply_delta_updates,
    connect_sqlx_db, ingest_zip_sqlx, sync_cwe_catalog_sqlx, sync_kev_epss_snapshots_sqlx,
    sync_osv_selection_from_gcs_sqlx_with_full_snapshot,
};
use std::path::PathBuf;

/// CLI arguments for `qanvuli update`.
#[derive(Debug, Default, clap::Args)]
#[command(after_help = OSV_SOURCE_PREFIX_HELP)]
pub struct Args {
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
    /// Ignore the OSV cursor and refresh complete selected source snapshots.
    #[arg(long)]
    osv_full_snapshot: bool,
}

/// Applies CVE deltas, refreshes enrichment sources, and rebuilds the graph.
pub async fn run(db_url: &str, args: Args) -> Result<(), String> {
    run_with_progress(db_url, args, None).await
}

/// SQLx-only entry point for integrations that already own their argument parsing.
///
/// This deliberately does not reuse a caller-held database handle: update closes its dedicated
/// writer before any file replacement or cleanup can occur.
pub async fn run_sqlx_update(
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
            zip,
            max_chunks,
            keep,
            osv_all,
            osv_prefixes,
            osv_full_snapshot: false,
        },
    )
    .await
}

async fn run_with_progress(
    db_url: &str,
    args: Args,
    _progress: Option<IngestProgressCallback>,
) -> Result<(), String> {
    if let Some(zip) = args.zip {
        eprintln!("update: applying local SQLx delta {}", zip.display());
        let db = connect_sqlx_db(db_url).await?;
        db.check_required_schema()
            .await
            .map_err(|error| format!("database rebuild required or check failed: {error}"))?;
        let imported = ingest_zip_sqlx(db.clone(), "update", &zip, args.max_chunks).await?;
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
            let stored = db
                .metadata_value(super::common::OSV_IMPORT_ID_PREFIXES_METADATA_KEY)
                .await
                .map_err(|error| format!("failed to read OSV selection: {error}"))?;
            let current = OsvImportSelection::from_metadata(stored.as_deref())
                .unwrap_or_else(|| OsvImportSelection::default_init(false, &[]));
            sync_osv_selection_from_gcs_sqlx_with_full_snapshot(
                db.clone(),
                "update",
                current.merged_with(&additions),
                args.osv_full_snapshot,
            )
            .await?;
        }
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
    let sqlx_db = connect_sqlx_db(db_url).await?;
    if sqlx_db.check_required_schema().await.is_ok() {
        eprintln!("update: applying CVE delta archives");
        let applied_paths = apply_delta_updates(&sqlx_db, None, args.max_chunks).await?;
        let cve_changed = !applied_paths.is_empty();
        sync_cwe_catalog_sqlx(sqlx_db.clone()).await?;
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
        sync_osv_selection_from_gcs_sqlx_with_full_snapshot(
            sqlx_db.clone(),
            "update",
            selection,
            args.osv_full_snapshot,
        )
        .await?;
        sync_kev_epss_snapshots_sqlx(sqlx_db.clone(), "update", cve_changed).await?;
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

    #[tokio::test]
    async fn local_zip_update_uses_sqlx_schema_without_network() {
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
