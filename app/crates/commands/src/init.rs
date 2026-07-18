use super::common::{
    IngestProgress, IngestProgressCallback, OSV_SOURCE_PREFIX_HELP, OsvImportSelection,
    ReleaseAssetKind, connect_sqlx_db, download_latest_asset_with_source, ingest_zip_sqlx_bulk,
    redact_database_url, remove_processed_zip, remove_sqlite_database_files,
    replacement_sqlite_database_url, sync_cwe_catalog_sqlx, sync_kev_epss_snapshots_sqlx,
    sync_osv_selection_from_gcs_sqlx,
};
use qanvuli_core::database::install_closed_database;
use std::path::PathBuf;

/// CLI arguments for `qanvuli init`.
#[derive(Debug, Default, clap::Args)]
#[command(after_help = OSV_SOURCE_PREFIX_HELP)]
pub struct Args {
    #[arg(long)]
    schema_only: bool,
    #[arg(long)]
    rebuild: bool,
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
}

/// Initializes the database schema and, unless schema-only, imports CVE data.
pub async fn run(db_url: &str, args: Args) -> Result<(), String> {
    run_with_progress(db_url, args, None).await
}

async fn run_with_progress(
    db_url: &str,
    args: Args,
    progress: Option<IngestProgressCallback>,
) -> Result<(), String> {
    if args.schema_only {
        emit_init_progress(&progress, "-", "connecting");
        eprintln!("init: connecting database {}", redact_database_url(db_url));
        if args.rebuild {
            let (candidate_path, candidate_url) = replacement_sqlite_database_url(db_url)?;
            let db = connect_sqlx_db(&candidate_url).await?;
            db.initialize()
                .await
                .map_err(|error| format!("failed to initialize replacement schema: {error}"))?;
            db.check()
                .await
                .map_err(|error| format!("failed to validate replacement schema: {error}"))?;
            db.close()
                .await
                .map_err(|error| format!("failed to close replacement database: {error}"))?;
            let target = super::common::database::sqlite_file_path(db_url).ok_or_else(|| {
                "schema rebuild requires a file-backed SQLite database".to_owned()
            })?;
            install_closed_database(&candidate_path, &target)
                .map_err(|error| format!("failed to install rebuilt schema: {error}"))?;
            emit_init_progress(&progress, "-", "done");
            println!("rebuilt schema: {}", redact_database_url(db_url));
            return Ok(());
        }
        let db = connect_sqlx_db(db_url).await?;
        emit_init_progress(&progress, "-", "initializing");
        db.initialize()
            .await
            .map_err(|err| format!("failed to initialize SQLx schema: {err}"))?;
        db.check()
            .await
            .map_err(|err| format!("failed to validate SQLx schema: {err}"))?;
        emit_init_progress(&progress, "-", "done");
        println!("initialized schema: {}", redact_database_url(db_url));
        db.close()
            .await
            .map_err(|error| format!("failed to close database: {error}"))?;
        return Ok(());
    }

    let asset_path = if let Some(zip) = args.zip {
        emit_init_progress(&progress, &zip.display().to_string(), "using local zip");
        zip
    } else {
        emit_init_progress(&progress, "-", "downloading");
        download_latest_asset_with_source(ReleaseAssetKind::All)
            .await?
            .path
    };

    let (candidate_path, candidate_url) = replacement_sqlite_database_url(db_url)?;
    emit_init_progress(
        &progress,
        &asset_path.display().to_string(),
        "building replacement database",
    );
    eprintln!(
        "init: building replacement database beside {}",
        redact_database_url(db_url)
    );
    let db = connect_sqlx_db(&candidate_url).await?;
    let osv_selection = OsvImportSelection::default_init(args.osv_all, &args.osv_prefixes);
    let db_for_build = db.clone();
    let asset_for_build = asset_path.clone();
    let progress_for_build = progress.clone();
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
        ingest_zip_sqlx_bulk(
            db_for_build.clone(),
            "all",
            &asset_for_build,
            args.max_chunks,
        )
        .await?;
        sync_cwe_catalog_sqlx(db_for_build.clone()).await?;
        sync_osv_selection_from_gcs_sqlx(db_for_build.clone(), "init", osv_selection).await?;
        sync_kev_epss_snapshots_sqlx(db_for_build.clone(), "init").await?;
        db_for_build
            .check()
            .await
            .map_err(|error| format!("replacement database integrity check failed: {error}"))
    }
    .await;
    let close_result = db
        .close()
        .await
        .map_err(|error| format!("failed to close replacement database: {error}"));
    if let Err(error) = build_result.and(close_result) {
        let _ = remove_sqlite_database_files(&candidate_path);
        return Err(error);
    }
    emit_init_progress(
        &progress,
        &asset_path.display().to_string(),
        "installing replacement",
    );
    let target = super::common::database::sqlite_file_path(db_url).ok_or_else(|| {
        "full database replacement requires a file-backed SQLite database".to_owned()
    })?;
    install_closed_database(&candidate_path, &target)
        .map_err(|error| format!("failed to install validated replacement database: {error}"))?;
    if !args.keep {
        remove_processed_zip(&asset_path)?;
    }
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
    use qanvuli_core::database::SqlxDatabase;
    use std::io::Write;

    #[tokio::test]
    async fn failed_full_init_preserves_the_existing_database_file() {
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
                keep: true,
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
        assert!(std::fs::read_dir(&directory).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".building-")
        }));
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test]
    async fn schema_rebuild_installs_a_new_sqlx_database_over_an_old_file() {
        let directory = std::env::temp_dir().join(format!(
            "qanvuli-schema-rebuild-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("database.sqlite");
        std::fs::write(&path, b"not a SQLite database").unwrap();
        let url = format!("sqlite://{}?mode=rwc", path.display());
        run_with_progress(
            &url,
            Args {
                schema_only: true,
                rebuild: true,
                ..Args::default()
            },
            None,
        )
        .await
        .unwrap();
        let database = SqlxDatabase::connect(&url).await.unwrap();
        database.check().await.unwrap();
        database.close().await.unwrap();
        let _ = std::fs::remove_dir_all(directory);
    }
}
