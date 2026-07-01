use super::common::{
    IngestMode, IngestProgress, IngestProgressCallback, ReleaseAssetKind, connect_db,
    download_latest_asset_with_source, ingest_zip_with_progress, remove_downloaded_zip,
    reset_sqlite_database_files,
};
use std::path::PathBuf;

#[derive(Debug, clap::Args)]
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
}

impl Default for Args {
    fn default() -> Self {
        Self {
            schema_only: false,
            rebuild: false,
            zip: None,
            max_chunks: None,
            keep: false,
        }
    }
}

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
        eprintln!("init: connecting database {db_url}");
        let db = connect_db(db_url).await?;
        if args.rebuild {
            emit_init_progress(&progress, "-", "rebuilding");
            eprintln!("init: rebuilding schema");
            db.rebuild_schema()
                .await
                .map_err(|err| format!("failed to rebuild schema: {err}"))?;
        } else {
            emit_init_progress(&progress, "-", "migrating");
            eprintln!("init: applying schema migrations");
            db.initialize_schema()
                .await
                .map_err(|err| format!("failed to initialize schema: {err}"))?;
        }
        emit_init_progress(&progress, "-", "done");
        println!("initialized schema: {db_url}");
        db.close()
            .await
            .map_err(|err| format!("failed to close database: {err}"))?;
        return Ok(());
    }

    let (asset_path, downloaded_asset) = if let Some(zip) = args.zip {
        emit_init_progress(&progress, &zip.display().to_string(), "using local zip");
        (zip, false)
    } else {
        emit_init_progress(&progress, "-", "downloading");
        let asset = download_latest_asset_with_source(ReleaseAssetKind::All).await?;
        (asset.path, asset.downloaded)
    };

    emit_init_progress(
        &progress,
        &asset_path.display().to_string(),
        "resetting database",
    );
    reset_sqlite_database_files(db_url)?;

    emit_init_progress(&progress, &asset_path.display().to_string(), "connecting");
    eprintln!("init: connecting database {db_url}");
    let db = connect_db(db_url).await?;
    emit_init_progress(&progress, &asset_path.display().to_string(), "importing");
    eprintln!("init: importing all CVEs; schema will be rebuilt before insert");
    ingest_zip_with_progress(
        &db,
        "all",
        &asset_path,
        IngestMode::ReplaceAll,
        args.max_chunks,
        false,
        progress,
    )
    .await;
    db.close()
        .await
        .map_err(|err| format!("failed to close database: {err}"))?;
    if downloaded_asset && !args.keep {
        remove_downloaded_zip(&asset_path)?;
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

pub async fn run_default(db_url: &str) -> Result<(), String> {
    run(db_url, Args::default()).await
}

pub async fn run_default_with_progress(
    db_url: &str,
    progress: IngestProgressCallback,
) -> Result<(), String> {
    run_with_progress(db_url, Args::default(), Some(progress)).await
}

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
