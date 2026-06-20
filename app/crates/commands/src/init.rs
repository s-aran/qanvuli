use super::common::{
    IngestMode, IngestProgress, IngestProgressCallback, ReleaseAssetKind, connect_db,
    download_latest_asset, ingest_zip_with_progress, reset_sqlite_database_files,
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
}

impl Default for Args {
    fn default() -> Self {
        Self {
            schema_only: false,
            rebuild: false,
            zip: None,
            max_chunks: None,
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

    let asset_path = if let Some(zip) = args.zip {
        emit_init_progress(&progress, &zip.display().to_string(), "using local zip");
        zip
    } else {
        emit_init_progress(&progress, "-", "downloading");
        download_latest_asset(ReleaseAssetKind::All).await?
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
