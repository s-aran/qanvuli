use super::common::{IngestProgressCallback, apply_delta_updates_with_progress, connect_db};
use std::path::PathBuf;

#[derive(Debug, clap::Args)]
pub struct Args {
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
    eprintln!("update: connecting database {db_url}");
    let db = connect_db(db_url).await?;
    eprintln!("update: applying schema migrations");
    db.initialize_schema()
        .await
        .map_err(|err| format!("failed to initialize schema: {err}"))?;

    let applied =
        apply_delta_updates_with_progress(&db, args.zip, args.max_chunks, args.keep, progress)
            .await?;
    eprintln!("update: applied {} delta archive(s)", applied.len());
    db.close()
        .await
        .map_err(|err| format!("failed to close database: {err}"))?;
    Ok(())
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
