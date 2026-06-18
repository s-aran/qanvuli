use super::common::{IngestProgressCallback, apply_delta_updates_with_progress, connect_db};
use std::path::PathBuf;

#[derive(Debug, clap::Args)]
pub struct Args {
    #[arg(long, value_name = "PATH")]
    zip: Option<PathBuf>,
    #[arg(long, value_name = "N")]
    max_chunks: Option<usize>,
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
        apply_delta_updates_with_progress(&db, args.zip, args.max_chunks, progress).await?;
    eprintln!("update: applied {} delta archive(s)", applied.len());
    db.close()
        .await
        .map_err(|err| format!("failed to close database: {err}"))?;
    Ok(())
}

pub async fn run_default(db_url: &str) -> Result<(), String> {
    run(
        db_url,
        Args {
            zip: None,
            max_chunks: None,
        },
    )
    .await
}

pub async fn run_default_with_progress(
    db_url: &str,
    progress: IngestProgressCallback,
) -> Result<(), String> {
    run_with_progress(
        db_url,
        Args {
            zip: None,
            max_chunks: None,
        },
        Some(progress),
    )
    .await
}
