use super::common::{IngestMode, ReleaseAssetKind, connect_db, download_latest_asset, ingest_zip};
use std::path::PathBuf;

#[derive(Debug, clap::Args)]
pub struct Args {
    #[arg(long, value_name = "PATH")]
    zip: Option<PathBuf>,
    #[arg(long, value_name = "N")]
    max_chunks: Option<usize>,
}

pub async fn run(db_url: &str, args: Args) -> Result<(), String> {
    eprintln!("update: connecting database {db_url}");
    let db = connect_db(db_url).await?;
    eprintln!("update: applying schema migrations");
    db.initialize_schema()
        .await
        .map_err(|err| format!("failed to initialize schema: {err}"))?;

    let asset_path = if let Some(zip) = args.zip {
        zip
    } else {
        download_latest_asset(ReleaseAssetKind::Delta).await?
    };

    ingest_zip(
        &db,
        "delta",
        &asset_path,
        IngestMode::Upsert,
        args.max_chunks,
    )
    .await;
    db.close()
        .await
        .map_err(|err| format!("failed to close database: {err}"))?;
    Ok(())
}
