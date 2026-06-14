use super::common::{
    IngestMode, ReleaseAssetKind, connect_db, download_latest_asset, ingest_zip,
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
}

pub async fn run(db_url: &str, args: Args) -> Result<(), String> {
    if args.schema_only {
        eprintln!("init: connecting database {db_url}");
        let db = connect_db(db_url).await?;
        if args.rebuild {
            eprintln!("init: rebuilding schema");
            db.rebuild_schema()
                .await
                .map_err(|err| format!("failed to rebuild schema: {err}"))?;
        } else {
            eprintln!("init: applying schema migrations");
            db.initialize_schema()
                .await
                .map_err(|err| format!("failed to initialize schema: {err}"))?;
        }
        println!("initialized schema: {db_url}");
        db.close()
            .await
            .map_err(|err| format!("failed to close database: {err}"))?;
        return Ok(());
    }

    let asset_path = if let Some(zip) = args.zip {
        zip
    } else {
        download_latest_asset(ReleaseAssetKind::All).await?
    };

    reset_sqlite_database_files(db_url)?;

    eprintln!("init: connecting database {db_url}");
    let db = connect_db(db_url).await?;
    eprintln!("init: importing all CVEs; schema will be rebuilt before insert");
    ingest_zip(
        &db,
        "all",
        &asset_path,
        IngestMode::ReplaceAll,
        args.max_chunks,
    )
    .await;
    db.close()
        .await
        .map_err(|err| format!("failed to close database: {err}"))?;
    Ok(())
}
