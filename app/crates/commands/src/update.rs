use super::common::{apply_delta_updates, connect_db};
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

    let applied = apply_delta_updates(&db, args.zip, args.max_chunks).await?;
    eprintln!("update: applied {} delta archive(s)", applied.len());
    db.close()
        .await
        .map_err(|err| format!("failed to close database: {err}"))?;
    Ok(())
}
