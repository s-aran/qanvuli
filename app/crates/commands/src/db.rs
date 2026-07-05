use super::common::{connect_db, print_json};

#[derive(Debug, clap::Args)]
pub struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, clap::Subcommand)]
enum Command {
    /// Return CVE and enrichment database status.
    Status,
}

pub async fn run(db_url: &str, args: Args) -> Result<(), String> {
    let db = connect_db(db_url).await?;
    db.initialize_schema()
        .await
        .map_err(|err| format!("failed to initialize schema: {err}"))?;
    match args.command {
        Command::Status => {
            let mut status = serde_json::to_value(
                db.database_status_enriched()
                    .await
                    .map_err(|err| format!("failed to read database status: {err}"))?,
            )
            .map_err(|err| format!("failed to encode database status: {err}"))?;
            status["source_sync"] = serde_json::to_value(
                db.source_sync_states()
                    .await
                    .map_err(|err| format!("failed to read source sync state: {err}"))?,
            )
            .map_err(|err| format!("failed to encode source sync state: {err}"))?;
            print_json(&status)?;
        }
    }
    db.close()
        .await
        .map_err(|err| format!("failed to close database: {err}"))?;
    Ok(())
}
