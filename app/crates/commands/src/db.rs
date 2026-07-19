use super::common::{connect_sqlx_db, print_json};

/// CLI arguments for `qanvuli db`.
#[derive(Debug, clap::Args)]
pub struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, clap::Subcommand)]
enum Command {
    /// Return CVE and enrichment database status.
    Status,
    /// Verify SQLite, foreign keys, schema-derived search data, and FTS indexes.
    Check,
    /// Rebuild derived CVE and OSV search indexes, then verify them.
    RebuildSearch,
}

/// Runs a database inspection subcommand.
pub async fn run(db_url: &str, args: Args) -> Result<(), String> {
    let db = connect_sqlx_db(db_url).await?;
    db.check_schema()
        .await
        .map_err(|error| format!("database rebuild required or check failed: {error}"))?;
    match args.command {
        Command::Status => {
            let mut status = serde_json::to_value(
                db.database_status()
                    .await
                    .map_err(|error| format!("failed to read database status: {error}"))?,
            )
            .map_err(|error| format!("failed to encode database status: {error}"))?;
            status["source_sync"] = serde_json::to_value(
                db.source_sync_states()
                    .await
                    .map_err(|error| format!("failed to read source sync state: {error}"))?,
            )
            .map_err(|error| format!("failed to encode source sync state: {error}"))?;
            print_json(&status)?;
        }
        Command::Check => {
            db.check()
                .await
                .map_err(|error| format!("database check failed: {error}"))?;
            print_json(&serde_json::json!({"ok": true}))?;
        }
        Command::RebuildSearch => {
            db.rebuild_search()
                .await
                .map_err(|error| format!("failed to rebuild search indexes: {error}"))?;
            db.check()
                .await
                .map_err(|error| format!("search verification failed: {error}"))?;
            print_json(&serde_json::json!({"ok": true}))?;
        }
    }
    db.close()
        .await
        .map_err(|error| format!("failed to close database: {error}"))?;
    Ok(())
}
