use super::common::{connect_database, print_json};

/// CLI arguments for `qanvuli graph`.
#[derive(Debug, clap::Args)]
pub struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, clap::Subcommand)]
enum Command {
    /// Rebuild derived typed identifier edges from normalized OSV relations.
    Rebuild,
}

/// Runs an identifier graph maintenance subcommand.
pub async fn run(db_url: &str, args: Args) -> Result<(), String> {
    let db = connect_database(db_url).await?;
    db.check_required_schema()
        .await
        .map_err(|error| format!("database rebuild required or check failed: {error}"))?;
    match args.command {
        Command::Rebuild => {
            db.rebuild_identifier_graph()
                .await
                .map_err(|error| format!("failed to rebuild graph: {error}"))?;
            print_json(&serde_json::json!({"ok": true}))?;
        }
    }
    db.close()
        .await
        .map_err(|error| format!("failed to close database: {error}"))?;
    Ok(())
}
