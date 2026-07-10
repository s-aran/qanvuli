use super::common::{connect_db, print_json};

/// CLI arguments for `qanvuli graph`.
#[derive(Debug, clap::Args)]
pub struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, clap::Subcommand)]
enum Command {
    /// Rebuild identifier nodes and alias edges from local CVE/OSV/KEV/EPSS tables.
    Rebuild,
}

/// Runs an identifier graph maintenance subcommand.
pub async fn run(db_url: &str, args: Args) -> Result<(), String> {
    let db = connect_db(db_url).await?;
    db.initialize_schema()
        .await
        .map_err(|err| format!("failed to initialize schema: {err}"))?;
    match args.command {
        Command::Rebuild => {
            let summary = db
                .rebuild_identifier_graph()
                .await
                .map_err(|err| format!("failed to rebuild graph: {err}"))?;
            print_json(&summary)?;
        }
    }
    db.close()
        .await
        .map_err(|err| format!("failed to close database: {err}"))?;
    Ok(())
}
