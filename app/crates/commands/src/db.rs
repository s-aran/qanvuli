use super::common::{connect_sqlx_db, print_json};
use std::time::Instant;

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
    /// Run a bounded routine health check; use --full for exhaustive scans.
    Check(CheckArgs),
    /// Rebuild derived CVE and OSV search indexes, then verify them.
    RebuildSearch,
}

#[derive(Debug, clap::Args)]
struct CheckArgs {
    /// Run expensive SQLite, foreign-key, and native FTS integrity scans.
    #[arg(long)]
    full: bool,
}

/// Runs a database inspection subcommand.
pub async fn run(db_url: &str, args: Args) -> Result<(), String> {
    let db = connect_sqlx_db(db_url).await?;
    match args.command {
        Command::Status => {
            db.check_schema()
                .await
                .map_err(|error| format!("database rebuild required or check failed: {error}"))?;
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
            status["database_url"] = serde_json::json!(super::common::redact_database_url(db_url));
            if let Some(path) = super::common::database::sqlite_file_path(db_url) {
                let resolved = if path.is_absolute() {
                    path
                } else {
                    std::env::current_dir()
                        .map_err(|error| format!("failed to resolve database path: {error}"))?
                        .join(path)
                };
                status["database_path"] = serde_json::json!(resolved.display().to_string());
            }
            print_json(&status)?;
        }
        Command::Check(check_args) => {
            db.check()
                .await
                .map_err(|error| format!("database check failed: {error}"))?;
            if check_args.full {
                run_full_check(&db).await?;
            }
            print_json(&serde_json::json!({
                "ok": true,
                "mode": if check_args.full { "full" } else { "quick" },
                "checks": {
                    "schema": "ok",
                    "sqlite": "ok",
                    "foreign_keys_enabled": true,
                    "search": "ok"
                }
            }))?;
        }
        Command::RebuildSearch => {
            db.check_required_schema()
                .await
                .map_err(|error| format!("database rebuild required or check failed: {error}"))?;
            db.rebuild_search()
                .await
                .map_err(|error| format!("failed to rebuild search indexes: {error}"))?;
            db.check_schema()
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

async fn run_full_check(db: &qanvuli_core::database::SqlxDatabase) -> Result<(), String> {
    let stages = [
        "checking SQLite file integrity",
        "checking foreign keys",
        "checking CVE search data",
        "checking OSV search data",
    ];
    for (index, label) in stages.iter().enumerate() {
        eprintln!("db check: [{}/4] {label}...", index + 1);
        let started = Instant::now();
        match index {
            0 => db.check_full_sqlite().await,
            1 => db.check_full_foreign_keys().await,
            2 => db.check_full_cve_search().await,
            3 => db.check_full_osv_search().await,
            _ => unreachable!(),
        }
        .map_err(|error| format!("database full check failed during {label}: {error}"))?;
        eprintln!(
            "db check: [{}/4] completed in {:.3}s",
            index + 1,
            started.elapsed().as_secs_f64()
        );
    }
    Ok(())
}
