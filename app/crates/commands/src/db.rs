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
    /// Run a low-latency health check; use --scan or --full for database-wide scans.
    Check(CheckArgs),
    /// Rebuild derived CVE and OSV search indexes, then verify them.
    RebuildSearch,
}

#[derive(Debug, clap::Args)]
struct CheckArgs {
    /// Run SQLite quick_check and broader projection scans.
    #[arg(long, conflicts_with = "full")]
    scan: bool,
    /// Run expensive SQLite, foreign-key, and native FTS integrity scans.
    #[arg(long, conflicts_with = "scan")]
    full: bool,
}

/// Runs a database inspection subcommand.
pub async fn run(db_url: &str, args: Args) -> Result<(), String> {
    let db = connect_sqlx_db(db_url).await?;
    match args.command {
        Command::Status => {
            db.check_required_schema()
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
            if check_args.full {
                run_full_check(&db).await?;
            } else if check_args.scan {
                run_scan_check(&db).await?;
            } else {
                run_quick_check(&db).await?;
            }
            let mode = if check_args.full {
                "full"
            } else if check_args.scan {
                "scan"
            } else {
                "quick"
            };
            print_json(&check_report(mode))?;
        }
        Command::RebuildSearch => {
            db.check_required_schema()
                .await
                .map_err(|error| format!("database rebuild required or check failed: {error}"))?;
            db.rebuild_search()
                .await
                .map_err(|error| format!("failed to rebuild search indexes: {error}"))?;
            db.check_search_integrity_quick()
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

fn check_report(mode: &str) -> serde_json::Value {
    let (sqlite_status, sqlite_coverage, foreign_key_coverage, search_coverage) = match mode {
        "quick" => ("not_run", "none", "connection_setting", "sentinel"),
        "scan" => (
            "ok",
            "quick_check",
            "complete_correspondence",
            "fts_native_and_complete_correspondence",
        ),
        "full" => (
            "ok",
            "integrity_check",
            "complete_correspondence",
            "fts_native_and_complete_correspondence",
        ),
        _ => unreachable!("known check mode"),
    };
    serde_json::json!({
        "ok": true,
        "mode": mode,
        "checks": {
            "schema": { "status": "ok", "coverage": "full_schema_shape" },
            "sqlite": { "status": sqlite_status, "coverage": sqlite_coverage },
            "foreign_keys": { "status": "ok", "coverage": foreign_key_coverage },
            "search": { "status": "ok", "coverage": search_coverage }
        }
    })
}

async fn run_quick_check(db: &qanvuli_core::database::SqlxDatabase) -> Result<(), String> {
    eprintln!("db check: mode=quick");
    let started = Instant::now();
    eprintln!("db check: [1/1] validating schema and bounded search sentinels...");
    db.check()
        .await
        .map_err(|error| format!("database quick check failed: {error}"))?;
    eprintln!(
        "db check: [1/1] completed in {:.3}s",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

async fn run_scan_check(db: &qanvuli_core::database::SqlxDatabase) -> Result<(), String> {
    eprintln!("db check: mode=scan");
    let started = Instant::now();
    eprintln!("db check: [1/1] running quick_check and broader search scans...");
    db.check_scan()
        .await
        .map_err(|error| format!("database scan check failed: {error}"))?;
    eprintln!(
        "db check: [1/1] completed in {:.3}s",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

async fn run_full_check(db: &qanvuli_core::database::SqlxDatabase) -> Result<(), String> {
    let stages = [
        "validating schema",
        "checking SQLite file integrity",
        "checking foreign keys",
        "checking CVE search data",
        "checking OSV search data",
    ];
    eprintln!("db check: mode=full");
    for (index, label) in stages.iter().enumerate() {
        eprintln!("db check: [{}/5] {label}...", index + 1);
        let started = Instant::now();
        match index {
            0 => db.check_required_schema().await,
            1 => db.check_full_sqlite().await,
            2 => db.check_full_foreign_keys().await,
            3 => db.check_full_cve_search().await,
            4 => db.check_full_osv_search().await,
            _ => unreachable!(),
        }
        .map_err(|error| format!("database full check failed during {label}: {error}"))?;
        eprintln!(
            "db check: [{}/5] completed in {:.3}s",
            index + 1,
            started.elapsed().as_secs_f64()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_reports_describe_actual_mode_coverage() {
        let quick = check_report("quick");
        assert_eq!(quick["checks"]["sqlite"]["status"], "not_run");
        assert_eq!(quick["checks"]["search"]["coverage"], "sentinel");

        let scan = check_report("scan");
        assert_eq!(scan["checks"]["sqlite"]["coverage"], "quick_check");
        assert_eq!(
            scan["checks"]["search"]["coverage"],
            "fts_native_and_complete_correspondence"
        );

        let full = check_report("full");
        assert_eq!(full["checks"]["sqlite"]["coverage"], "integrity_check");
        assert_eq!(
            full["checks"]["foreign_keys"]["coverage"],
            "complete_correspondence"
        );
    }
}
