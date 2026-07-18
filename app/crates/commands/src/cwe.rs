use super::common::{DEFAULT_LIMIT, connect_sqlx_db, print_json};

/// CLI arguments for `qanvuli cwe`.
#[derive(Debug, clap::Args)]
pub struct Args {
    #[arg(value_name = "CWE")]
    cwe: String,
    #[arg(long)]
    include_rejected: bool,
}

/// Runs a CWE search and prints matching CVE summaries as JSON.
pub async fn run(db_url: &str, args: Args) -> Result<(), String> {
    let db = connect_sqlx_db(db_url).await?;
    db.check()
        .await
        .map_err(|error| format!("database rebuild required or check failed: {error}"))?;
    let cves = db
        .search_cves_by_cwes(
            &[args.cwe],
            args.include_rejected,
            i64::try_from(DEFAULT_LIMIT).unwrap_or(i64::MAX),
            0,
        )
        .await
        .map_err(|error| format!("failed to search CWE: {error}"))?;

    print_json(&cves)?;
    db.close()
        .await
        .map_err(|error| format!("failed to close database: {error}"))?;
    Ok(())
}
