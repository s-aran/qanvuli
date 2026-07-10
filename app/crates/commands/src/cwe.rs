use super::common::{DEFAULT_LIMIT, connect_db, print_json};
use qanvuli_db::CveStateScope;

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
    let db = connect_db(db_url).await?;
    let state_scope = if args.include_rejected {
        CveStateScope::IncludeRejected
    } else {
        CveStateScope::PublishedOnly
    };
    let cves = db
        .search_cve_summaries_by_cwe_with_state_scope(&[args.cwe], state_scope, DEFAULT_LIMIT, 0)
        .await
        .map_err(|err| format!("failed to search CWE: {err}"))?;

    print_json(&cves)?;
    db.close()
        .await
        .map_err(|err| format!("failed to close database: {err}"))?;
    Ok(())
}
