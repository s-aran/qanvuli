use super::common::{DEFAULT_LIMIT, connect_db, print_json};

#[derive(Debug, clap::Args)]
pub struct Args {
    #[arg(value_name = "CWE")]
    cwe: String,
}

pub async fn run(db_url: &str, args: Args) -> Result<(), String> {
    let db = connect_db(db_url).await?;
    let cves = db
        .search_cve_summaries_by_cwe(&[args.cwe], DEFAULT_LIMIT, 0)
        .await
        .map_err(|err| format!("failed to search CWE: {err}"))?;

    print_json(&cves)?;
    db.close()
        .await
        .map_err(|err| format!("failed to close database: {err}"))?;
    Ok(())
}
