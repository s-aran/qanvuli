use super::common::{connect_database, print_json};

/// CLI arguments for `qanvuli query`.
#[derive(Debug, clap::Args)]
pub struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, clap::Subcommand)]
enum Command {
    /// Resolve an identifier to its linked advisories.
    Resolve(IdArgs),
    /// Return a CVE with OSV, KEV, and EPSS data.
    EnrichedCve(IdArgs),
    /// Find advisories affecting a package version.
    Package(PackageArgs),
}

#[derive(Debug, clap::Args)]
struct IdArgs {
    /// CVE, GHSA, RustSec, PySEC, or OSV identifier.
    #[arg(long)]
    id: String,
}

#[derive(Debug, clap::Args)]
struct PackageArgs {
    /// OSV ecosystem name.
    #[arg(long)]
    ecosystem: String,
    /// Package name.
    #[arg(long)]
    name: String,
    /// Installed package version.
    #[arg(long)]
    version: String,
    /// Package URL used to refine matching.
    #[arg(long)]
    purl: Option<String>,
    /// Include CVE, KEV, and EPSS data.
    #[arg(long)]
    enriched: bool,
}

/// Runs cross-source identifier and package enrichment queries.
pub async fn run(db_url: &str, args: Args) -> Result<(), String> {
    match args.command {
        Command::Resolve(args) => {
            let db = connect_database(db_url).await?;
            db.check_required_schema()
                .await
                .map_err(|error| format!("database rebuild required or check failed: {error}"))?;
            let result = db
                .resolve_identifier(&args.id)
                .await
                .map_err(|error| format!("failed to resolve identifier: {error}"))?;
            print_json(&result)?;
            db.close()
                .await
                .map_err(|error| format!("failed to close database: {error}"))?;
        }
        Command::EnrichedCve(args) => {
            let db = connect_database(db_url).await?;
            db.check_required_schema()
                .await
                .map_err(|error| format!("database rebuild required or check failed: {error}"))?;
            let summary = db
                .find_cve_summary(&args.id)
                .await
                .map_err(|error| format!("failed to find CVE: {error}"))?;
            let detail = db
                .cve_detail(&args.id)
                .await
                .map_err(|error| format!("failed to enrich CVE: {error}"))?;
            print_json(&serde_json::json!({"summary": summary, "detail": detail}))?;
            db.close()
                .await
                .map_err(|error| format!("failed to close database: {error}"))?;
        }
        Command::Package(args) => {
            let db = connect_database(db_url).await?;
            db.check_required_schema()
                .await
                .map_err(|error| format!("database rebuild required or check failed: {error}"))?;
            let findings = db
                .query_osv_package_with_purl(
                    &args.ecosystem,
                    &args.name,
                    &args.version,
                    args.purl.as_deref(),
                )
                .await
                .map_err(|error| format!("failed to query package: {error}"))?;
            let confirmed_cve_ids = findings
                .iter()
                .filter(|finding| finding.status == "affected")
                .flat_map(|finding| finding.cve_ids.iter().cloned())
                .collect::<std::collections::BTreeSet<_>>();
            let enrichment = if args.enriched {
                let mut rows = Vec::with_capacity(confirmed_cve_ids.len());
                for cve_id in &confirmed_cve_ids {
                    rows.push(serde_json::json!({
                        "summary": db.find_cve_summary(cve_id).await.map_err(|error| format!("failed to load {cve_id}: {error}"))?,
                        "detail": db.cve_detail(cve_id).await.map_err(|error| format!("failed to enrich {cve_id}: {error}"))?,
                    }));
                }
                Some(rows)
            } else {
                None
            };
            let confirmed_count = findings
                .iter()
                .filter(|finding| finding.status == "affected")
                .count();
            print_json(&serde_json::json!({
                "vulnerable": confirmed_count > 0,
                "confirmed_count": confirmed_count,
                "candidate_count": findings.len() - confirmed_count,
                "findings": findings,
                "enrichment": enrichment,
            }))?;
            db.close()
                .await
                .map_err(|error| format!("failed to close database: {error}"))?;
        }
    }
    Ok(())
}
