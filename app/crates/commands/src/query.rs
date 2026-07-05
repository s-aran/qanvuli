use super::common::{connect_db, print_json};

#[derive(Debug, clap::Args)]
pub struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, clap::Subcommand)]
enum Command {
    /// Resolve a CVE/GHSA/RUSTSEC/PYSEC/OSV identifier through the local alias graph.
    Resolve(IdArgs),
    /// Fetch one CVE with OSV/KEV/EPSS enrichment.
    EnrichedCve(IdArgs),
    /// Query OSV by package/version and attach CVE enrichment.
    Package(PackageArgs),
}

#[derive(Debug, clap::Args)]
struct IdArgs {
    #[arg(long)]
    id: String,
}

#[derive(Debug, clap::Args)]
struct PackageArgs {
    #[arg(long)]
    ecosystem: String,
    #[arg(long, alias = "package")]
    name: String,
    #[arg(long)]
    version: String,
    #[arg(long)]
    purl: Option<String>,
    #[arg(long)]
    enriched: bool,
}

pub async fn run(db_url: &str, args: Args) -> Result<(), String> {
    let db = connect_db(db_url).await?;
    db.initialize_schema()
        .await
        .map_err(|err| format!("failed to initialize schema: {err}"))?;
    match args.command {
        Command::Resolve(args) => {
            let result = db
                .resolve_identifier(&args.id)
                .await
                .map_err(|err| format!("failed to resolve identifier: {err}"))?;
            print_json(&result)?;
        }
        Command::EnrichedCve(args) => {
            let result = db
                .get_enriched_cve(&args.id)
                .await
                .map_err(|err| format!("failed to enrich CVE: {err}"))?;
            print_json(&result)?;
        }
        Command::Package(args) => {
            let result = db
                .query_package_enriched(
                    &args.ecosystem,
                    &args.name,
                    &args.version,
                    args.purl.as_deref(),
                )
                .await
                .map_err(|err| format!("failed to query package: {err}"))?;
            print_json(&result)?;
        }
    }
    db.close()
        .await
        .map_err(|err| format!("failed to close database: {err}"))?;
    Ok(())
}
