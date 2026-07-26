use qanvuli_core::database::CapecSearchFilters;

use super::{
    common::{DEFAULT_LIMIT, connect_database, print_json},
    cwe::{catalog_query, parse_id},
};

#[derive(Debug, clap::Args)]
#[command(group(
    clap::ArgGroup::new("selector")
        .args(["query", "id"])
        .multiple(false)
))]
pub struct Args {
    #[arg(value_name = "QUERY", value_parser = catalog_query)]
    query: Option<String>,
    #[arg(long, value_name = "CAPEC_ID")]
    id: Option<String>,
    #[arg(long = "status", value_name = "STATUS")]
    statuses: Vec<String>,
    #[arg(long = "type", value_name = "TYPE")]
    types: Vec<String>,
    #[arg(long, value_name = "CWE_ID")]
    cwe: Option<String>,
    #[arg(long)]
    limit: Option<u64>,
    #[arg(long)]
    offset: Option<u64>,
    #[arg(long, requires = "id")]
    detail: bool,
}

pub async fn run(db_url: &str, args: Args) -> Result<(), String> {
    let db = connect_database(db_url).await?;
    db.check_required_schema()
        .await
        .map_err(|error| format!("database rebuild required or check failed: {error}"))?;

    if let Some(id) = args.id {
        let id = parse_id(&id, "CAPEC")?;
        let detail = db
            .find_capec(id)
            .await
            .map_err(|error| format!("failed to fetch CAPEC-{id}: {error}"))?;
        if args.detail {
            print_json(&detail)?;
        } else {
            print_json(&detail.map(|detail| detail.entry))?;
        }
    } else {
        let rows = db
            .search_capec_entries(CapecSearchFilters {
                query: args.query,
                statuses: args.statuses,
                types: args.types,
                cwe_id: args
                    .cwe
                    .as_deref()
                    .map(|value| parse_id(value, "CWE"))
                    .transpose()?,
                limit: args.limit.unwrap_or(DEFAULT_LIMIT),
                offset: args.offset.unwrap_or_default(),
            })
            .await
            .map_err(|error| format!("failed to search CAPEC catalog: {error}"))?;
        print_json(&rows)?;
    }
    db.close()
        .await
        .map_err(|error| format!("failed to close database: {error}"))
}
