use super::common::{DEFAULT_LIMIT, connect_database, print_json};

#[derive(Debug, clap::Args)]
#[command(group(
    clap::ArgGroup::new("selector")
        .args(["query", "id"])
        .multiple(false)
))]
pub struct Args {
    /// Text to search.
    #[arg(value_name = "QUERY", value_parser = catalog_query)]
    query: Option<String>,
    /// Return one CWE entry.
    #[arg(long, value_name = "CWE_ID")]
    id: Option<String>,
    /// Include this status. Repeat to include more.
    #[arg(long = "status", value_name = "STATUS")]
    statuses: Vec<String>,
    /// Include entries linked to this CAPEC.
    #[arg(long, value_name = "CAPEC_ID")]
    capec: Option<String>,
    /// Maximum number of results.
    #[arg(long)]
    limit: Option<u64>,
    /// Number of results to skip.
    #[arg(long)]
    offset: Option<u64>,
    /// Request detailed output for --id.
    #[arg(long, requires = "id")]
    detail: bool,
}

pub async fn run(db_url: &str, args: Args) -> Result<(), String> {
    let db = connect_database(db_url).await?;
    db.check_required_schema()
        .await
        .map_err(|error| format!("database rebuild required or check failed: {error}"))?;

    if let Some(id) = args.id {
        let id = parse_id(&id, "CWE")?;
        let entry = db
            .find_cwe_entry(id)
            .await
            .map_err(|error| format!("failed to fetch CWE-{id}: {error}"))?;
        print_json(&entry)?;
    } else {
        let statuses = if args.statuses.is_empty() {
            [
                "Stable",
                "Usable",
                "Draft",
                "Incomplete",
                "Obsolete",
                "Deprecated",
            ]
            .map(str::to_owned)
            .to_vec()
        } else {
            args.statuses
        };
        let capec_id = args
            .capec
            .as_deref()
            .map(|value| parse_id(value, "CAPEC"))
            .transpose()?;
        let offset = args.offset.unwrap_or_default();
        let requested = args.limit.unwrap_or(DEFAULT_LIMIT);
        let mut rows = db
            .search_cwe_entries_filtered(
                args.query.as_deref().unwrap_or_default(),
                requested.saturating_add(offset),
                &statuses,
                capec_id,
            )
            .await
            .map_err(|error| format!("failed to search CWE catalog: {error}"))?;
        let rows = rows
            .drain(offset.min(rows.len() as u64) as usize..)
            .take(requested as usize)
            .collect::<Vec<_>>();
        print_json(&rows)?;
    }
    db.close()
        .await
        .map_err(|error| format!("failed to close database: {error}"))
}

pub(crate) fn parse_id(value: &str, prefix: &str) -> Result<i32, String> {
    let upper = value.trim().to_ascii_uppercase();
    upper
        .strip_prefix(prefix)
        .unwrap_or(&upper)
        .trim_start_matches('-')
        .parse()
        .map_err(|error| format!("invalid {prefix} ID `{value}`: {error}"))
}

pub(crate) fn catalog_query(value: &str) -> Result<String, String> {
    let trimmed = value.trim();
    let upper = trimmed.to_ascii_uppercase();
    let numeric = trimmed.chars().all(|ch| ch.is_ascii_digit());
    let prefixed_id = ["CWE-", "CAPEC-"].iter().any(|prefix| {
        upper
            .strip_prefix(prefix)
            .is_some_and(|id| id.chars().all(|ch| ch.is_ascii_digit()))
    });
    if numeric || prefixed_id {
        Err("catalog IDs must be specified with --id".to_owned())
    } else {
        Ok(trimmed.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Command {
        #[command(flatten)]
        args: Args,
    }

    #[test]
    fn parses_prefixed_ids() {
        assert_eq!(parse_id("CWE-79", "CWE").unwrap(), 79);
        assert_eq!(parse_id("79", "CWE").unwrap(), 79);
        assert!(parse_id("CAPEC-1", "CWE").is_err());
    }

    #[test]
    fn detail_lookup_requires_id_flag() {
        assert!(Command::try_parse_from(["cwe", "CWE-79"]).is_err());
        assert!(Command::try_parse_from(["cwe", "--detail"]).is_err());
        assert!(Command::try_parse_from(["cwe", "--id", "79", "--detail"]).is_ok());
    }
}
