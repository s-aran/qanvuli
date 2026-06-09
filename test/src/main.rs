mod subcommands;

use clap::{CommandFactory, Parser, Subcommand};
use subcommands::common::DEFAULT_DB_CONNECTION_STRING;

fn main() {
    if let Err(err) = run() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let cli = Cli::parse();
    let db_url = cli.db_url();
    let command = cli.command.unwrap_or(Command::Help);

    if matches!(command, Command::Help) {
        print_help();
        return Ok(());
    }
    if matches!(command, Command::Mcp) {
        return subcommands::mcp::run(db_url);
    }

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| format!("failed to build tokio runtime: {err}"))?;

    runtime.block_on(async {
        match command {
            Command::Help | Command::Mcp => Ok(()),
            Command::Init(args) => subcommands::init::run(&db_url, args).await,
            Command::Update(args) => subcommands::update::run(&db_url, args).await,
            Command::DownloadCve(args) => subcommands::download_cve::run(args).await,
            Command::Search(args) => subcommands::search::run(&db_url, args).await,
            Command::Sbom(args) => subcommands::sbom::run(&db_url, args).await,
        }
    })
}

#[derive(Debug, Parser)]
#[command(
    name = "qanvuli-test",
    version,
    about = "CVE DB maintenance and search tool",
    disable_help_subcommand = true
)]
struct Cli {
    #[arg(long = "db-url", global = true, value_name = "URL")]
    db_url: Option<String>,
    #[command(subcommand)]
    command: Option<Command>,
}

impl Cli {
    fn db_url(&self) -> String {
        self.db_url
            .clone()
            .or_else(|| std::env::var("QANVULI_DB_URL").ok())
            .unwrap_or_else(|| DEFAULT_DB_CONNECTION_STRING.to_owned())
    }
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Show help. This is also the default mode.
    Help,
    /// Initialize the DB from the latest all CVE zip, or only schema with --schema-only.
    ///
    /// Full initialization downloads and imports the all-CVE archive, so it can take a while.
    Init(subcommands::init::Args),
    /// Apply the latest delta CVE zip to the DB.
    Update(subcommands::update::Args),
    /// Download a CVE zip only. It does not touch the DB.
    DownloadCve(subcommands::download_cve::Args),
    /// Search existing CVE DB records.
    Search(subcommands::search::Args),
    /// Read a GitHub SBOM JSON and report matching CVEs.
    Sbom(subcommands::sbom::Args),
    /// Run the MCP server over stdio.
    Mcp,
}

fn print_help() {
    let mut command = Cli::command();
    command.print_help().expect("failed to print help");
    println!();
}

#[cfg(test)]
mod tests {
    use qanvuli_db::{CveActiveModels, CveDatabase};
    use qanvuli_models::parse_json_with_raw;

    const CNA_CVE_JSON: &str = r#"{
        "dataType": "CVE_RECORD",
        "dataVersion": "5.1.0",
        "cveMetadata": {
            "cveId": "CVE-2024-1000",
            "assignerOrgId": "00000000-0000-4000-8000-000000000000",
            "state": "PUBLISHED",
            "serial": 7,
            "datePublished": "2024-02-01T00:00:00Z",
            "dateUpdated": "2024-02-02T00:00:00Z"
        },
        "containers": {
            "cna": {
                "providerMetadata": {
                    "orgId": "00000000-0000-4000-8000-000000000000",
                    "shortName": "example-cna"
                },
                "title": "CNA sourced CVE",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "CNA description stored in DB."
                    }
                ],
                "affected": [
                    {
                        "vendor": "Example Vendor",
                        "product": "Example Product"
                    }
                ],
                "metrics": [
                    {
                        "cvssV3_1": {
                            "attackComplexity": "LOW",
                            "attackVector": "LOCAL",
                            "availabilityImpact": "HIGH",
                            "baseScore": 6,
                            "baseSeverity": "MEDIUM",
                            "confidentialityImpact": "HIGH",
                            "integrityImpact": "NONE",
                            "privilegesRequired": "HIGH",
                            "scope": "UNCHANGED",
                            "userInteraction": "NONE",
                            "vectorString": "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:H",
                            "version": "3.1"
                        },
                        "format": "CVSS",
                        "scenarios": [
                            {
                                "lang": "en",
                                "value": "GENERAL"
                            }
                        ]
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "lang": "en",
                                "cweId": "CWE-79",
                                "description": "Cross-site Scripting"
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "https://example.com/advisory"
                    }
                ]
            }
        },
        "x_testRawField": {
            "kept": true
        }
    }"#;

    #[test]
    fn test_db() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        runtime.block_on(async {
            let db = CveDatabase::connect("sqlite::memory:").await.unwrap();
            db.initialize_schema().await.unwrap();

            let raw_record = parse_json_with_raw(CNA_CVE_JSON).unwrap();
            let expected_raw_json = raw_record.raw_json().clone();
            let models = CveActiveModels::from(raw_record);

            db.upsert_cve(models.cve).await.unwrap();
            db.replace_cve_children(
                "CVE-2024-1000",
                models.cvss_rows,
                models.affected_rows,
                models.cwe_rows,
            )
            .await
            .unwrap();

            let found = db.find_cve_by_id("CVE-2024-1000").await.unwrap().unwrap();
            assert_eq!(found.cve_id, "CVE-2024-1000");
            assert_eq!(found.state, "PUBLISHED");
            assert_eq!(found.published_at, "2024-02-01T00:00:00+00:00");
            assert_eq!(found.updated_at, "2024-02-02T00:00:00+00:00");
            assert_eq!(found.serial, 7);
            assert_eq!(found.title, "CNA sourced CVE");
            assert_eq!(
                found.description_en.as_deref(),
                Some("CNA description stored in DB.")
            );
            assert_eq!(found.raw_json, expected_raw_json);
            assert_eq!(
                found.raw_json["containers"]["cna"]["providerMetadata"]["shortName"],
                "example-cna"
            );
            assert_eq!(found.raw_json["x_testRawField"]["kept"], true);

            let all = db.get_all().await.unwrap();
            assert_eq!(all.len(), 1);

            let by_product = db
                .search_cves_by_vendor_product(
                    Some("Example Vendor"),
                    Some("Example Product"),
                    10,
                    0,
                )
                .await
                .unwrap();
            assert_eq!(by_product.len(), 1);

            let by_cwe = db
                .search_cves_by_cwe(&["CWE-79".to_owned()], 10, 0)
                .await
                .unwrap();
            assert_eq!(by_cwe.len(), 1);
        });
    }
}
