use clap::{CommandFactory, Parser, Subcommand};
use qanvuli_app_commands::common::default_db_connection_string;
use std::ffi::OsString;
use std::io::IsTerminal;

fn main() {
    if let Err(err) = run() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    qanvuli_utils::init_tls_provider();

    let cli = Cli::parse_from(normalize_osv_prefix_flags(std::env::args_os())?);
    if cli.version {
        print_version();
        return Ok(());
    }

    let db_url = cli.db_url()?;
    let command = cli.command.unwrap_or(Command::Help);

    if matches!(command, Command::Help) {
        print_help();
        return Ok(());
    }
    if matches!(command, Command::Mcp) {
        return qanvuli_app_mcp::run(db_url);
    }

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| format!("failed to build tokio runtime: {err}"))?;

    runtime.block_on(async {
        match command {
            Command::Help | Command::Mcp => Ok(()),
            Command::Init(args) => qanvuli_app_commands::init::run(&db_url, args).await,
            Command::Update(args) => qanvuli_app_commands::update::run(&db_url, args).await,
            Command::DownloadCve(args) => qanvuli_app_commands::download_cve::run(args).await,
            Command::Graph(args) => qanvuli_app_commands::graph::run(&db_url, args).await,
            Command::Query(args) => qanvuli_app_commands::query::run(&db_url, args).await,
            Command::Db(args) => qanvuli_app_commands::db::run(&db_url, args).await,
            Command::Cwe(args) => qanvuli_app_commands::cwe::run(&db_url, args).await,
            Command::Search(args) => qanvuli_app_commands::search::run(&db_url, args).await,
            Command::Tui(args) => qanvuli_app_tui::run(&db_url, args).await,
            Command::Sbom(args) => qanvuli_app_commands::sbom::run(&db_url, args).await,
        }
    })
}

#[derive(Debug, Parser)]
#[command(
    name = "qanvuli",
    about = "CVE DB maintenance and search tool",
    disable_help_subcommand = true,
    disable_version_flag = true
)]
struct Cli {
    #[arg(long, global = true, action = clap::ArgAction::SetTrue)]
    version: bool,
    #[arg(long = "db-url", global = true, value_name = "URL")]
    db_url: Option<String>,
    #[command(subcommand)]
    command: Option<Command>,
}

impl Cli {
    fn db_url(&self) -> Result<String, String> {
        self.db_url
            .clone()
            .or_else(|| std::env::var("QANVULI_DB_URL").ok())
            .map(Ok)
            .unwrap_or_else(default_db_connection_string)
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Subcommand)]
enum Command {
    /// Show help. This is also the default mode.
    Help,
    /// Initialize the DB from the latest all CVE zip, or only schema with --schema-only.
    ///
    /// Full initialization downloads and imports the all-CVE archive, so it can take a while.
    Init(qanvuli_app_commands::init::Args),
    /// Apply the latest delta CVE zip to the DB.
    Update(qanvuli_app_commands::update::Args),
    /// Download a CVE zip only. It does not touch the DB.
    DownloadCve(qanvuli_app_commands::download_cve::Args),
    /// Build or rebuild cross-source vulnerability identifier graph data.
    Graph(qanvuli_app_commands::graph::Args),
    /// Run cross-source and enriched vulnerability queries.
    Query(qanvuli_app_commands::query::Args),
    /// Inspect local database status.
    Db(qanvuli_app_commands::db::Args),
    /// Search CVEs by one CWE ID, such as CWE-42 or 42.
    Cwe(qanvuli_app_commands::cwe::Args),
    /// Search existing CVE DB records.
    Search(qanvuli_app_commands::search::Args),
    /// Open an interactive terminal UI for free-word CVE search.
    Tui(qanvuli_app_tui::Args),
    /// Read a GitHub SBOM JSON and report matching CVEs.
    Sbom(qanvuli_app_commands::sbom::Args),
    /// Run the MCP server over stdio.
    Mcp,
}

fn print_help() {
    let mut command = Cli::command();
    command.print_help().expect("failed to print help");
    println!();
}

fn print_version() {
    if can_show_emoji() {
        println!(
            "🐟 {} 🍣️ v{}",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION")
        );
    } else {
        println!("{} v{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
    }
}

fn normalize_osv_prefix_flags<I>(args: I) -> Result<Vec<OsString>, String>
where
    I: IntoIterator<Item = OsString>,
{
    let mut normalized = Vec::new();
    for arg in args {
        let Some(value) = arg.to_str() else {
            normalized.push(arg);
            continue;
        };
        if value == "--osv-all" {
            normalized.push(arg);
            continue;
        }
        if value == "--osv-prefix" || value.starts_with("--osv-prefix=") {
            return Err("use --osv-<prefix>, for example --osv-ghsa or --osv-pysec".to_owned());
        }
        if let Some(prefix) = value.strip_prefix("--osv-") {
            if prefix.is_empty() || prefix.starts_with('-') {
                return Err(format!("invalid OSV source prefix flag `{value}`"));
            }
            if prefix.contains('=') {
                return Err(format!(
                    "OSV source prefix flag `{value}` does not take a value; use --osv-{prefix}"
                ));
            }
            normalized.push(OsString::from("--osv-source"));
            normalized.push(OsString::from(prefix));
            continue;
        }
        normalized.push(arg);
    }
    Ok(normalized)
}

fn can_show_emoji() -> bool {
    std::io::stdout().is_terminal()
        && !std::env::var("CI").is_ok_and(|value| !value.is_empty() && value != "0")
        && !std::env::var("TERM").is_ok_and(|value| value == "dumb")
        && locale_is_utf8()
}

fn locale_is_utf8() -> bool {
    ["LC_ALL", "LC_CTYPE", "LANG"]
        .into_iter()
        .filter_map(|key| std::env::var(key).ok())
        .any(|value| {
            let value = value.to_ascii_uppercase();
            value.contains("UTF-8") || value.contains("UTF8")
        })
}
