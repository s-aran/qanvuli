use clap::{CommandFactory, Parser, Subcommand};
use qanvuli_app_commands::common::DEFAULT_DB_CONNECTION_STRING;

fn main() {
    if let Err(err) = run() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    qanvuli_utils::init_tls_provider();

    let cli = Cli::parse();
    let db_url = cli.db_url();
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
            Command::Cwe(args) => qanvuli_app_commands::cwe::run(&db_url, args).await,
            Command::Search(args) => qanvuli_app_commands::search::run(&db_url, args).await,
            Command::Tui(args) => qanvuli_app_tui::run(&db_url, args).await,
            Command::Sbom(args) => qanvuli_app_commands::sbom::run(&db_url, args).await,
        }
    })
}

#[derive(Debug, Parser)]
#[command(
    name = "qanvuli-app",
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
    Init(qanvuli_app_commands::init::Args),
    /// Apply the latest delta CVE zip to the DB.
    Update(qanvuli_app_commands::update::Args),
    /// Download a CVE zip only. It does not touch the DB.
    DownloadCve(qanvuli_app_commands::download_cve::Args),
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
