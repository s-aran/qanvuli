use clap::{CommandFactory, Parser, Subcommand};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use qanvuli_app_commands::common::{
    IngestProgress, IngestProgressCallback, default_db_connection_string,
};
use std::ffi::OsString;
use std::io::IsTerminal;
use std::sync::{Arc, Mutex};

fn main() {
    qanvuli_utils::logging::init();
    if let Err(err) = run() {
        qanvuli_utils::logging::stderr(format_args!("{err}"));
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    qanvuli_core::runtime::init_tls_provider();

    let cli = Cli::parse_from(normalize_osv_prefix_flags(std::env::args_os())?);
    if cli.version {
        print_version();
        return Ok(());
    }
    let _pretty = cli.pretty;

    let db_url = cli.db_url()?;
    let command = cli.command.unwrap_or(Command::Help);

    if matches!(command, Command::Help) {
        print_help()?;
        return Ok(());
    }
    #[cfg(feature = "mcp")]
    if matches!(command, Command::Mcp) {
        return qanvuli_app_mcp::run(db_url);
    }

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| format!("failed to build tokio runtime: {err}"))?;

    runtime.block_on(async {
        match command {
            Command::Help => Ok(()),
            Command::Init(args) => {
                if args.use_progress() {
                    let display = CliProgress::new("init", args.download_targets());
                    let silence = qanvuli_utils::logging::suppress();
                    let result = qanvuli_app_commands::init::run_with_cli_progress(
                        &db_url,
                        args,
                        display.callback(),
                    )
                    .await;
                    drop(silence);
                    display.finish(&result);
                    result
                } else {
                    qanvuli_app_commands::init::run(&db_url, args).await
                }
            }
            Command::Update(args) => {
                if args.use_progress() {
                    let display = CliProgress::new("update", args.download_targets());
                    let silence = qanvuli_utils::logging::suppress();
                    let result = qanvuli_app_commands::update::run_with_cli_progress(
                        &db_url,
                        args,
                        display.callback(),
                    )
                    .await;
                    drop(silence);
                    display.finish(&result);
                    result
                } else {
                    qanvuli_app_commands::update::run(&db_url, args).await
                }
            }
            Command::DownloadCve(args) => qanvuli_app_commands::download_cve::run(args).await,
            Command::Graph(args) => qanvuli_app_commands::graph::run(&db_url, args).await,
            Command::Query(args) => qanvuli_app_commands::query::run(&db_url, args).await,
            Command::Db(args) => qanvuli_app_commands::db::run(&db_url, args).await,
            Command::Cwe(args) => qanvuli_app_commands::cwe::run(&db_url, args).await,
            Command::Capec(args) => qanvuli_app_commands::capec::run(&db_url, args).await,
            Command::Search(args) => qanvuli_app_commands::search::run(&db_url, args).await,
            #[cfg(feature = "tui")]
            Command::Tui(args) => qanvuli_app_tui::run(&db_url, args).await,
            Command::Sbom(args) => qanvuli_app_commands::sbom::run(&db_url, args).await,
            #[cfg(feature = "mcp")]
            Command::Mcp => Ok(()),
        }
    })
}

struct CliProgress {
    operation: &'static str,
    progress: Arc<MultiProgress>,
    active: Arc<Mutex<ActiveProgress>>,
}

struct ActiveProgress {
    bar: ProgressBar,
    task: Option<String>,
}

impl CliProgress {
    fn new(operation: &'static str, download_targets: Vec<String>) -> Self {
        let progress = Arc::new(MultiProgress::new());
        if download_targets.is_empty() {
            let _ = progress.println(format!("{operation}: no remote downloads"));
        } else {
            let _ = progress.println(format!(
                "{operation}: downloads {}",
                download_targets.join(", ")
            ));
        }
        let bar = progress.add(ProgressBar::new_spinner());
        bar.set_style(spinner_style());
        bar.set_message(format!("{operation}: starting"));
        bar.enable_steady_tick(std::time::Duration::from_millis(80));
        Self {
            operation,
            progress,
            active: Arc::new(Mutex::new(ActiveProgress { bar, task: None })),
        }
    }

    fn callback(&self) -> IngestProgressCallback {
        let progress_group = self.progress.clone();
        let active = self.active.clone();
        Arc::new(move |progress: IngestProgress| {
            let task = format!("{}: {}", progress.label, progress.phase);
            let Ok(mut active) = active.lock() else {
                return;
            };
            if active.task.as_deref() != Some(&task) {
                if let Some(previous) = active.task.take() {
                    active.bar.finish_with_message(format!("✓ {previous}"));
                    active.bar = progress_group.add(ProgressBar::new_spinner());
                    active
                        .bar
                        .enable_steady_tick(std::time::Duration::from_millis(80));
                }
                active.task = Some(task.clone());
            }
            if progress.total_files > 0 {
                active.bar.set_length(progress.total_files as u64);
                active.bar.set_position(progress.written_files as u64);
                active.bar.set_style(
                    ProgressStyle::with_template(
                        "{spinner:.cyan} {msg} [{bar:38.cyan/blue}] {pos}/{len} [{elapsed_precise}]",
                    )
                    .expect("valid progress bar template")
                    .progress_chars("━━╸"),
                );
            } else {
                active.bar.set_style(spinner_style());
            }
            active.bar.set_message(task);
        })
    }

    fn finish(&self, result: &Result<(), String>) {
        let Ok(mut active) = self.active.lock() else {
            return;
        };
        let task = active
            .task
            .take()
            .unwrap_or_else(|| format!("{}: starting", self.operation));
        match result {
            Ok(()) => {
                active.bar.finish_with_message(format!("✓ {task}"));
                let _ = self
                    .progress
                    .println(format!("✓ {} completed", self.operation));
            }
            Err(_) => {
                active.bar.abandon_with_message(format!("✗ {task}"));
                let _ = self
                    .progress
                    .println(format!("✗ {} failed", self.operation));
            }
        }
    }
}

fn spinner_style() -> ProgressStyle {
    ProgressStyle::with_template("{spinner:.cyan} {msg}  [{elapsed_precise}]")
        .expect("valid progress spinner template")
        .tick_chars("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏ ")
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
    #[arg(
        long = "db-url",
        global = true,
        value_name = "URL",
        help = "Database URL (default: ./db.sqlite in the current working directory)"
    )]
    db_url: Option<String>,
    #[arg(long, global = true, action = clap::ArgAction::SetTrue)]
    pretty: bool,
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
    /// Show help.
    Help,
    /// Build a replacement database from current vulnerability feeds.
    ///
    /// Full initialization downloads and imports the all-CVE archive, so it can take a while.
    Init(qanvuli_app_commands::init::Args),
    /// Apply CVE deltas and refresh enrichment feeds.
    Update(qanvuli_app_commands::update::Args),
    /// Download a CVE archive without changing the database.
    DownloadCve(qanvuli_app_commands::download_cve::Args),
    /// Rebuild cross-source identifier relationships.
    Graph(qanvuli_app_commands::graph::Args),
    /// Query identifiers, packages, and enrichment data.
    Query(qanvuli_app_commands::query::Args),
    /// Inspect and maintain the database.
    Db(qanvuli_app_commands::db::Args),
    /// Search the CWE catalog.
    Cwe(qanvuli_app_commands::cwe::Args),
    /// Search the CAPEC catalog.
    Capec(qanvuli_app_commands::capec::Args),
    /// Search CVE and OSV records.
    Search(qanvuli_app_commands::search::Args),
    /// Open the terminal UI.
    #[cfg(feature = "tui")]
    Tui(qanvuli_app_tui::Args),
    /// Scan a GitHub SBOM with local vulnerability data.
    Sbom(qanvuli_app_commands::sbom::Args),
    /// Run the MCP server over stdio.
    #[cfg(feature = "mcp")]
    Mcp,
}

fn print_help() -> Result<(), String> {
    let mut command = Cli::command();
    let help = command.render_help();
    qanvuli_utils::logging::stdout(format_args!("{}", help.to_string().trim_end()));
    Ok(())
}

fn print_version() {
    if can_show_emoji() {
        qanvuli_utils::logging::stdout(format_args!(
            "🐟 {} 🍣️ v{}",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION")
        ));
    } else {
        qanvuli_utils::logging::stdout(format_args!(
            "{} v{}",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION")
        ));
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
        if value == "--osv-all" || value == "--osv-refresh-all" {
            normalized.push(arg);
            continue;
        }
        if value == "--osv-full-snapshot" {
            return Err("--osv-full-snapshot was renamed to --osv-refresh-all because it does not infer deletions from missing snapshot entries".to_owned());
        }
        if value == "--osv-prefix" || value.starts_with("--osv-prefix=") {
            return Err("use --osv-<prefix>, for example --osv-ghsa or --osv-pysec".to_owned());
        }
        if value == "--osv-source" || value.starts_with("--osv-source=") {
            return Err(
                "use --osv-<prefix>, for example --osv-ghsa or --osv-pysec; --osv-source is internal"
                    .to_owned(),
            );
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn osv_refresh_all_is_a_real_option_not_a_dynamic_source_prefix() {
        let normalized = normalize_osv_prefix_flags(
            ["qanvuli", "update", "--osv-refresh-all"]
                .into_iter()
                .map(OsString::from),
        )
        .unwrap();
        assert_eq!(
            normalized,
            ["qanvuli", "update", "--osv-refresh-all"].map(OsString::from)
        );
        Cli::try_parse_from(normalized).unwrap();
    }

    #[test]
    fn removed_osv_full_snapshot_name_is_rejected() {
        let error = normalize_osv_prefix_flags(
            ["qanvuli", "update", "--osv-full-snapshot"]
                .into_iter()
                .map(OsString::from),
        )
        .unwrap_err();
        assert!(error.contains("--osv-refresh-all"));
    }

    #[test]
    fn internal_osv_source_flag_is_rejected_but_dynamic_prefix_is_accepted() {
        let error = normalize_osv_prefix_flags(
            ["qanvuli", "update", "--osv-source", "pysec"]
                .into_iter()
                .map(OsString::from),
        )
        .unwrap_err();
        assert!(error.contains("--osv-<prefix>"));

        let normalized = normalize_osv_prefix_flags(
            ["qanvuli", "update", "--osv-pysec"]
                .into_iter()
                .map(OsString::from),
        )
        .unwrap();
        Cli::try_parse_from(normalized).unwrap();
    }
}
