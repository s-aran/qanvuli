use super::common::{
    IngestProgressCallback, OSV_SOURCE_PREFIX_HELP, OsvImportSelection,
    apply_delta_updates_with_progress, connect_db, rebuild_graph_and_report,
    report_enrichment_source_status, sync_all_enrichment_sources_after_update,
};
use std::path::PathBuf;

/// CLI arguments for `qanvuli update`.
#[derive(Debug, Default, clap::Args)]
#[command(after_help = OSV_SOURCE_PREFIX_HELP)]
pub struct Args {
    #[arg(long, value_name = "PATH")]
    zip: Option<PathBuf>,
    #[arg(long, value_name = "N")]
    max_chunks: Option<usize>,
    #[arg(long)]
    keep: bool,
    #[arg(long)]
    osv_all: bool,
    #[arg(long = "osv-source", value_name = "PREFIX", hide = true)]
    osv_prefixes: Vec<String>,
}

/// Applies CVE deltas, refreshes enrichment sources, and rebuilds the graph.
pub async fn run(db_url: &str, args: Args) -> Result<(), String> {
    run_with_progress(db_url, args, None).await
}

async fn run_with_progress(
    db_url: &str,
    args: Args,
    progress: Option<IngestProgressCallback>,
) -> Result<(), String> {
    eprintln!("update: connecting database {db_url}");
    let db = connect_db(db_url).await?;
    eprintln!("update: applying schema migrations");
    db.initialize_schema()
        .await
        .map_err(|err| format!("failed to initialize schema: {err}"))?;

    let applied =
        apply_delta_updates_with_progress(&db, args.zip, args.max_chunks, args.keep, progress)
            .await?;
    eprintln!("update: applied {} delta archive(s)", applied.len());
    let osv_additions = OsvImportSelection::update_additions(args.osv_all, &args.osv_prefixes);
    sync_all_enrichment_sources_after_update(&db, "update", osv_additions.as_ref()).await?;
    rebuild_graph_and_report(&db, "update").await?;
    report_enrichment_source_status(&db, "update").await?;
    db.close()
        .await
        .map_err(|err| format!("failed to close database: {err}"))?;
    Ok(())
}

/// Runs update with default CLI arguments.
pub async fn run_default(db_url: &str) -> Result<(), String> {
    run(db_url, Args::default()).await
}

/// Runs default update and reports progress through the callback.
pub async fn run_default_with_progress(
    db_url: &str,
    progress: IngestProgressCallback,
) -> Result<(), String> {
    run_with_progress(db_url, Args::default(), Some(progress)).await
}

/// Runs default update with progress and optional archive retention.
pub async fn run_default_with_progress_and_keep(
    db_url: &str,
    progress: IngestProgressCallback,
    keep: bool,
) -> Result<(), String> {
    run_with_progress(
        db_url,
        Args {
            keep,
            ..Args::default()
        },
        Some(progress),
    )
    .await
}
