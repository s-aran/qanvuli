use super::common::{ReleaseAssetKind, latest_asset};
use std::path::PathBuf;

/// CLI arguments for `qanvuli download-cve`.
#[derive(Debug, clap::Args)]
pub struct Args {
    /// CVE archive type.
    #[arg(long, value_enum, default_value_t = ReleaseAssetKind::Delta)]
    kind: ReleaseAssetKind,
    /// Destination directory.
    #[arg(long, value_name = "DIR", default_value = ".")]
    output_dir: PathBuf,
}

/// Downloads the selected CVE release archive and prints its local path.
pub async fn run(args: Args) -> Result<(), String> {
    let asset = latest_asset(args.kind).await?;
    std::fs::create_dir_all(&args.output_dir)
        .map_err(|err| format!("failed to create {}: {err}", args.output_dir.display()))?;
    let filename = asset
        .safe_file_name()
        .map_err(|err| format!("unsafe asset name {}: {err}", asset.name))?;
    let output_path = args.output_dir.join(filename);

    asset
        .download_to(&output_path)
        .await
        .map_err(|err| format!("failed to download {}: {err}", asset.name))?;
    println!("{}", output_path.display());
    Ok(())
}
