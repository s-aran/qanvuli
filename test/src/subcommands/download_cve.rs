use super::common::{ReleaseAssetKind, latest_asset};
use std::path::PathBuf;

#[derive(Debug, clap::Args)]
pub struct Args {
    #[arg(long, value_enum, default_value_t = ReleaseAssetKind::Delta)]
    kind: ReleaseAssetKind,
    #[arg(long, value_name = "DIR", default_value = ".")]
    output_dir: PathBuf,
}

pub async fn run(args: Args) -> Result<(), String> {
    let asset = latest_asset(args.kind).await?;
    std::fs::create_dir_all(&args.output_dir)
        .map_err(|err| format!("failed to create {}: {err}", args.output_dir.display()))?;
    let output_path = args.output_dir.join(&asset.name);

    asset
        .async_download_as(&output_path)
        .await
        .map_err(|err| format!("failed to download {}: {err}", asset.name))?;
    println!("{}", output_path.display());
    Ok(())
}
