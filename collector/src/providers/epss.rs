use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use std::io::Read;

pub const FIRST_EPSS_CURRENT_CSV_URL: &str = "https://epss.cyentia.com/epss_scores-current.csv.gz";

pub async fn download_epss_current_csv() -> Result<String> {
    let bytes = qanvuli_utils::http::client_builder()
        .user_agent("qanvuli")
        .build()?
        .get(FIRST_EPSS_CURRENT_CSV_URL)
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await
        .context("failed to read FIRST EPSS current CSV response")?;
    let mut decoder = GzDecoder::new(bytes.as_ref());
    let mut csv = String::new();
    decoder
        .read_to_string(&mut csv)
        .context("failed to decompress FIRST EPSS current CSV")?;
    Ok(csv)
}
