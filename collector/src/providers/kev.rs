use anyhow::{Context, Result};

pub const CISA_KEV_JSON_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

pub async fn download_kev_json() -> Result<String> {
    reqwest::Client::builder()
        .user_agent("qanvuli")
        .build()?
        .get(CISA_KEV_JSON_URL)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await
        .context("failed to read CISA KEV JSON response")
}
