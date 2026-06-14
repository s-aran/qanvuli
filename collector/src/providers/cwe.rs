use std::io::Write;
use std::path::{Path, PathBuf};

pub const CWE_CATALOG_URL: &str = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip";
pub const CWE_CATALOG_FILENAME: &str = "cwec_latest.xml.zip";

#[derive(Debug, Clone)]
pub struct CweCatalogFile {
    pub name: String,
    pub url: String,
}

impl Default for CweCatalogFile {
    fn default() -> Self {
        Self {
            name: CWE_CATALOG_FILENAME.to_owned(),
            url: CWE_CATALOG_URL.to_owned(),
        }
    }
}

impl CweCatalogFile {
    pub async fn async_download_as(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut response = reqwest::Client::new()
            .get(&self.url)
            .header(reqwest::header::USER_AGENT, "qanvuli")
            .send()
            .await?
            .error_for_status()?;
        let mut file = std::fs::File::create(path)?;
        while let Some(chunk) = response.chunk().await? {
            file.write_all(&chunk)?;
        }
        file.flush()?;
        Ok(())
    }

    pub async fn async_download_as_file(
        &self,
    ) -> Result<PathBuf, Box<dyn std::error::Error + Send + Sync>> {
        let path = PathBuf::from(&self.name);
        if path.is_file() {
            return Ok(path);
        }
        self.async_download_as(&path).await?;
        Ok(path)
    }
}
