use std::io::Write;
use std::path::{Path, PathBuf};

pub const CWE_CATALOG_URL: &str = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip";
pub const CWE_CATALOG_FILENAME: &str = "cwec_latest.xml.zip";

#[derive(Debug, Clone)]
pub struct CweCatalogFile {
    pub name: String,
    pub url: String,
}

#[derive(Debug, Clone)]
pub struct CweCatalogDownload {
    pub path: Option<PathBuf>,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
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
    pub async fn async_download_if_changed(
        &self,
        etag: Option<&str>,
        last_modified: Option<&str>,
    ) -> Result<CweCatalogDownload, Box<dyn std::error::Error + Send + Sync>> {
        let client = reqwest::Client::new();
        let mut request = client.get(&self.url);
        if let Some(etag) = etag {
            request = request.header(reqwest::header::IF_NONE_MATCH, etag);
        }
        if let Some(last_modified) = last_modified {
            request = request.header(reqwest::header::IF_MODIFIED_SINCE, last_modified);
        }

        let mut response = request.send().await?;
        if response.status() == reqwest::StatusCode::NOT_MODIFIED {
            return Ok(CweCatalogDownload {
                path: None,
                etag: etag.map(ToOwned::to_owned),
                last_modified: last_modified.map(ToOwned::to_owned),
            });
        }

        response = response.error_for_status()?;
        let etag = header_string(response.headers(), reqwest::header::ETAG);
        let last_modified = header_string(response.headers(), reqwest::header::LAST_MODIFIED);
        let path = PathBuf::from(&self.name);
        let mut file = std::fs::File::create(&path)?;
        while let Some(chunk) = response.chunk().await? {
            file.write_all(&chunk)?;
        }
        file.flush()?;

        Ok(CweCatalogDownload {
            path: Some(path),
            etag,
            last_modified,
        })
    }

    pub async fn async_download_as(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut response = reqwest::Client::new()
            .get(&self.url)
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

fn header_string(
    headers: &reqwest::header::HeaderMap,
    key: reqwest::header::HeaderName,
) -> Option<String> {
    headers
        .get(key)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
}
