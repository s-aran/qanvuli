use std::io::Write;
use std::path::{Path, PathBuf};

pub const CAPEC_CATALOG_URL: &str = "https://capec.mitre.org/data/xml/capec_latest.xml";
pub const CAPEC_CATALOG_FILENAME: &str = "capec_latest.xml";

#[derive(Clone, Debug)]
pub struct CapecCatalogFile {
    pub name: String,
    pub url: String,
}

#[derive(Clone, Debug)]
pub struct CapecCatalogDownload {
    pub path: Option<PathBuf>,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

impl Default for CapecCatalogFile {
    fn default() -> Self {
        Self {
            name: CAPEC_CATALOG_FILENAME.to_owned(),
            url: CAPEC_CATALOG_URL.to_owned(),
        }
    }
}

impl CapecCatalogFile {
    pub async fn download_if_changed_as(
        &self,
        path: impl AsRef<Path>,
        etag: Option<&str>,
        last_modified: Option<&str>,
    ) -> Result<CapecCatalogDownload, Box<dyn std::error::Error + Send + Sync>> {
        let mut request = reqwest::Client::new().get(&self.url);
        if let Some(etag) = etag {
            request = request.header(reqwest::header::IF_NONE_MATCH, etag);
        }
        if let Some(last_modified) = last_modified {
            request = request.header(reqwest::header::IF_MODIFIED_SINCE, last_modified);
        }

        let mut response = request.send().await?;
        if response.status() == reqwest::StatusCode::NOT_MODIFIED {
            return Ok(CapecCatalogDownload {
                path: None,
                etag: etag.map(ToOwned::to_owned),
                last_modified: last_modified.map(ToOwned::to_owned),
            });
        }

        response = response.error_for_status()?;
        let etag = header(&response, reqwest::header::ETAG);
        let last_modified = header(&response, reqwest::header::LAST_MODIFIED);
        let path = path.as_ref().to_path_buf();
        if let Err(error) = write_response(&mut response, &path).await {
            let _ = std::fs::remove_file(&path);
            return Err(error);
        }
        Ok(CapecCatalogDownload {
            path: Some(path),
            etag,
            last_modified,
        })
    }
}

fn header(response: &reqwest::Response, name: reqwest::header::HeaderName) -> Option<String> {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
}

async fn write_response(
    response: &mut reqwest::Response,
    path: &Path,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut file = std::fs::File::create(path)?;
    while let Some(chunk) = response.chunk().await? {
        file.write_all(&chunk)?;
    }
    file.flush()?;
    Ok(())
}
