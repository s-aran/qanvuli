use anyhow::{Context, Result, anyhow};
use futures::StreamExt;
use object_store::{ObjectStoreExt, gcp::GoogleCloudStorageBuilder, path::Path};
use std::path::Path as FsPath;
use tokio::io::AsyncWriteExt;
use url::Url;

pub const OSV_BUCKET: &str = "osv-vulnerabilities";
pub const OSV_ALL_ZIP: &str = "all.zip";
pub const OSV_MODIFIED_ID_CSV: &str = "modified_id.csv";

#[derive(Debug)]
pub enum OsvDownloadError {
    CreateFile {
        path: std::path::PathBuf,
        source: std::io::Error,
    },
    WriteFile {
        path: std::path::PathBuf,
        source: std::io::Error,
    },
    Network(anyhow::Error),
    InvalidResponse(anyhow::Error),
}

impl OsvDownloadError {
    pub const fn is_local_storage(&self) -> bool {
        matches!(self, Self::CreateFile { .. } | Self::WriteFile { .. })
    }
}

impl std::fmt::Display for OsvDownloadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CreateFile { path, source } => {
                write!(formatter, "failed to create {}: {source}", path.display())
            }
            Self::WriteFile { path, source } => {
                write!(formatter, "failed to write {}: {source}", path.display())
            }
            Self::Network(error) => write!(formatter, "network download failed: {error:#}"),
            Self::InvalidResponse(error) => {
                write!(formatter, "invalid download response: {error:#}")
            }
        }
    }
}

impl std::error::Error for OsvDownloadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CreateFile { source, .. } | Self::WriteFile { source, .. } => Some(source),
            Self::Network(error) | Self::InvalidResponse(error) => Some(error.as_ref()),
        }
    }
}

pub struct OsvGcsSource {
    store: object_store::gcp::GoogleCloudStorage,
}

impl OsvGcsSource {
    pub fn new_public() -> Result<Self> {
        let store = GoogleCloudStorageBuilder::new()
            .with_bucket_name(OSV_BUCKET)
            .with_skip_signature(true)
            .build()
            .context("failed to build OSV GCS client")?;
        Ok(Self { store })
    }

    pub async fn all_zip(&self) -> Result<Vec<u8>> {
        self.get_object(OSV_ALL_ZIP).await
    }

    pub async fn download_all_zip_to_file(&self, output: &FsPath) -> Result<(), OsvDownloadError> {
        self.download_zip_to_file(OSV_ALL_ZIP, output).await
    }

    pub async fn download_source_zip_to_file(
        &self,
        source_prefix: &str,
        output: &FsPath,
    ) -> Result<(), OsvDownloadError> {
        self.download_zip_to_file(&format!("{source_prefix}/{OSV_ALL_ZIP}"), output)
            .await
    }

    async fn download_zip_to_file(
        &self,
        object_path: &str,
        output: &FsPath,
    ) -> Result<(), OsvDownloadError> {
        let mut file = tokio::fs::File::create(output).await.map_err(|source| {
            OsvDownloadError::CreateFile {
                path: output.to_path_buf(),
                source,
            }
        })?;
        match self.store.get(&Path::from(object_path)).await {
            Ok(result) => {
                let mut stream = result.into_stream();
                while let Some(chunk) = stream.next().await {
                    let chunk = chunk.map_err(|error| {
                        OsvDownloadError::Network(anyhow!(
                            "failed to read OSV zip chunk from {object_path}: {error}"
                        ))
                    })?;
                    file.write_all(&chunk)
                        .await
                        .map_err(|source| OsvDownloadError::WriteFile {
                            path: output.to_path_buf(),
                            source,
                        })?;
                }
            }
            Err(gcs_err) => {
                let url = object_url(object_path).map_err(OsvDownloadError::InvalidResponse)?;
                let response = reqwest::get(url.clone())
                    .await
                    .map_err(|error| OsvDownloadError::Network(anyhow!(
                        "failed to fetch gs://{OSV_BUCKET}/{object_path}; HTTPS fallback {url} also failed after GCS error: {gcs_err}: {error}"
                    )))?
                    .error_for_status()
                    .map_err(|error| OsvDownloadError::InvalidResponse(anyhow!(
                        "failed to fetch gs://{OSV_BUCKET}/{object_path}; HTTPS fallback {url} returned an error after GCS error: {gcs_err}: {error}"
                    )))?;
                let mut stream = response.bytes_stream();
                while let Some(chunk) = stream.next().await {
                    let chunk = chunk.map_err(|error| {
                        OsvDownloadError::Network(anyhow!(
                            "failed to read OSV zip chunk from HTTPS fallback {url}: {error}"
                        ))
                    })?;
                    file.write_all(&chunk)
                        .await
                        .map_err(|source| OsvDownloadError::WriteFile {
                            path: output.to_path_buf(),
                            source,
                        })?;
                }
            }
        }
        file.flush()
            .await
            .map_err(|source| OsvDownloadError::WriteFile {
                path: output.to_path_buf(),
                source,
            })?;
        Ok(())
    }

    pub async fn modified_id_csv(&self) -> Result<String> {
        let bytes = self.get_object(OSV_MODIFIED_ID_CSV).await?;
        String::from_utf8(bytes).context("OSV modified_id.csv was not UTF-8")
    }

    pub async fn advisory_json(&self, object_path: &str) -> Result<String> {
        let bytes = self.get_object(object_path).await?;
        String::from_utf8(bytes)
            .with_context(|| format!("OSV object `{object_path}` was not UTF-8"))
    }

    async fn get_object(&self, object_path: &str) -> Result<Vec<u8>> {
        match self.store.get(&Path::from(object_path)).await {
            Ok(result) => Ok(result.bytes().await?.to_vec()),
            Err(gcs_err) => {
                let url = object_url(object_path)?;
                let bytes = reqwest::get(url.clone())
                    .await
                    .with_context(|| {
                        format!(
                            "failed to fetch gs://{OSV_BUCKET}/{object_path}; HTTPS fallback {url} also failed after GCS error: {gcs_err}"
                        )
                    })?
                    .error_for_status()
                    .with_context(|| {
                        format!(
                            "failed to fetch gs://{OSV_BUCKET}/{object_path}; HTTPS fallback {url} returned an error after GCS error: {gcs_err}"
                        )
                    })?
                    .bytes()
                    .await
                    .with_context(|| {
                        format!("failed to read OSV object bytes from HTTPS fallback {url}")
                    })?;
                Ok(bytes.to_vec())
            }
        }
    }
}

fn object_url(object_path: &str) -> Result<Url> {
    let mut url = Url::parse("https://storage.googleapis.com/")
        .context("failed to build OSV HTTPS fallback URL")?;
    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|_| anyhow!("failed to append OSV object path to HTTPS fallback URL"))?;
        segments.push(OSV_BUCKET);
        for segment in object_path.split('/') {
            segments.push(segment);
        }
    }
    Ok(url)
}

#[cfg(test)]
mod download_error_tests {
    use super::*;

    #[test]
    fn only_local_storage_errors_request_fallback() {
        let io_error = || std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        assert!(
            OsvDownloadError::CreateFile {
                path: "primary.zip".into(),
                source: io_error(),
            }
            .is_local_storage()
        );
        assert!(
            OsvDownloadError::WriteFile {
                path: "primary.zip".into(),
                source: io_error(),
            }
            .is_local_storage()
        );
        assert!(!OsvDownloadError::Network(anyhow!("offline")).is_local_storage());
        assert!(!OsvDownloadError::InvalidResponse(anyhow!("bad status")).is_local_storage());
    }
}

#[derive(Clone, Debug)]
pub struct OsvModifiedId {
    pub modified_at: String,
    pub object_path: String,
}

pub fn parse_modified_id_csv(csv: &str) -> Vec<OsvModifiedId> {
    csv.lines()
        .filter(|line| !line.trim().is_empty())
        .filter(|line| !line.trim_start().starts_with('#'))
        .filter_map(|line| {
            let (modified_at, object_path) = line.split_once(',')?;
            Some(OsvModifiedId {
                modified_at: modified_at.trim().to_owned(),
                object_path: format!("{}.json", object_path.trim()),
            })
        })
        .collect()
}
