use anyhow::{Context, Result, anyhow};
use futures::StreamExt;
use object_store::{ObjectStoreExt, gcp::GoogleCloudStorageBuilder, path::Path};
use std::path::Path as FsPath;
use tokio::io::AsyncWriteExt;
use url::Url;

pub const OSV_BUCKET: &str = "osv-vulnerabilities";
pub const OSV_ALL_ZIP: &str = "all.zip";
pub const OSV_MODIFIED_ID_CSV: &str = "modified_id.csv";

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

    pub async fn download_all_zip_to_file(&self, output: &FsPath) -> Result<()> {
        self.download_zip_to_file(OSV_ALL_ZIP, output).await
    }

    pub async fn download_source_zip_to_file(
        &self,
        source_prefix: &str,
        output: &FsPath,
    ) -> Result<()> {
        self.download_zip_to_file(&format!("{source_prefix}/{OSV_ALL_ZIP}"), output)
            .await
    }

    async fn download_zip_to_file(&self, object_path: &str, output: &FsPath) -> Result<()> {
        let mut file = tokio::fs::File::create(output)
            .await
            .with_context(|| format!("failed to create {}", output.display()))?;
        match self.store.get(&Path::from(object_path)).await {
            Ok(result) => {
                let mut stream = result.into_stream();
                while let Some(chunk) = stream.next().await {
                    let chunk = chunk.with_context(|| {
                        format!("failed to read OSV zip chunk from {object_path}")
                    })?;
                    file.write_all(&chunk)
                        .await
                        .with_context(|| format!("failed to write {}", output.display()))?;
                }
            }
            Err(gcs_err) => {
                let url = object_url(object_path)?;
                let response = reqwest::get(url.clone())
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
                    })?;
                let mut stream = response.bytes_stream();
                while let Some(chunk) = stream.next().await {
                    let chunk = chunk.with_context(|| {
                        format!("failed to read OSV zip chunk from HTTPS fallback {url}")
                    })?;
                    file.write_all(&chunk)
                        .await
                        .with_context(|| format!("failed to write {}", output.display()))?;
                }
            }
        }
        file.flush()
            .await
            .with_context(|| format!("failed to flush {}", output.display()))?;
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
