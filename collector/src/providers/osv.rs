use anyhow::{Context, Result};
use futures::StreamExt;
use object_store::{ObjectStoreExt, gcp::GoogleCloudStorageBuilder, path::Path};
use std::path::Path as FsPath;
use tokio::io::AsyncWriteExt;

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
        let result = self
            .store
            .get(&Path::from(OSV_ALL_ZIP))
            .await
            .with_context(|| format!("failed to fetch gs://{OSV_BUCKET}/{OSV_ALL_ZIP}"))?;
        let mut stream = result.into_stream();
        let mut file = tokio::fs::File::create(output)
            .await
            .with_context(|| format!("failed to create {}", output.display()))?;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.context("failed to read OSV all.zip chunk")?;
            file.write_all(&chunk)
                .await
                .with_context(|| format!("failed to write {}", output.display()))?;
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
        let result = self
            .store
            .get(&Path::from(object_path))
            .await
            .with_context(|| format!("failed to fetch gs://{OSV_BUCKET}/{object_path}"))?;
        Ok(result.bytes().await?.to_vec())
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
