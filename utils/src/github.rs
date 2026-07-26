use chrono::{DateTime, Utc};
use octocrab::models::repos::{Asset, Release};
use reqwest::{StatusCode, header};
use std::{
    io::{self, SeekFrom, Write},
    path::{Component, Path},
};
use tokio::{
    io::{AsyncSeekExt, AsyncWriteExt},
    task::JoinSet,
};

pub const GITHUB_OWNER: &str = "CVEProject";
pub const GITHUB_REPO: &str = "cvelistV5";

const RANGE_DOWNLOAD_MIN_BYTES: u64 = 32 * 1024 * 1024;
const RANGE_DOWNLOAD_MAX_CONNECTIONS: u64 = 4;

#[derive(Debug, Clone)]
pub struct GitHubReleaseFile {
    pub name: String,
    pub url: String,
    pub size: u64,
}

impl GitHubReleaseFile {
    pub fn safe_file_name(&self) -> Result<&str, io::Error> {
        safe_file_name(&self.name)
    }

    pub async fn download_bytes(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let content = reqwest::Client::new()
            .get(&self.url)
            .header(reqwest::header::USER_AGENT, "qanvuli")
            .send()
            .await?
            .error_for_status()?
            .bytes()
            .await?;
        Ok(content.to_vec())
    }

    pub fn download_bytes_blocking(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let content = reqwest::blocking::Client::new()
            .get(&self.url)
            .header(reqwest::header::USER_AGENT, "qanvuli")
            .send()?
            .error_for_status()?
            .bytes()?;
        Ok(content.to_vec())
    }

    pub async fn download_to(
        &self,
        path: impl AsRef<std::path::Path>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let path = path.as_ref();
        if self.size >= RANGE_DOWNLOAD_MIN_BYTES && self.parallel_range_download(path).await? {
            return Ok(());
        }
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

    /// Downloads an immutable asset with independent HTTP/1.1 range requests.
    ///
    /// The probe must return `206` before the output file is created. A changed or inconsistent
    /// asset fails without leaving a partial file.
    async fn parallel_range_download(
        &self,
        path: &Path,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let probe_client = reqwest::Client::builder().http1_only().build()?;
        let probe = probe_client
            .get(&self.url)
            .header(header::USER_AGENT, "qanvuli")
            .header(header::ACCEPT_ENCODING, "identity")
            .header(header::RANGE, "bytes=0-0")
            .send()
            .await?;
        if probe.status() != StatusCode::PARTIAL_CONTENT {
            return Ok(false);
        }
        let content_range = probe
            .headers()
            .get(header::CONTENT_RANGE)
            .and_then(|value| value.to_str().ok())
            .and_then(parse_content_range)
            .filter(|range| range.start == 0 && range.end == 0)
            .ok_or_else(|| "invalid Content-Range in release asset range response".to_owned())?;
        if self.size != 0 && content_range.total != self.size {
            return Err(format!(
                "release asset size changed during download: metadata={}, range={}",
                self.size, content_range.total
            )
            .into());
        }
        let validator = probe
            .headers()
            .get(header::ETAG)
            .or_else(|| probe.headers().get(header::LAST_MODIFIED))
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned);
        if probe.bytes().await?.len() != 1 || content_range.total < RANGE_DOWNLOAD_MIN_BYTES {
            return Ok(false);
        }
        let connection_count = content_range
            .total
            .div_ceil(RANGE_DOWNLOAD_MIN_BYTES)
            .clamp(2, RANGE_DOWNLOAD_MAX_CONNECTIONS);
        let chunk_size = content_range.total.div_ceil(connection_count);
        let file = std::fs::File::create(path)?;
        file.set_len(content_range.total)?;
        drop(file);

        let mut tasks = JoinSet::new();
        for index in 0..connection_count {
            let start = index * chunk_size;
            if start >= content_range.total {
                break;
            }
            let end = (start + chunk_size - 1).min(content_range.total - 1);
            tasks.spawn(download_range(
                self.url.clone(),
                path.to_path_buf(),
                start,
                end,
                content_range.total,
                validator.clone(),
            ));
        }
        while let Some(result) = tasks.join_next().await {
            match result {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    tasks.abort_all();
                    while tasks.join_next().await.is_some() {}
                    let _ = std::fs::remove_file(path);
                    return Err(error.into());
                }
                Err(error) => {
                    tasks.abort_all();
                    while tasks.join_next().await.is_some() {}
                    let _ = std::fs::remove_file(path);
                    return Err(format!("release asset range task failed: {error}").into());
                }
            }
        }
        Ok(true)
    }

    pub fn download_to_blocking(
        &self,
        path: impl AsRef<std::path::Path>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut response = reqwest::blocking::Client::new()
            .get(&self.url)
            .header(reqwest::header::USER_AGENT, "qanvuli")
            .send()?
            .error_for_status()?;
        let mut file = std::fs::File::create(path)?;
        std::io::copy(&mut response, &mut file)?;
        file.flush()?;
        Ok(())
    }

    pub async fn download_to_default_path(&self) -> Result<(), Box<dyn std::error::Error>> {
        let filename = self.safe_file_name()?;
        if self.size > 0
            && let Ok(metadata) = std::fs::metadata(filename)
            && metadata.len() == self.size
        {
            return Ok(());
        }
        self.download_to(filename).await
    }

    pub fn download_to_default_path_blocking(&self) -> Result<(), Box<dyn std::error::Error>> {
        let filename = self.safe_file_name()?;
        if self.size > 0
            && let Ok(metadata) = std::fs::metadata(filename)
            && metadata.len() == self.size
        {
            return Ok(());
        }
        self.download_to_blocking(filename)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ContentRange {
    start: u64,
    end: u64,
    total: u64,
}

fn parse_content_range(value: &str) -> Option<ContentRange> {
    let value = value.strip_prefix("bytes ")?;
    let (range, total) = value.split_once('/')?;
    let (start, end) = range.split_once('-')?;
    let start = start.parse().ok()?;
    let end = end.parse().ok()?;
    let total = total.parse().ok()?;
    (start <= end && end < total).then_some(ContentRange { start, end, total })
}

async fn download_range(
    url: String,
    path: std::path::PathBuf,
    start: u64,
    end: u64,
    total: u64,
    validator: Option<String>,
) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .http1_only()
        .build()
        .map_err(|error| format!("failed to create range download client: {error}"))?;
    let mut request = client
        .get(url)
        .header(header::USER_AGENT, "qanvuli")
        .header(header::ACCEPT_ENCODING, "identity")
        .header(header::RANGE, format!("bytes={start}-{end}"));
    if let Some(validator) = validator {
        request = request.header(header::IF_RANGE, validator);
    }
    let mut response = request
        .send()
        .await
        .map_err(|error| format!("range request {start}-{end} failed: {error}"))?;
    if response.status() != StatusCode::PARTIAL_CONTENT {
        return Err(format!(
            "range request {start}-{end} returned {}, expected 206",
            response.status()
        ));
    }
    let actual = response
        .headers()
        .get(header::CONTENT_RANGE)
        .and_then(|value| value.to_str().ok())
        .and_then(parse_content_range)
        .filter(|actual| actual.start == start && actual.end == end && actual.total == total)
        .ok_or_else(|| {
            format!("range request {start}-{end} returned an inconsistent Content-Range")
        })?;
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .await
        .map_err(|error| format!("failed to open range output: {error}"))?;
    file.seek(SeekFrom::Start(actual.start))
        .await
        .map_err(|error| format!("failed to seek range output: {error}"))?;
    let mut written = 0_u64;
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| format!("failed to receive range {start}-{end}: {error}"))?
    {
        file.write_all(&chunk)
            .await
            .map_err(|error| format!("failed to write range {start}-{end}: {error}"))?;
        written += chunk.len() as u64;
    }
    file.flush()
        .await
        .map_err(|error| format!("failed to flush range {start}-{end}: {error}"))?;
    (written == actual.end - actual.start + 1)
        .then_some(())
        .ok_or_else(|| format!("range {start}-{end} was truncated: received {written} bytes"))
}

fn safe_file_name(value: &str) -> Result<&str, io::Error> {
    let mut components = Path::new(value).components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(_)), None) => Ok(value),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsafe release asset filename: {value}"),
        )),
    }
}

impl From<Asset> for GitHubReleaseFile {
    fn from(asset: Asset) -> Self {
        Self {
            name: asset.name,
            url: asset.browser_download_url.to_string(),
            size: asset.size.max(0) as u64,
        }
    }
}

#[derive(Debug, Clone)]
pub struct GitHubRelease {
    pub version: String,
    pub url: String,
    pub published_at: Option<DateTime<Utc>>,
    pub files: Vec<GitHubReleaseFile>,
}

impl From<Release> for GitHubRelease {
    fn from(release: Release) -> Self {
        Self {
            version: release.tag_name,
            url: release.html_url.to_string(),
            published_at: release.published_at,
            files: release
                .assets
                .into_iter()
                .map(|asset| asset.into())
                .collect(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct GitHub {
    pub owner: String,
    pub repo: String,
}

impl GitHub {
    pub fn new(owner: impl Into<String>, repo: impl Into<String>) -> Self {
        Self {
            owner: owner.into(),
            repo: repo.into(),
        }
    }

    pub fn url(&self) -> String {
        format!("https://github.com/{}/{}/", self.owner, self.repo)
    }

    pub async fn list_releases(
        &self,
    ) -> Result<Vec<GitHubRelease>, Box<dyn std::error::Error + Send + Sync>> {
        let octocrab = octocrab::instance();
        let page = octocrab
            .repos(&self.owner, &self.repo)
            .releases()
            .list()
            .per_page(100)
            .send()
            .await?;
        release_items_to_sorted_releases(page.items)
    }

    pub async fn list_all_releases(
        &self,
    ) -> Result<Vec<GitHubRelease>, Box<dyn std::error::Error + Send + Sync>> {
        let octocrab = octocrab::instance();
        let page = octocrab
            .repos(&self.owner, &self.repo)
            .releases()
            .list()
            .per_page(100)
            .send()
            .await?;
        let mut release_items = Vec::new();
        let mut page = page;
        release_items.append(&mut page.items);
        while page.next.is_some() {
            let next = match octocrab.get_page(&page.next).await {
                Ok(Some(next)) => next,
                Ok(None) => break,
                Err(err) => {
                    eprintln!("GitHub release pagination stopped early: {err}");
                    break;
                }
            };
            page = next;
            release_items.append(&mut page.items);
        }
        release_items_to_sorted_releases(release_items)
    }

    pub fn list_releases_blocking(
        &self,
    ) -> Result<Vec<GitHubRelease>, Box<dyn std::error::Error + Send + Sync>> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(self.list_releases())
    }
}

fn release_items_to_sorted_releases(
    release_items: Vec<Release>,
) -> Result<Vec<GitHubRelease>, Box<dyn std::error::Error + Send + Sync>> {
    let mut releases = release_items
        .into_iter()
        .map(GitHubRelease::from)
        .collect::<Vec<GitHubRelease>>();

    releases.sort_by(|a, b| match (&a.published_at, &b.published_at) {
        (Some(a), Some(b)) => b.cmp(a),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    });

    Ok(releases)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_byte_content_ranges() {
        assert_eq!(
            parse_content_range("bytes 0-1023/4096"),
            Some(ContentRange {
                start: 0,
                end: 1023,
                total: 4096,
            })
        );
    }

    #[test]
    fn rejects_invalid_byte_content_ranges() {
        for value in ["bytes 1024-0/4096", "bytes 0-4096/4096", "items 0-1/2"] {
            assert_eq!(parse_content_range(value), None, "{value}");
        }
    }
}
