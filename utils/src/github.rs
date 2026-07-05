use chrono::{DateTime, Utc};
use octocrab::models::repos::{Asset, Release};
use std::{
    io::{self, Write},
    path::{Component, Path},
};

pub const GITHUB_OWNER: &str = "CVEProject";
pub const GITHUB_REPO: &str = "cvelistV5";

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

    pub async fn async_download(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
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

    pub fn download(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let content = reqwest::blocking::Client::new()
            .get(&self.url)
            .header(reqwest::header::USER_AGENT, "qanvuli")
            .send()?
            .error_for_status()?
            .bytes()?;
        Ok(content.to_vec())
    }

    pub async fn async_download_as(
        &self,
        path: impl AsRef<std::path::Path>,
    ) -> Result<(), Box<dyn std::error::Error>> {
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

    pub fn download_as(
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

    pub async fn async_download_as_file(&self) -> Result<(), Box<dyn std::error::Error>> {
        let filename = self.safe_file_name()?;
        if self.size > 0
            && let Ok(metadata) = std::fs::metadata(filename)
            && metadata.len() == self.size
        {
            return Ok(());
        }
        self.async_download_as(filename).await
    }

    pub fn download_as_file(&self) -> Result<(), Box<dyn std::error::Error>> {
        let filename = self.safe_file_name()?;
        if self.size > 0
            && let Ok(metadata) = std::fs::metadata(filename)
            && metadata.len() == self.size
        {
            return Ok(());
        }
        self.download_as(filename)
    }
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

    pub fn get_url(&self) -> String {
        format!("https://github.com/{}/{}/", self.owner, self.repo)
    }

    pub async fn async_get_release_list(
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

    pub async fn async_get_all_release_list(
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

    pub fn get_release_list(
        &self,
    ) -> Result<Vec<GitHubRelease>, Box<dyn std::error::Error + Send + Sync>> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(self.async_get_release_list())
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
