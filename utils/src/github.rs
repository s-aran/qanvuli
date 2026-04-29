use chrono::{DateTime, Utc};
use octocrab::models::repos::{Asset, Release};

pub const GITHUB_OWNER: &str = "CVEProject";
pub const GITHUB_REPO: &str = "cvelistV5";

#[derive(Debug, Clone)]
pub struct GitHubReleaseFile {
    pub name: String,
    pub url: String,
    pub size: u64,
}

impl GitHubReleaseFile {
    pub async fn async_download(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let content = reqwest::get(&self.url).await?.bytes().await?;
        Ok(content.to_vec())
    }

    pub fn download(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let content = reqwest::blocking::get(&self.url)?.bytes()?;
        Ok(content.to_vec())
    }

    pub async fn async_download_as(
        &self,
        path: impl AsRef<std::path::Path>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let bytes = self.async_download().await?;
        std::fs::write(path, bytes)?;
        Ok(())
    }

    pub fn download_as(
        &self,
        path: impl AsRef<std::path::Path>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let bytes = self.download()?;
        std::fs::write(path, bytes)?;
        Ok(())
    }

    pub async fn async_download_as_file(&self) -> Result<(), Box<dyn std::error::Error>> {
        let filename = self.name.clone();
        self.async_download_as(filename).await
    }

    pub fn download_as_file(&self) -> Result<(), Box<dyn std::error::Error>> {
        let filename = self.name.clone();
        self.download_as(filename)
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
            published_at: release.published_at.clone(),
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

        let releases: Vec<GitHubRelease> = {
            let mut releases = page
                .items
                .iter()
                .map(|release: &Release| release.clone().into())
                .collect::<Vec<GitHubRelease>>();

            releases.sort_by(|a, b| match (&a.published_at, &b.published_at) {
                (Some(a), Some(b)) => b.cmp(a), // Z -> A
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => std::cmp::Ordering::Equal,
            });

            releases
        };

        Ok(releases)
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
