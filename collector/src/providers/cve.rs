use chrono::{DateTime, Utc};
use qanvuli_utils::github::{self, GitHubRelease, GitHubReleaseFile};

pub struct CveRelease {
    releases: Vec<GitHubRelease>,
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;

    fn release(published_at: &str, asset_name: &str) -> GitHubRelease {
        GitHubRelease {
            version: published_at.to_owned(),
            url: String::new(),
            published_at: Some(
                DateTime::parse_from_rfc3339(published_at)
                    .unwrap()
                    .with_timezone(&Utc),
            ),
            files: vec![GitHubReleaseFile {
                name: asset_name.to_owned(),
                url: String::new(),
                size: 1,
            }],
        }
    }

    #[test]
    fn delta_cursor_filters_old_releases_and_keeps_chronological_order() {
        let provider = CveRelease {
            releases: vec![
                release("2026-07-19T02:00:00Z", "2026-07-19_delta_0200.zip"),
                release("2026-07-19T01:00:00Z", "2026-07-19_delta_0100.zip"),
                release("2026-07-19T00:00:00Z", "2026-07-19_delta_0000.zip"),
            ],
        };
        let cursor = DateTime::parse_from_rfc3339("2026-07-19T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        let names = provider
            .delta_assets_after(cursor)
            .into_iter()
            .map(|(_, asset)| asset.name)
            .collect::<Vec<_>>();

        assert_eq!(
            names,
            vec![
                "2026-07-19_delta_0100.zip".to_owned(),
                "2026-07-19_delta_0200.zip".to_owned(),
            ]
        );
    }
}

impl Default for CveRelease {
    fn default() -> Self {
        Self::new()
    }
}

impl CveRelease {
    pub fn new() -> Self {
        Self {
            releases: Vec::new(),
        }
    }

    pub fn refresh_blocking(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let gh = github::GitHub::new(github::GITHUB_OWNER, github::GITHUB_REPO);
        match gh.list_releases_blocking() {
            Ok(releases) => {
                self.releases = releases;
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    pub async fn refresh(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let gh = github::GitHub::new(github::GITHUB_OWNER, github::GITHUB_REPO);
        self.releases = gh.list_releases().await?;
        Ok(())
    }

    pub async fn refresh_all(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let gh = github::GitHub::new(github::GITHUB_OWNER, github::GITHUB_REPO);
        self.releases = gh.list_all_releases().await?;
        Ok(())
    }

    fn is_hourly_release(release: &GitHubRelease) -> bool {
        !Self::is_end_of_day_release(release)
    }

    fn is_end_of_day_release(release: &GitHubRelease) -> bool {
        release.version.ends_with("_at_end_of_day")
    }

    fn select_releases<T: Fn(&GitHubRelease) -> bool>(
        releases: &[GitHubRelease],
        filter_func: T,
    ) -> Vec<&GitHubRelease> {
        releases.iter().filter(|r| filter_func(r)).collect()
    }

    fn hourly_releases(&self) -> Vec<&GitHubRelease> {
        Self::select_releases(&self.releases, Self::is_hourly_release)
    }

    fn end_of_day_releases(&self) -> Vec<&GitHubRelease> {
        Self::select_releases(&self.releases, Self::is_end_of_day_release)
    }

    fn is_delta_zip(asset: &GitHubReleaseFile) -> bool {
        asset.name.contains("_delta_") && asset.name.ends_with(".zip")
    }

    fn is_end_of_day_zip(asset: &GitHubReleaseFile) -> bool {
        asset.name.contains("_at_end_of_day") && asset.name.ends_with(".zip")
    }

    fn is_all_zip(asset: &GitHubReleaseFile) -> bool {
        asset.name.contains("_all_") && asset.name.ends_with(".zip")
    }

    fn latest_asset<T: Fn(&GitHubReleaseFile) -> bool>(
        releases: Vec<&GitHubRelease>,
        filter_func: T,
    ) -> Option<&GitHubReleaseFile> {
        let latest_release = releases.first()?;

        latest_release
            .files
            .iter()
            .filter(|f| filter_func(f))
            .collect::<Vec<&GitHubReleaseFile>>()
            .first()
            .copied()
    }

    pub fn latest_full_asset(&self) -> Option<&GitHubReleaseFile> {
        let releases = self.hourly_releases();
        Self::latest_asset(releases, Self::is_all_zip)
    }

    pub fn latest_full_asset_with_date(
        &self,
    ) -> Option<(&GitHubReleaseFile, Option<DateTime<Utc>>)> {
        let release = self.hourly_releases().into_iter().next()?;
        let file = release.files.iter().find(|file| Self::is_all_zip(file))?;
        Some((file, release.published_at))
    }

    pub fn latest_delta_asset(&self) -> Option<&GitHubReleaseFile> {
        let releases = self.hourly_releases();
        Self::latest_asset(releases, Self::is_delta_zip)
    }

    pub fn latest_end_of_day_asset(&self) -> Option<&GitHubReleaseFile> {
        let releases = self.end_of_day_releases();
        Self::latest_asset(releases, |_| true)
    }

    pub fn delta_assets(&self) -> Vec<GitHubReleaseFile> {
        let mut releases = self.hourly_releases();
        releases.reverse();
        releases
            .into_iter()
            .flat_map(|release| release.files.iter().filter(|file| Self::is_delta_zip(file)))
            .cloned()
            .collect()
    }

    pub fn delta_assets_after(
        &self,
        cursor: DateTime<Utc>,
    ) -> Vec<(DateTime<Utc>, GitHubReleaseFile)> {
        let mut releases = self
            .hourly_releases()
            .into_iter()
            .filter_map(|release| {
                release
                    .published_at
                    .map(|published_at| (published_at, release))
            })
            .filter(|(published_at, _)| *published_at > cursor)
            .collect::<Vec<_>>();
        releases.sort_by_key(|(published_at, _)| *published_at);
        releases
            .into_iter()
            .flat_map(|(published_at, release)| {
                release
                    .files
                    .iter()
                    .filter(|file| Self::is_delta_zip(file))
                    .cloned()
                    .map(move |file| (published_at, file))
            })
            .collect()
    }

    pub fn all_assets(&self) -> Vec<GitHubReleaseFile> {
        let mut releases = self.releases.iter().collect::<Vec<_>>();
        releases.reverse();
        releases
            .into_iter()
            .flat_map(|release| {
                release.files.iter().filter(|file| {
                    Self::is_all_zip(file)
                        || Self::is_delta_zip(file)
                        || Self::is_end_of_day_zip(file)
                })
            })
            .cloned()
            .collect()
    }
}
