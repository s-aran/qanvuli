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
            .get_delta_files_published_after(cursor)
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

    pub fn get(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let gh = github::GitHub::new(github::GITHUB_OWNER, github::GITHUB_REPO);
        match gh.get_release_list() {
            Ok(releases) => {
                self.releases = releases;
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    pub async fn async_get(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let gh = github::GitHub::new(github::GITHUB_OWNER, github::GITHUB_REPO);
        self.releases = gh.async_get_release_list().await?;
        Ok(())
    }

    pub async fn async_get_all(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let gh = github::GitHub::new(github::GITHUB_OWNER, github::GITHUB_REPO);
        self.releases = gh.async_get_all_release_list().await?;
        Ok(())
    }

    fn is_hourly_release(release: &GitHubRelease) -> bool {
        !Self::is_end_of_day_release(release)
    }

    fn is_end_of_day_release(release: &GitHubRelease) -> bool {
        release.version.ends_with("_at_end_of_day")
    }

    fn get_releases<T: Fn(&GitHubRelease) -> bool>(
        releases: &[GitHubRelease],
        filter_func: T,
    ) -> Vec<&GitHubRelease> {
        releases.iter().filter(|r| filter_func(r)).collect()
    }

    fn get_hourly_release(&self) -> Vec<&GitHubRelease> {
        Self::get_releases(&self.releases, Self::is_hourly_release)
    }

    fn get_end_of_day_release(&self) -> Vec<&GitHubRelease> {
        Self::get_releases(&self.releases, Self::is_end_of_day_release)
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

    fn get_latest_file<T: Fn(&GitHubReleaseFile) -> bool>(
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

    pub fn get_latest_all_file(&self) -> Option<&GitHubReleaseFile> {
        let releases = self.get_hourly_release();
        Self::get_latest_file(releases, Self::is_all_zip)
    }

    pub fn get_latest_all_file_with_published_at(
        &self,
    ) -> Option<(&GitHubReleaseFile, Option<DateTime<Utc>>)> {
        let release = self.get_hourly_release().into_iter().next()?;
        let file = release.files.iter().find(|file| Self::is_all_zip(file))?;
        Some((file, release.published_at))
    }

    pub fn get_latest_delta_file(&self) -> Option<&GitHubReleaseFile> {
        let releases = self.get_hourly_release();
        Self::get_latest_file(releases, Self::is_delta_zip)
    }

    pub fn get_latest_delta_midnight_file(&self) -> Option<&GitHubReleaseFile> {
        let releases = self.get_end_of_day_release();
        Self::get_latest_file(releases, |_| true)
    }

    pub fn get_delta_files_oldest_first(&self) -> Vec<GitHubReleaseFile> {
        let mut releases = self.get_hourly_release();
        releases.reverse();
        releases
            .into_iter()
            .flat_map(|release| release.files.iter().filter(|file| Self::is_delta_zip(file)))
            .cloned()
            .collect()
    }

    pub fn get_delta_files_published_after(
        &self,
        cursor: DateTime<Utc>,
    ) -> Vec<(DateTime<Utc>, GitHubReleaseFile)> {
        let mut releases = self
            .get_hourly_release()
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

    pub fn get_all_and_delta_files_oldest_first(&self) -> Vec<GitHubReleaseFile> {
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
