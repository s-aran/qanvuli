use qanvuli_utils::github::{self, GitHubRelease, GitHubReleaseFile};

pub struct CveRelease {
    releases: Vec<GitHubRelease>,
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

    fn is_hourly_release(release: &GitHubRelease) -> bool {
        !Self::is_end_of_day_release(release)
    }

    fn is_end_of_day_release(release: &GitHubRelease) -> bool {
        release.version.ends_with("_at_end_of_day")
    }

    fn get_releases<T: Fn(&GitHubRelease) -> bool>(
        releases: &Vec<GitHubRelease>,
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

    fn is_all_zip(asset: &GitHubReleaseFile) -> bool {
        asset.name.contains("_all_") && asset.name.ends_with(".zip")
    }

    fn get_latest_file<T: Fn(&GitHubReleaseFile) -> bool>(
        releases: Vec<&GitHubRelease>,
        filter_func: T,
    ) -> Option<&GitHubReleaseFile> {
        let latest_release = if let Some(e) = releases.get(0) {
            e
        } else {
            return None;
        };

        let asset = latest_release
            .files
            .iter()
            .filter(|f| filter_func(f))
            .collect::<Vec<&GitHubReleaseFile>>();
        let asset = asset.get(0).map(|e| *e);

        asset
    }

    pub fn get_latest_all_file(&self) -> Option<&GitHubReleaseFile> {
        let releases = self.get_hourly_release();
        Self::get_latest_file(releases, Self::is_all_zip)
    }

    pub fn get_latest_delta_file(&self) -> Option<&GitHubReleaseFile> {
        let releases = self.get_hourly_release();
        Self::get_latest_file(releases, Self::is_delta_zip)
    }

    pub fn get_latest_delta_midnight_file(&self) -> Option<&GitHubReleaseFile> {
        let releases = self.get_end_of_day_release();
        Self::get_latest_file(releases, |_| true)
    }
}
