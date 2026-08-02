use super::{EcosystemPolicy, OsvRange, RangeEvaluation, is_semver_version, strip_conventional_v};

pub(super) static POLICY: GitHubActionsPolicy = GitHubActionsPolicy;

pub(super) struct GitHubActionsPolicy;

impl EcosystemPolicy for GitHubActionsPolicy {
    fn ecosystem_name(&self) -> &'static str {
        "GitHub Actions"
    }

    fn normalize_package_name(&self, name: &str) -> String {
        name.to_ascii_lowercase()
    }

    fn canonical_purl_name(&self, segments: Vec<String>) -> Option<(String, Vec<String>)> {
        if segments.len() != 2 {
            return None;
        }
        let segments = segments
            .into_iter()
            .map(|segment| segment.to_ascii_lowercase())
            .collect::<Vec<_>>();
        Some((segments.join("/"), segments))
    }

    fn versions_equivalent(&self, left: &str, right: &str) -> bool {
        strip_conventional_v(left) == strip_conventional_v(right)
    }

    fn is_concrete_version(&self, version: &str) -> bool {
        is_semver_version(version, true)
    }

    fn allows_semver_v_prefix(&self) -> bool {
        true
    }

    fn evaluate_ecosystem_range(&self, installed: &str, range: &OsvRange) -> RangeEvaluation {
        self.evaluate_semver_range(installed, range)
    }
}
