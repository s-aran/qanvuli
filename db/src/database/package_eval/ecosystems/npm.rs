use super::{
    CveRangeKind, EcosystemPolicy, OsvRange, RangeEvaluation, default_cve_range_kind,
    is_semver_version, strip_conventional_v,
};

pub(super) static POLICY: NpmPolicy = NpmPolicy;

pub(super) struct NpmPolicy;

impl EcosystemPolicy for NpmPolicy {
    fn ecosystem_name(&self) -> &'static str {
        "npm"
    }

    fn canonical_purl_name(&self, segments: Vec<String>) -> Option<(String, Vec<String>)> {
        match segments.as_slice() {
            [name] if !name.starts_with('@') => Some((name.clone(), segments)),
            [scope, name] if scope.starts_with('@') && scope.len() > 1 => {
                Some((format!("{scope}/{name}"), segments))
            }
            _ => None,
        }
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

    fn cve_range_kind(&self, version_type: Option<&str>) -> CveRangeKind {
        match version_type
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            Some(value) if value.eq_ignore_ascii_case("npm") => CveRangeKind::Semver,
            value => default_cve_range_kind(value),
        }
    }
}
