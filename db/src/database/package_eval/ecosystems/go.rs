use super::{
    CveRangeKind, EcosystemPolicy, OsvRange, RangeEvaluation, default_cve_range_kind,
    strip_conventional_v,
};

pub(super) static POLICY: GoPolicy = GoPolicy;

pub(super) struct GoPolicy;

impl EcosystemPolicy for GoPolicy {
    fn ecosystem_name(&self) -> &'static str {
        "Go"
    }

    fn canonical_purl_name(&self, segments: Vec<String>) -> Option<(String, Vec<String>)> {
        (segments.len() >= 2).then(|| (segments.join("/"), segments))
    }

    fn versions_equivalent(&self, left: &str, right: &str) -> bool {
        strip_conventional_v(left) == strip_conventional_v(right)
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
            Some(value) if value.eq_ignore_ascii_case("go") => CveRangeKind::Semver,
            value => default_cve_range_kind(value),
        }
    }
}
