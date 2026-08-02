use super::{
    CveRangeKind, EcosystemPolicy, OsvRange, RangeEvaluation, canonical_single_segment,
    default_cve_range_kind,
};

pub(super) static POLICY: CargoPolicy = CargoPolicy;

pub(super) struct CargoPolicy;

impl EcosystemPolicy for CargoPolicy {
    fn ecosystem_name(&self) -> &'static str {
        "crates.io"
    }

    fn canonical_purl_name(&self, segments: Vec<String>) -> Option<(String, Vec<String>)> {
        canonical_single_segment(self, segments)
    }

    fn evaluate_ecosystem_range(&self, installed: &str, range: &OsvRange) -> RangeEvaluation {
        self.evaluate_semver_range(installed, range)
    }

    fn cve_range_kind(&self, version_type: Option<&str>) -> CveRangeKind {
        match version_type
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            Some(value)
                if value.eq_ignore_ascii_case("cargo") || value.eq_ignore_ascii_case("rust") =>
            {
                CveRangeKind::Semver
            }
            value => default_cve_range_kind(value),
        }
    }
}
