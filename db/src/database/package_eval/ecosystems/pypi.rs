use super::{
    CveRangeKind, EcosystemPolicy, OsvRange, RangeEvaluation, canonical_single_segment,
    default_cve_range_kind, evaluate_parsed_range,
};
use pep440_rs::Version as Pep440Version;

pub(super) static POLICY: PyPiPolicy = PyPiPolicy;

pub(super) struct PyPiPolicy;

impl EcosystemPolicy for PyPiPolicy {
    fn ecosystem_name(&self) -> &'static str {
        "PyPI"
    }

    fn normalize_package_name(&self, name: &str) -> String {
        let mut normalized = String::with_capacity(name.len());
        let mut previous_separator = false;
        for character in name.chars() {
            if matches!(character, '-' | '_' | '.') {
                if !previous_separator {
                    normalized.push('-');
                }
                previous_separator = true;
            } else {
                normalized.push(character.to_ascii_lowercase());
                previous_separator = false;
            }
        }
        normalized
    }

    fn canonical_purl_name(&self, segments: Vec<String>) -> Option<(String, Vec<String>)> {
        canonical_single_segment(self, segments)
    }

    fn versions_equivalent(&self, left: &str, right: &str) -> bool {
        left == right
            || left
                .parse::<Pep440Version>()
                .ok()
                .zip(right.parse::<Pep440Version>().ok())
                .is_some_and(|(left, right)| left == right)
    }

    fn is_concrete_version(&self, version: &str) -> bool {
        version.parse::<Pep440Version>().is_ok()
    }

    fn evaluate_ecosystem_range(&self, installed: &str, range: &OsvRange) -> RangeEvaluation {
        evaluate_parsed_range(
            installed,
            range,
            |version| version.parse::<Pep440Version>().ok(),
            Ord::cmp,
        )
    }

    fn cve_range_kind(&self, version_type: Option<&str>) -> CveRangeKind {
        match version_type
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            Some(value)
                if value.eq_ignore_ascii_case("python")
                    || value.eq_ignore_ascii_case("pep440")
                    || value.eq_ignore_ascii_case("pep 440") =>
            {
                CveRangeKind::Pep440
            }
            value => default_cve_range_kind(value),
        }
    }
}
