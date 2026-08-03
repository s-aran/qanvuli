//! Ecosystem-specific package identity and version policies.

use super::{
    CveConstraintEvaluation, CveVersionRange, OsvRange, Pep440Version, RangeEvaluation,
    evaluate_ordered_cve_range, evaluate_parsed_range, pep440_matches_wildcard,
    semver_matches_wildcard,
};

mod cargo;
mod github_actions;
mod go;
mod maven;
mod npm;
mod nuget;
mod pub_registry;
mod pypi;
mod rubygems;
mod strict;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CveRangeKind {
    Semver,
    Pep440,
    Unsupported,
}

pub(super) trait EcosystemPolicy: Sync {
    fn ecosystem_name(&self) -> &'static str;

    fn normalize_package_name(&self, name: &str) -> String {
        name.to_owned()
    }

    fn canonical_purl_name(&self, _segments: Vec<String>) -> Option<(String, Vec<String>)> {
        None
    }

    fn versions_equivalent(&self, left: &str, right: &str) -> bool {
        left == right
    }

    fn is_concrete_version(&self, _version: &str) -> bool {
        false
    }

    fn allows_semver_v_prefix(&self) -> bool {
        false
    }

    fn evaluate_semver_range(&self, installed: &str, range: &OsvRange) -> RangeEvaluation {
        evaluate_semver_range(installed, range, self.allows_semver_v_prefix())
    }

    fn evaluate_ecosystem_range(&self, _installed: &str, _range: &OsvRange) -> RangeEvaluation {
        RangeEvaluation::Unsupported
    }

    fn cve_range_kind(&self, version_type: Option<&str>) -> CveRangeKind {
        default_cve_range_kind(version_type)
    }

    fn evaluate_cve_range(
        &self,
        installed: &str,
        version: &CveVersionRange,
    ) -> CveConstraintEvaluation {
        evaluate_default_cve_range(self, installed, version)
    }

    fn ecosystem_identity_key(&self, base: &str, suffix: Option<&str>) -> String {
        let base = base.to_ascii_lowercase();
        suffix.map_or(base.clone(), |suffix| format!("{base}:{suffix}"))
    }

    fn supports_repository_url(&self) -> bool {
        false
    }

    fn canonical_repository_url(&self, _value: &str) -> Option<String> {
        None
    }

    fn is_default_repository(&self, _value: &str) -> bool {
        false
    }
}

pub(super) fn evaluate_default_cve_range(
    policy: &(impl EcosystemPolicy + ?Sized),
    installed: &str,
    version: &CveVersionRange,
) -> CveConstraintEvaluation {
    match policy.cve_range_kind(version.version_type.as_deref()) {
        CveRangeKind::Semver => {
            let allow_v_prefix = policy.allows_semver_v_prefix();
            evaluate_ordered_cve_range(
                installed,
                version,
                |value| {
                    let value = if allow_v_prefix {
                        strip_conventional_v(value)
                    } else {
                        value
                    };
                    semver::Version::parse(value).ok()
                },
                semver::Version::cmp_precedence,
                semver_matches_wildcard,
            )
        }
        CveRangeKind::Pep440 => evaluate_ordered_cve_range(
            installed,
            version,
            |value| value.parse::<Pep440Version>().ok(),
            Ord::cmp,
            pep440_matches_wildcard,
        ),
        CveRangeKind::Unsupported => CveConstraintEvaluation::Unsupported,
    }
}

pub(super) fn policy_for_ecosystem(ecosystem: &str) -> &'static dyn EcosystemPolicy {
    let base = ecosystem
        .split_once(':')
        .map_or(ecosystem, |(base, _)| base);
    if base.eq_ignore_ascii_case("crates.io") {
        &cargo::POLICY
    } else if base.eq_ignore_ascii_case("RubyGems") {
        &rubygems::POLICY
    } else if base.eq_ignore_ascii_case("GitHub Actions") {
        &github_actions::POLICY
    } else if base.eq_ignore_ascii_case("Go") {
        &go::POLICY
    } else if base.eq_ignore_ascii_case("Maven") {
        &maven::POLICY
    } else if base.eq_ignore_ascii_case("npm") {
        &npm::POLICY
    } else if base.eq_ignore_ascii_case("NuGet") {
        &nuget::POLICY
    } else if base.eq_ignore_ascii_case("PyPI") {
        &pypi::POLICY
    } else if base.eq_ignore_ascii_case("Pub") {
        &pub_registry::POLICY
    } else {
        &strict::POLICY
    }
}

pub(super) fn policy_for_purl_type(purl_type: &str) -> Option<&'static dyn EcosystemPolicy> {
    match purl_type {
        "cargo" => Some(&cargo::POLICY),
        "gem" => Some(&rubygems::POLICY),
        "github" => Some(&github_actions::POLICY),
        "golang" => Some(&go::POLICY),
        "maven" => Some(&maven::POLICY),
        "npm" => Some(&npm::POLICY),
        "nuget" => Some(&nuget::POLICY),
        "pypi" => Some(&pypi::POLICY),
        "pub" => Some(&pub_registry::POLICY),
        _ => None,
    }
}

pub(super) fn default_cve_range_kind(version_type: Option<&str>) -> CveRangeKind {
    match version_type
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(value) if value.eq_ignore_ascii_case("semver") => CveRangeKind::Semver,
        Some(_) | None => CveRangeKind::Unsupported,
    }
}

pub(super) fn canonical_single_segment(
    policy: &dyn EcosystemPolicy,
    segments: Vec<String>,
) -> Option<(String, Vec<String>)> {
    if segments.len() != 1 {
        return None;
    }
    let name = policy.normalize_package_name(&segments[0]);
    Some((name.clone(), vec![name]))
}

pub(super) fn strip_conventional_v(version: &str) -> &str {
    version
        .strip_prefix('v')
        .filter(|version| !version.is_empty() && !version.starts_with('v'))
        .unwrap_or(version)
}

fn evaluate_semver_range(
    installed: &str,
    range: &OsvRange,
    allow_leading_v: bool,
) -> RangeEvaluation {
    evaluate_parsed_range(
        installed,
        range,
        |version| {
            let version = if allow_leading_v {
                strip_conventional_v(version)
            } else {
                version
            };
            semver::Version::parse(version).ok()
        },
        semver::Version::cmp_precedence,
    )
}

pub(super) fn is_semver_version(version: &str, allow_leading_v: bool) -> bool {
    let version = if allow_leading_v {
        strip_conventional_v(version)
    } else {
        version
    };
    semver::Version::parse(version).is_ok()
}
