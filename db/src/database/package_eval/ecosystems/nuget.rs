use super::{
    CveConstraintEvaluation, CveVersionRange, EcosystemPolicy, OsvRange, RangeEvaluation,
    canonical_single_segment, evaluate_default_cve_range, evaluate_ordered_cve_range,
    evaluate_parsed_range,
};
use std::cmp::Ordering;

pub(super) static POLICY: NuGetPolicy = NuGetPolicy;

pub(super) struct NuGetPolicy;

impl EcosystemPolicy for NuGetPolicy {
    fn ecosystem_name(&self) -> &'static str {
        "NuGet"
    }

    fn normalize_package_name(&self, name: &str) -> String {
        name.to_ascii_lowercase()
    }

    fn canonical_purl_name(&self, segments: Vec<String>) -> Option<(String, Vec<String>)> {
        canonical_single_segment(self, segments)
    }

    fn versions_equivalent(&self, left: &str, right: &str) -> bool {
        left == right
            || version_key(left)
                .zip(version_key(right))
                .is_some_and(|(left, right)| left == right)
    }

    fn is_concrete_version(&self, version: &str) -> bool {
        version_key(version).is_some()
    }

    fn evaluate_ecosystem_range(&self, installed: &str, range: &OsvRange) -> RangeEvaluation {
        evaluate_parsed_range(installed, range, version_key, compare_versions)
    }

    fn evaluate_cve_range(
        &self,
        installed: &str,
        version: &CveVersionRange,
    ) -> CveConstraintEvaluation {
        if version.version_type.as_deref().is_some_and(|value| {
            value.eq_ignore_ascii_case("nuget") || value.eq_ignore_ascii_case("dotnet")
        }) {
            evaluate_ordered_cve_range(
                installed,
                version,
                version_key,
                compare_versions,
                nuget_matches_wildcard,
            )
        } else {
            evaluate_default_cve_range(self, installed, version)
        }
    }
}

fn nuget_matches_wildcard(version: &VersionKey, pattern: &str) -> Option<bool> {
    if pattern.matches('*').count() != 1 || !pattern.ends_with('*') {
        return None;
    }
    let prefix = pattern.trim_end_matches('*').trim_end_matches(['.', '-']);
    if prefix.is_empty() {
        return Some(true);
    }
    let prefix = version_key(prefix)?;
    Some(
        version.release.starts_with(&prefix.release)
            && (prefix.prerelease.is_empty() || version.prerelease.starts_with(&prefix.prerelease)),
    )
}

fn version_key(version: &str) -> Option<VersionKey> {
    let (without_build, build) = version
        .split_once('+')
        .map_or((version, None), |(value, build)| (value, Some(build)));
    if build.is_some_and(|build| build.contains('+') || !valid_identifiers(build)) {
        return None;
    }
    let (release, prerelease) = without_build
        .split_once('-')
        .map_or((without_build, None), |(release, prerelease)| {
            (release, Some(prerelease))
        });
    if prerelease.is_some_and(|prerelease| !valid_identifiers(prerelease)) {
        return None;
    }
    let mut release = release
        .split('.')
        .map(decimal)
        .collect::<Option<Vec<_>>>()?;
    if release.is_empty() || release.len() > 4 {
        return None;
    }
    while release.len() > 1 && release.last().is_some_and(|value| value == "0") {
        release.pop();
    }
    let prerelease = prerelease.map_or_else(Vec::new, |prerelease| {
        prerelease
            .split('.')
            .map(|part| {
                if part.bytes().all(|byte| byte.is_ascii_digit()) {
                    PrereleasePart::Numeric(decimal(part).expect("validated decimal"))
                } else {
                    PrereleasePart::Text(part.to_lowercase())
                }
            })
            .collect()
    });
    Some(VersionKey {
        release,
        prerelease,
    })
}

fn valid_identifiers(value: &str) -> bool {
    !value.is_empty()
        && value.split('.').all(|identifier| {
            !identifier.is_empty()
                && identifier
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum PrereleasePart {
    Numeric(String),
    Text(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct VersionKey {
    release: Vec<String>,
    prerelease: Vec<PrereleasePart>,
}

fn compare_versions(left: &VersionKey, right: &VersionKey) -> Ordering {
    for index in 0..left.release.len().max(right.release.len()) {
        let left_release = left.release.get(index).map_or("0", String::as_str);
        let right_release = right.release.get(index).map_or("0", String::as_str);
        let ordering = compare_decimal(left_release, right_release);
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    match (left.prerelease.is_empty(), right.prerelease.is_empty()) {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Greater,
        (false, true) => Ordering::Less,
        (false, false) => {
            for (left, right) in left.prerelease.iter().zip(&right.prerelease) {
                let ordering = match (left, right) {
                    (PrereleasePart::Numeric(left), PrereleasePart::Numeric(right)) => {
                        compare_decimal(left, right)
                    }
                    (PrereleasePart::Text(left), PrereleasePart::Text(right)) => left.cmp(right),
                    (PrereleasePart::Numeric(_), PrereleasePart::Text(_)) => Ordering::Less,
                    (PrereleasePart::Text(_), PrereleasePart::Numeric(_)) => Ordering::Greater,
                };
                if ordering != Ordering::Equal {
                    return ordering;
                }
            }
            left.prerelease.len().cmp(&right.prerelease.len())
        }
    }
}

fn decimal(value: &str) -> Option<String> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let value = value.trim_start_matches('0');
    Some(if value.is_empty() { "0" } else { value }.to_owned())
}

fn compare_decimal(left: &str, right: &str) -> Ordering {
    left.len().cmp(&right.len()).then_with(|| left.cmp(right))
}
