use super::{
    CveConstraintEvaluation, CveVersionRange, EcosystemPolicy, OsvRange, RangeEvaluation,
    canonical_single_segment, evaluate_default_cve_range, evaluate_ordered_cve_range,
    evaluate_parsed_range,
};
use std::cmp::Ordering;

pub(super) static POLICY: PubPolicy = PubPolicy;

pub(super) struct PubPolicy;

impl EcosystemPolicy for PubPolicy {
    fn ecosystem_name(&self) -> &'static str {
        "Pub"
    }

    fn normalize_package_name(&self, name: &str) -> String {
        name.chars()
            .map(|character| {
                let character = character.to_ascii_lowercase();
                if character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_'
                {
                    character
                } else {
                    '_'
                }
            })
            .collect()
    }

    fn canonical_purl_name(&self, segments: Vec<String>) -> Option<(String, Vec<String>)> {
        canonical_single_segment(self, segments)
    }

    fn versions_equivalent(&self, left: &str, right: &str) -> bool {
        pub_version(left)
            .zip(pub_version(right))
            .is_some_and(|(left, right)| left == right)
    }

    fn is_concrete_version(&self, version: &str) -> bool {
        pub_version(version).is_some()
    }

    fn evaluate_ecosystem_range(&self, installed: &str, range: &OsvRange) -> RangeEvaluation {
        evaluate_parsed_range(installed, range, pub_version, compare_versions)
    }

    fn evaluate_cve_range(
        &self,
        installed: &str,
        version: &CveVersionRange,
    ) -> CveConstraintEvaluation {
        if version
            .version_type
            .as_deref()
            .is_some_and(|value| value.eq_ignore_ascii_case("pub"))
        {
            evaluate_ordered_cve_range(
                installed,
                version,
                pub_version,
                compare_versions,
                pub_matches_wildcard,
            )
        } else {
            evaluate_default_cve_range(self, installed, version)
        }
    }
}

fn pub_matches_wildcard(version: &PubVersion, pattern: &str) -> Option<bool> {
    if pattern.matches('*').count() != 1 || !pattern.ends_with('*') {
        return None;
    }
    let prefix = pattern.trim_end_matches('*').trim_end_matches('.');
    let release = prefix.split('.').map(decimal).collect::<Option<Vec<_>>>()?;
    if release.len() > 3 {
        return None;
    }
    Some(version.release[..release.len()] == release)
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Identifier {
    Number(String),
    Text(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PubVersion {
    release: [String; 3],
    prerelease: Vec<Identifier>,
    build: Vec<Identifier>,
}

fn pub_version(version: &str) -> Option<PubVersion> {
    let (without_build, build) = version
        .split_once('+')
        .map_or((version, None), |(version, build)| (version, Some(build)));
    if build.is_some_and(|build| build.contains('+')) {
        return None;
    }
    let (release, prerelease) = without_build
        .split_once('-')
        .map_or((without_build, None), |(release, prerelease)| {
            (release, Some(prerelease))
        });
    let release = release
        .split('.')
        .map(decimal)
        .collect::<Option<Vec<_>>>()?
        .try_into()
        .ok()?;
    Some(PubVersion {
        release,
        prerelease: match prerelease {
            Some(value) => parse_identifiers(value)?,
            None => Vec::new(),
        },
        build: match build {
            Some(value) => parse_identifiers(value)?,
            None => Vec::new(),
        },
    })
}

fn decimal(value: &str) -> Option<String> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let value = value.trim_start_matches('0');
    Some(if value.is_empty() { "0" } else { value }.to_owned())
}

fn parse_identifiers(value: &str) -> Option<Vec<Identifier>> {
    value
        .split('.')
        .map(|identifier| {
            if identifier.is_empty()
                || !identifier
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            {
                None
            } else if identifier.bytes().all(|byte| byte.is_ascii_digit()) {
                decimal(identifier).map(Identifier::Number)
            } else {
                Some(Identifier::Text(identifier.to_owned()))
            }
        })
        .collect()
}

fn compare_versions(left: &PubVersion, right: &PubVersion) -> Ordering {
    for (left, right) in left.release.iter().zip(&right.release) {
        let ordering = compare_decimal(left, right);
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    match (left.prerelease.is_empty(), right.prerelease.is_empty()) {
        (true, false) => return Ordering::Greater,
        (false, true) => return Ordering::Less,
        _ => {}
    }
    let ordering = compare_identifiers(&left.prerelease, &right.prerelease);
    if ordering != Ordering::Equal {
        return ordering;
    }
    match (left.build.is_empty(), right.build.is_empty()) {
        (true, false) => Ordering::Less,
        (false, true) => Ordering::Greater,
        _ => compare_identifiers(&left.build, &right.build),
    }
}

fn compare_identifiers(left: &[Identifier], right: &[Identifier]) -> Ordering {
    for (left, right) in left.iter().zip(right) {
        let ordering = match (left, right) {
            (Identifier::Number(left), Identifier::Number(right)) => compare_decimal(left, right),
            (Identifier::Number(_), Identifier::Text(_)) => Ordering::Less,
            (Identifier::Text(_), Identifier::Number(_)) => Ordering::Greater,
            (Identifier::Text(left), Identifier::Text(right)) => left.cmp(right),
        };
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    left.len().cmp(&right.len())
}

fn compare_decimal(left: &str, right: &str) -> Ordering {
    left.len().cmp(&right.len()).then_with(|| left.cmp(right))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pub_semver_orders_build_identifiers() {
        for (left, right) in [
            ("1.0.0", "1.0.0+1"),
            ("1.0.0+1", "1.0.0+2"),
            ("1.0.0+2", "1.0.0+10"),
            ("1.0.0+10", "1.0.0+hotfix"),
        ] {
            assert_eq!(
                compare_versions(&pub_version(left).unwrap(), &pub_version(right).unwrap()),
                Ordering::Less,
                "{left} !< {right}"
            );
        }
    }

    #[test]
    fn pub_semver_canonicalizes_numeric_identifiers() {
        assert!(POLICY.versions_equivalent("01.02.03-01.dev+pre.02", "1.2.3-1.dev+pre.2"));
        assert!(!POLICY.versions_equivalent("1.2.3+1", "1.2.3+2"));
    }
}
