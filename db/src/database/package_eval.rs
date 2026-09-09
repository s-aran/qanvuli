//! DB-independent OSV range evaluation used by SQLx package queries.

use pep440_rs::Version as Pep440Version;
use serde::Serialize;
use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
};

mod ecosystems;

use ecosystems::{policy_for_ecosystem, policy_for_purl_type};

/// Canonical package identity extracted from a supported Package URL.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedPackagePurl {
    pub ecosystem: String,
    pub name: String,
    pub version: Option<String>,
    pub identity_purl: String,
}

/// Normalizes a package name according to the identity rules of its ecosystem.
///
/// PyPI follows PEP 503, while NuGet identifiers are case-insensitive. Other
/// supported purl types are kept case- and punctuation-sensitive so distinct
/// npm, Cargo, Maven, Go, and RubyGems names are never merged accidentally.
pub fn normalize_package_name(ecosystem: &str, name: &str) -> String {
    policy_for_ecosystem(ecosystem).normalize_package_name(name)
}

/// Builds a separator-insensitive key for joining dependency names to CVE List product/package
/// names. This deliberately has narrower use than ecosystem identity normalization: OSV package
/// identities keep their ecosystem-specific punctuation semantics.
pub fn normalize_cve_component_name(name: &str) -> String {
    name.chars()
        .filter(|character| !character.is_whitespace() && !matches!(character, '-' | '_' | '.'))
        .flat_map(char::to_lowercase)
        .collect()
}

/// Builds an ecosystem identity key whose base is ASCII-case-insensitive.
///
/// Scoped ecosystem suffixes remain case-sensitive. Maven repository suffixes
/// additionally normalize URL scheme/host spelling and the default Central
/// repository is represented by the unscoped `maven` key.
pub fn ecosystem_identity_key(ecosystem: &str) -> String {
    let (base, suffix) = ecosystem
        .split_once(':')
        .map_or((ecosystem, None), |(base, suffix)| (base, Some(suffix)));
    policy_for_ecosystem(base).ecosystem_identity_key(base, suffix)
}

/// Compares explicitly enumerated OSV versions using ecosystem equivalence.
pub fn versions_equivalent(ecosystem: &str, left: &str, right: &str) -> bool {
    policy_for_ecosystem(ecosystem).versions_equivalent(left, right)
}

/// Returns whether `version` is a concrete installed version supported by the
/// ecosystem's existing version policy rather than a constraint or range.
pub fn is_concrete_package_version(ecosystem: &str, version: &str) -> bool {
    !version.is_empty()
        && version.trim() == version
        && policy_for_ecosystem(ecosystem).is_concrete_version(version)
}

/// Returns the canonical versionless identity of a supported purl.
///
/// Callers that need to distinguish malformed input should use
/// [`parse_package_purl`]. This compatibility wrapper leaves malformed or
/// unsupported input unchanged.
pub fn package_identity_purl(purl: &str) -> String {
    parse_package_purl(purl)
        .map(|parsed| parsed.identity_purl)
        .unwrap_or_else(|| purl.to_owned())
}

/// Extracts the OSV ecosystem and package name represented by a PURL.
/// This intentionally returns only identity fields; the installed version is
/// evaluated separately by the caller.
pub fn package_identity_from_purl(purl: &str) -> Option<(String, String)> {
    parse_package_purl(purl).map(|parsed| (parsed.ecosystem, parsed.name))
}

/// Parses and canonicalizes a supported Package URL.
pub fn parse_package_purl(purl: &str) -> Option<ParsedPackagePurl> {
    let (scheme, body) = purl.split_once(':')?;
    if !scheme.eq_ignore_ascii_case("pkg") {
        return None;
    }
    let body = body.trim_start_matches('/');
    if body.is_empty() {
        return None;
    }
    let (before_fragment, raw_subpath) = body
        .split_once('#')
        .map_or((body, None), |(before, subpath)| (before, Some(subpath)));
    if raw_subpath.is_some_and(|subpath| subpath.contains('#')) {
        return None;
    }
    let (path_and_version, raw_qualifiers) = before_fragment
        .split_once('?')
        .map_or((before_fragment, None), |(path, qualifiers)| {
            (path, Some(qualifiers))
        });
    if raw_qualifiers.is_some_and(|qualifiers| qualifiers.is_empty() || qualifiers.contains('?')) {
        return None;
    }
    let (package_path, raw_version) = match path_and_version.rsplit_once('@') {
        Some((package, version)) if !package.is_empty() && !version.is_empty() => {
            if package.contains('@') {
                return None;
            }
            (package, Some(version))
        }
        Some(_) => return None,
        None => (path_and_version, None),
    };
    let (raw_type, raw_name_path) = package_path.split_once('/')?;
    if raw_type.is_empty()
        || !raw_type.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphabetic()
                || (index > 0 && (byte.is_ascii_digit() || matches!(byte, b'.' | b'-')))
        })
    {
        return None;
    }
    let purl_type = raw_type.to_ascii_lowercase();
    let policy = policy_for_purl_type(&purl_type)?;
    let base_ecosystem = policy.ecosystem_name();
    let raw_segments = raw_name_path.split('/').collect::<Vec<_>>();
    if raw_segments.is_empty() || raw_segments.iter().any(|segment| segment.is_empty()) {
        return None;
    }
    let segments = raw_segments
        .into_iter()
        .map(strict_percent_decode)
        .collect::<Option<Vec<_>>>()?;
    if segments
        .iter()
        .any(|segment| segment.is_empty() || segment.contains('/'))
    {
        return None;
    }

    let (name, canonical_segments) = policy.canonical_purl_name(segments)?;
    let canonical_segments = canonical_segments
        .iter()
        .map(|segment| percent_encode(segment))
        .collect::<Vec<_>>();
    let version = match raw_version {
        Some(version) => Some(strict_percent_decode(version)?),
        None => None,
    }
    .filter(|version| !version.is_empty());

    let mut qualifiers = BTreeMap::<String, String>::new();
    let mut qualifier_keys = BTreeSet::new();
    let mut scoped_repository = None;
    if let Some(raw_qualifiers) = raw_qualifiers {
        for qualifier in raw_qualifiers.split('&') {
            let (raw_key, raw_value) = qualifier.split_once('=')?;
            if raw_key.is_empty()
                || raw_value.is_empty()
                || !raw_key.bytes().enumerate().all(|(index, byte)| {
                    byte.is_ascii_alphabetic()
                        || (index > 0
                            && (byte.is_ascii_digit() || matches!(byte, b'.' | b'-' | b'_')))
                })
            {
                return None;
            }
            let key = raw_key.to_ascii_lowercase();
            let mut value = strict_percent_decode(raw_value)?;
            if value.is_empty() || !qualifier_keys.insert(key.clone()) {
                return None;
            }
            if key == "repository_url" && policy.supports_repository_url() {
                value = policy.canonical_repository_url(&value)?;
                if policy.is_default_repository(&value) {
                    scoped_repository = None;
                    continue;
                }
                scoped_repository = Some(value.clone());
            }
            qualifiers.insert(key, value);
        }
    }

    let subpath = canonical_subpath(raw_subpath)?;
    let mut identity_purl = format!("pkg:{purl_type}/{}", canonical_segments.join("/"));
    if !qualifiers.is_empty() {
        identity_purl.push('?');
        identity_purl.push_str(
            &qualifiers
                .iter()
                .map(|(key, value)| format!("{key}={}", percent_encode(value)))
                .collect::<Vec<_>>()
                .join("&"),
        );
    }
    if let Some(subpath) = subpath {
        identity_purl.push('#');
        identity_purl.push_str(&subpath);
    }
    let ecosystem = match scoped_repository {
        Some(repository) => format!("{base_ecosystem}:{repository}"),
        None => base_ecosystem.to_owned(),
    };
    Some(ParsedPackagePurl {
        ecosystem,
        name,
        version,
        identity_purl,
    })
}

fn canonical_subpath(raw_subpath: Option<&str>) -> Option<Option<String>> {
    let Some(raw_subpath) = raw_subpath else {
        return Some(None);
    };
    let raw_subpath = raw_subpath.trim_matches('/');
    if raw_subpath.is_empty() {
        return Some(None);
    }
    let segments = raw_subpath
        .split('/')
        .map(strict_percent_decode)
        .collect::<Option<Vec<_>>>()?;
    if segments.iter().any(|segment| {
        segment.is_empty() || segment == "." || segment == ".." || segment.contains('/')
    }) {
        return None;
    }
    Some(Some(
        segments
            .iter()
            .map(|segment| percent_encode(segment))
            .collect::<Vec<_>>()
            .join("/"),
    ))
}

fn strict_percent_decode(value: &str) -> Option<String> {
    let mut decoded = Vec::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = bytes.get(index + 1..index + 3)?;
            let hex = std::str::from_utf8(hex).ok()?;
            decoded.push(u8::from_str_radix(hex, 16).ok()?);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).ok()
}

fn percent_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'~' | b':') {
            encoded.push(char::from(*byte));
        } else {
            use std::fmt::Write;
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OsvRange {
    pub range_type: String,
    pub events: Vec<(String, String)>,
}

/// A single version constraint from a CVE List affected record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CveVersionRange {
    pub version: Option<String>,
    pub status: Option<String>,
    pub version_type: Option<String>,
    pub less_than: Option<String>,
    pub less_than_or_equal: Option<String>,
    pub changes: Vec<CveVersionChange>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CveVersionChange {
    pub at: String,
    pub status: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct VersionMatch {
    pub status: String,
    pub confidence: String,
}

pub fn evaluate_version(ecosystem: &str, installed: &str, ranges: &[OsvRange]) -> VersionMatch {
    if ranges.is_empty() {
        return unknown();
    }

    let mut saw_not_affected = false;
    let mut saw_unknown = false;
    let mut saw_unsupported = false;
    let policy = policy_for_ecosystem(ecosystem);
    for range in ranges {
        let result = if range.range_type.eq_ignore_ascii_case("SEMVER") {
            policy.evaluate_semver_range(installed, range)
        } else if range.range_type.eq_ignore_ascii_case("ECOSYSTEM") {
            policy.evaluate_ecosystem_range(installed, range)
        } else {
            RangeEvaluation::Unsupported
        };
        match result {
            // Affected ranges are ORed. Once one supported range matches,
            // malformed or unsupported sibling ranges cannot undo that fact.
            RangeEvaluation::Affected => return affected(),
            RangeEvaluation::NotAffected => saw_not_affected = true,
            RangeEvaluation::Unknown => saw_unknown = true,
            RangeEvaluation::Unsupported => saw_unsupported = true,
        }
    }

    if saw_unknown {
        unknown()
    } else if saw_unsupported {
        unsupported()
    } else if saw_not_affected {
        not_affected()
    } else {
        unknown()
    }
}

/// Evaluates the CVE List forms that can be represented as a bounded version interval.
///
/// CNA records use a lower `version` plus `lessThan`/`lessThanOrEqual`, whereas
/// OSV stores introduced/fixed events. Translate the former to the latter so
/// both package query sources share ecosystem-specific comparison semantics.
pub fn evaluate_cve_version_ranges(
    ecosystem: &str,
    installed: &str,
    default_status: Option<&str>,
    versions: &[CveVersionRange],
) -> VersionMatch {
    for version in versions {
        let inline = match inline_cve_constraint(version) {
            Ok(inline) => inline,
            Err(()) => return unsupported(),
        };
        let version = inline.as_ref().unwrap_or(version);
        let lower = version
            .version
            .as_deref()
            .map(str::trim)
            .unwrap_or_default();
        if lower.is_empty() {
            return unknown();
        }
        let is_range = version.less_than.is_some() || version.less_than_or_equal.is_some();
        let result = if !is_range {
            if versions_equivalent(ecosystem, installed, lower) {
                CveConstraintEvaluation::Matched(cve_status(version.status.as_deref()))
            } else {
                CveConstraintEvaluation::NoMatch
            }
        } else {
            evaluate_cve_range(ecosystem, installed, version)
        };

        match result {
            CveConstraintEvaluation::Matched(status) => {
                return version_match_for_cve_status(status);
            }
            CveConstraintEvaluation::NoMatch => {}
            CveConstraintEvaluation::Unknown => return unknown(),
            CveConstraintEvaluation::Unsupported => return unsupported(),
        }
    }
    version_match_for_cve_status(cve_status(default_status))
}

/// Parses CVE List records that place a comma-separated constraint in `version` instead of
/// using `lessThan` or `lessThanOrEqual`.
fn inline_cve_constraint(version: &CveVersionRange) -> Result<Option<CveVersionRange>, ()> {
    if version.less_than.is_some() || version.less_than_or_equal.is_some() {
        return Ok(None);
    }
    let Some(expression) = version.version.as_deref().map(str::trim) else {
        return Ok(None);
    };
    if !expression.starts_with(['<', '>', '=']) {
        return Ok(None);
    }

    let mut lower = None;
    let mut less_than = None;
    let mut less_than_or_equal = None;
    for term in expression.split(',').map(str::trim) {
        if let Some(value) = term.strip_prefix(">=").map(str::trim) {
            if value.is_empty() || lower.replace(value.to_owned()).is_some() {
                return Err(());
            }
        } else if term.starts_with('>') {
            // An exclusive lower bound cannot be represented by the CVE List interval shape.
            return Err(());
        } else if let Some(value) = term.strip_prefix("<=").map(str::trim) {
            if value.is_empty() || less_than_or_equal.replace(value.to_owned()).is_some() {
                return Err(());
            }
        } else if let Some(value) = term.strip_prefix('<').map(str::trim) {
            if value.is_empty() || less_than.replace(value.to_owned()).is_some() {
                return Err(());
            }
        } else if let Some(value) = term
            .strip_prefix("==")
            .or_else(|| term.strip_prefix('='))
            .map(str::trim)
        {
            if expression.contains(',') || value.is_empty() {
                return Err(());
            }
            return Ok(Some(CveVersionRange {
                version: Some(value.to_owned()),
                status: version.status.clone(),
                version_type: version.version_type.clone(),
                less_than: None,
                less_than_or_equal: None,
                changes: version.changes.clone(),
            }));
        } else {
            return Err(());
        }
    }
    if less_than.is_some() && less_than_or_equal.is_some() {
        return Err(());
    }
    Ok(Some(CveVersionRange {
        version: Some(lower.unwrap_or_else(|| "*".to_owned())),
        status: version.status.clone(),
        version_type: version.version_type.clone(),
        // `*` is the existing representation of an open upper bound.
        less_than: less_than.or_else(|| less_than_or_equal.is_none().then(|| "*".to_owned())),
        less_than_or_equal,
        changes: version.changes.clone(),
    }))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CveStatus {
    Affected,
    Unaffected,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CveConstraintEvaluation {
    Matched(CveStatus),
    NoMatch,
    Unknown,
    Unsupported,
}

fn cve_status(status: Option<&str>) -> CveStatus {
    match status.map(str::trim) {
        Some(status) if status.eq_ignore_ascii_case("affected") => CveStatus::Affected,
        Some(status) if status.eq_ignore_ascii_case("unaffected") => CveStatus::Unaffected,
        _ => CveStatus::Unknown,
    }
}

fn version_match_for_cve_status(status: CveStatus) -> VersionMatch {
    match status {
        CveStatus::Affected => affected(),
        CveStatus::Unaffected => not_affected(),
        CveStatus::Unknown => unknown(),
    }
}

fn evaluate_cve_range(
    ecosystem: &str,
    installed: &str,
    version: &CveVersionRange,
) -> CveConstraintEvaluation {
    policy_for_ecosystem(ecosystem).evaluate_cve_range(installed, version)
}

pub(super) fn evaluate_ordered_cve_range<T>(
    installed: &str,
    version: &CveVersionRange,
    parse: impl Fn(&str) -> Option<T>,
    compare: impl Fn(&T, &T) -> Ordering,
    wildcard_matches: impl Fn(&T, &str) -> Option<bool>,
) -> CveConstraintEvaluation {
    if version.less_than.is_some() && version.less_than_or_equal.is_some() {
        return CveConstraintEvaluation::Unknown;
    }
    let Some(installed) = parse(installed) else {
        return CveConstraintEvaluation::Unknown;
    };
    let lower = version
        .version
        .as_deref()
        .map(str::trim)
        .unwrap_or_default();
    if lower != "*" && lower != "0" {
        let Some(lower) = parse(lower) else {
            return CveConstraintEvaluation::Unknown;
        };
        if compare(&installed, &lower) == Ordering::Less {
            return CveConstraintEvaluation::NoMatch;
        }
    }
    if let Some(upper) = version.less_than.as_deref().map(str::trim)
        && upper != "*"
    {
        if upper.contains('*') {
            let Some(matches) = wildcard_matches(&installed, upper) else {
                return CveConstraintEvaluation::Unsupported;
            };
            if !matches {
                return CveConstraintEvaluation::NoMatch;
            }
        } else {
            let Some(upper) = parse(upper) else {
                return CveConstraintEvaluation::Unknown;
            };
            if compare(&installed, &upper) != Ordering::Less {
                return CveConstraintEvaluation::NoMatch;
            }
        }
    }
    if let Some(upper) = version.less_than_or_equal.as_deref().map(str::trim) {
        if upper.contains('*') {
            return CveConstraintEvaluation::Unsupported;
        }
        let Some(upper) = parse(upper) else {
            return CveConstraintEvaluation::Unknown;
        };
        if compare(&installed, &upper) == Ordering::Greater {
            return CveConstraintEvaluation::NoMatch;
        }
    }

    let mut status = cve_status(version.status.as_deref());
    let mut changes = Vec::with_capacity(version.changes.len());
    for (index, change) in version.changes.iter().enumerate() {
        let Some(at) = parse(change.at.trim()) else {
            return CveConstraintEvaluation::Unknown;
        };
        changes.push((at, index, cve_status(Some(&change.status))));
    }
    changes.sort_by(|(left, left_index, _), (right, right_index, _)| {
        compare(left, right).then(left_index.cmp(right_index))
    });
    for (at, _, changed_status) in changes {
        if compare(&installed, &at) != Ordering::Less {
            status = changed_status;
        }
    }
    CveConstraintEvaluation::Matched(status)
}

pub(super) fn semver_matches_wildcard(version: &semver::Version, value: &str) -> Option<bool> {
    let parts = wildcard_numeric_prefix(value)?;
    if parts.len() > 3 {
        return None;
    }
    let release = [version.major, version.minor, version.patch];
    Some(
        parts
            .iter()
            .zip(release)
            .all(|(expected, actual)| *expected == actual),
    )
}

pub(super) fn pep440_matches_wildcard(version: &Pep440Version, value: &str) -> Option<bool> {
    let parts = wildcard_numeric_prefix(value)?;
    Some(parts.iter().enumerate().all(|(index, expected)| {
        version.release().get(index).copied().unwrap_or_default() == *expected
    }))
}

fn wildcard_numeric_prefix(value: &str) -> Option<Vec<u64>> {
    let prefix = value.strip_suffix('*')?.strip_suffix('.')?;
    if prefix.is_empty() {
        return None;
    }
    prefix
        .split('.')
        .map(str::parse::<u64>)
        .collect::<Result<Vec<_>, _>>()
        .ok()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RangeEvaluation {
    Affected,
    NotAffected,
    Unknown,
    Unsupported,
}

/// Evaluate OSV's alternating introduced/fixed/last_affected event sequence.
/// A range can contain multiple affected intervals, not merely one lower/upper bound.
pub(super) fn evaluate_parsed_range<T>(
    installed: &str,
    range: &OsvRange,
    parse: impl Fn(&str) -> Option<T>,
    compare: impl Fn(&T, &T) -> Ordering,
) -> RangeEvaluation {
    let Some(installed) = parse(installed) else {
        return RangeEvaluation::Unknown;
    };
    if !range
        .events
        .iter()
        .any(|(event_type, _)| event_type == "introduced")
    {
        return RangeEvaluation::Unknown;
    }

    let mut events = Vec::with_capacity(range.events.len());
    let mut saw_limit = false;
    let mut before_any_limit = false;
    for (index, (event_type, value)) in range.events.iter().enumerate() {
        match event_type.as_str() {
            "introduced" if value == "0" => events.push((None, index, event_type.as_str())),
            "introduced" | "fixed" | "last_affected" => {
                let Some(boundary) = parse(value) else {
                    return RangeEvaluation::Unknown;
                };
                events.push((Some(boundary), index, event_type.as_str()));
            }
            "limit" if value.contains('*') => {
                saw_limit = true;
                before_any_limit = true;
            }
            "limit" => {
                saw_limit = true;
                let Some(limit) = parse(value) else {
                    return RangeEvaluation::Unknown;
                };
                before_any_limit |= compare(&installed, &limit) == Ordering::Less;
            }
            _ => return RangeEvaluation::Unknown,
        }
    }
    if saw_limit && !before_any_limit {
        return RangeEvaluation::NotAffected;
    }

    // OSV defines events as a version-ordered timeline. Feeds normally publish
    // them in order, but valid records are not required to be pre-sorted.
    events.sort_by(|(left, left_index, _), (right, right_index, _)| {
        let ordering = match (left, right) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Less,
            (Some(_), None) => Ordering::Greater,
            (Some(left), Some(right)) => compare(left, right),
        };
        ordering.then(left_index.cmp(right_index))
    });
    let mut vulnerable = false;
    for (boundary, _, event_type) in events {
        match event_type {
            "introduced"
                if boundary
                    .as_ref()
                    .is_none_or(|start| compare(&installed, start) != Ordering::Less) =>
            {
                vulnerable = true;
            }
            "fixed"
                if boundary
                    .as_ref()
                    .is_some_and(|fixed| compare(&installed, fixed) != Ordering::Less) =>
            {
                vulnerable = false;
            }
            "last_affected"
                if boundary.as_ref().is_some_and(|last_affected| {
                    compare(&installed, last_affected) == Ordering::Greater
                }) =>
            {
                vulnerable = false;
            }
            _ => {}
        }
    }
    if vulnerable {
        RangeEvaluation::Affected
    } else {
        RangeEvaluation::NotAffected
    }
}

fn affected() -> VersionMatch {
    VersionMatch {
        status: "affected".to_owned(),
        confidence: "high".to_owned(),
    }
}

fn not_affected() -> VersionMatch {
    VersionMatch {
        status: "not_affected".to_owned(),
        confidence: "high".to_owned(),
    }
}

fn unsupported() -> VersionMatch {
    VersionMatch {
        status: "unsupported_version_scheme".to_owned(),
        confidence: "low".to_owned(),
    }
}

fn unknown() -> VersionMatch {
    VersionMatch {
        status: "unknown".to_owned(),
        confidence: "low".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_name_normalization_is_ecosystem_specific() {
        assert_eq!(
            normalize_package_name("PyPI", "Friendly-._-Bard"),
            "friendly-bard"
        );
        assert_eq!(
            normalize_package_name("NuGet", "Example.Core"),
            "example.core"
        );
        assert_eq!(
            normalize_package_name("GitHub Actions", "Owner/Repository"),
            "owner/repository"
        );
        assert_eq!(
            normalize_package_name("Pub", "Friendly-Package"),
            "friendly_package"
        );
        assert_ne!(normalize_package_name("npm", "node_forge"), "node-forge");
        assert_ne!(
            normalize_package_name("Maven", "org.example/core"),
            "org.example:core"
        );
        assert_ne!(
            normalize_package_name("crates.io", "example_crate"),
            "example-crate"
        );
    }

    #[test]
    fn cve_component_normalization_ignores_common_separators() {
        for (left, right) in [
            ("djangorestframework", "django-rest-framework"),
            ("httpcore", "http-core"),
            ("mysqlclient", "mysql client"),
            ("font-awesome", "font awesome"),
            ("pillow-heif", "pillow_heif"),
        ] {
            assert_eq!(
                normalize_cve_component_name(left),
                normalize_cve_component_name(right)
            );
        }
    }

    #[test]
    fn cve_inline_constraints_and_unaffected_status_are_evaluated() {
        let range = |version: &str, status: &str| CveVersionRange {
            version: Some(version.to_owned()),
            status: Some(status.to_owned()),
            version_type: Some("semver".to_owned()),
            less_than: None,
            less_than_or_equal: None,
            changes: Vec::new(),
        };

        assert_eq!(
            evaluate_cve_version_ranges(
                "npm",
                "3.17.1",
                Some("unaffected"),
                &[range("< 3.17.2", "affected")],
            )
            .status,
            "affected"
        );
        assert_eq!(
            evaluate_cve_version_ranges(
                "npm",
                "2.5.0",
                Some("unaffected"),
                &[range(">= 2.0.0, < 2.5.0", "affected")],
            )
            .status,
            "not_affected"
        );
        assert_eq!(
            evaluate_cve_version_ranges(
                "npm",
                "9.0.0",
                Some("unaffected"),
                &[range(">=0.0.0", "affected")],
            )
            .status,
            "affected"
        );
        assert_eq!(
            evaluate_cve_version_ranges(
                "npm",
                "1.0.0",
                Some("affected"),
                &[range("=1.0.0", "unaffected")],
            )
            .status,
            "not_affected"
        );
    }

    #[test]
    fn concrete_installed_versions_use_ecosystem_parsers() {
        for (ecosystem, version) in [
            ("crates.io", "1.2.3-alpha.1"),
            ("Go", "v1.2.3-20240101120000-abcdef123456"),
            ("GitHub Actions", "v4.1.2"),
            ("Maven", "1.0-SNAPSHOT"),
            ("npm", "v1.5.0"),
            ("NuGet", "1.0.0-ALPHA.2"),
            ("PyPI", "1!2.0"),
            ("Pub", "1.0.0+3"),
            ("RubyGems", "1.0.pre.2"),
        ] {
            assert!(
                is_concrete_package_version(ecosystem, version),
                "{ecosystem} should accept {version}"
            );
        }
    }

    #[test]
    fn package_constraints_are_never_concrete_installed_versions() {
        for ecosystem in [
            "crates.io",
            "Go",
            "GitHub Actions",
            "Maven",
            "npm",
            "NuGet",
            "PyPI",
            "Pub",
            "RubyGems",
        ] {
            for constraint in [
                ">=2.0",
                "!=2.1",
                "^1.2",
                "~1.2",
                "1.2.*",
                ">=1.0,<2.0",
                "1.0 || 2.0",
            ] {
                assert!(
                    !is_concrete_package_version(ecosystem, constraint),
                    "{ecosystem} should reject {constraint}"
                );
            }
        }
    }

    #[test]
    fn explicit_pypi_versions_use_pep440_equivalence() {
        assert!(versions_equivalent("PyPI", "1.0", "1.0.0"));
        assert!(versions_equivalent(
            "PyPI",
            "not-a-version",
            "not-a-version"
        ));
        assert!(!versions_equivalent("npm", "1.0", "1.0.0"));
    }

    #[test]
    fn explicit_nuget_versions_use_nuget_equivalence() {
        for (left, right) in [
            ("1", "1.0.0"),
            ("1.0.0.0", "01.00"),
            ("1.0.0-ALPHA", "1-alpha"),
            ("1.0.0+build.1", "1+other"),
        ] {
            assert!(
                versions_equivalent("NuGet", left, right),
                "{left} != {right}"
            );
        }
        assert!(!versions_equivalent("NuGet", "1.0.1", "1.0.0"));
        for invalid in ["1.0.0-", "1.0.0+", "1.0.0-alpha..1", "1.0.0+a..b"] {
            assert!(!versions_equivalent("NuGet", invalid, "1.0.0"));
        }
    }

    #[test]
    fn explicit_rubygems_versions_use_canonical_segments() {
        assert!(versions_equivalent("RubyGems", "1", "1.0.0"));
        assert!(versions_equivalent("RubyGems", "2.3", "2.3.0"));
        assert!(versions_equivalent("RubyGems", "1.0.0.pre", "1.0.pre"));
        assert!(!versions_equivalent("RubyGems", "2.3.0.pre", "2.3"));
        assert!(!versions_equivalent("RubyGems", "2.3.1", "2.3"));
    }

    #[test]
    fn explicit_versions_accept_only_conventional_v_prefixes() {
        for ecosystem in ["Go", "npm", "GitHub Actions"] {
            assert!(versions_equivalent(ecosystem, "v1.2.3", "1.2.3"));
            assert!(!versions_equivalent(ecosystem, "vv1.2.3", "1.2.3"));
        }
        assert!(!versions_equivalent("crates.io", "v1.2.3", "1.2.3"));
    }

    #[test]
    fn ecosystem_policies_route_semver_prefix_rules_consistently() {
        let range = OsvRange {
            range_type: "SEMVER".to_owned(),
            events: vec![
                ("introduced".to_owned(), "1.0.0".to_owned()),
                ("fixed".to_owned(), "2.0.0".to_owned()),
            ],
        };
        for ecosystem in ["Go", "npm", "GitHub Actions"] {
            assert_eq!(
                evaluate_version(ecosystem, "v1.5.0", std::slice::from_ref(&range)).status,
                "affected",
                "{ecosystem} should use its v-prefix policy"
            );
        }
        assert_eq!(
            evaluate_version("crates.io", "v1.5.0", &[range]).status,
            "unknown"
        );

        let npm_range = CveVersionRange {
            version: Some("1.0.0".to_owned()),
            status: Some("affected".to_owned()),
            version_type: Some("npm".to_owned()),
            less_than: Some("2.0.0".to_owned()),
            less_than_or_equal: None,
            changes: Vec::new(),
        };
        assert_eq!(
            evaluate_cve_version_ranges("npm", "v1.5.0", Some("unaffected"), &[npm_range]).status,
            "affected"
        );
    }

    #[test]
    fn osv_identity_purl_omits_the_installed_version() {
        assert_eq!(
            package_identity_purl("pkg:maven/org.example/core@1.2.3?type=jar"),
            "pkg:maven/org.example/core?type=jar"
        );
        assert_eq!(
            package_identity_purl("pkg:npm/%40scope/name@1.2.3"),
            "pkg:npm/%40scope/name"
        );
        assert_eq!(
            package_identity_purl("pkg:npm/%40scope/name"),
            "pkg:npm/%40scope/name"
        );
        assert_eq!(
            package_identity_purl("pkg://npm/%40scope/name@1.2.3%2Bbuild?arch=x64#lib"),
            "pkg:npm/%40scope/name?arch=x64#lib"
        );
    }

    #[test]
    fn canonical_purl_identity_normalizes_equivalent_spelling() {
        let parsed =
            parse_package_purl("PKG://NPM/%40scope/name@1.2.3%2bbuild?OS=linux&arch=x64#/lib/")
                .unwrap();
        assert_eq!(parsed.ecosystem, "npm");
        assert_eq!(parsed.name, "@scope/name");
        assert_eq!(parsed.version.as_deref(), Some("1.2.3+build"));
        assert_eq!(
            parsed.identity_purl,
            "pkg:npm/%40scope/name?arch=x64&os=linux#lib"
        );

        assert_eq!(
            parse_package_purl("pkg:nuget/Example.Core@1.0.0")
                .unwrap()
                .identity_purl,
            "pkg:nuget/example.core"
        );
        assert_eq!(
            parse_package_purl("pkg:pypi/Friendly_._Bard@1.0")
                .unwrap()
                .identity_purl,
            "pkg:pypi/friendly-bard"
        );
    }

    #[test]
    fn strict_purl_parser_rejects_malformed_encoding_and_structure() {
        for purl in [
            "pkg:npm/ex%ZZample@1.0.0",
            "pkg:npm/%FF@1.0.0",
            "pkg:npm/example?arch=x64&ARCH=arm64",
            "pkg:npm/example#lib/../secret",
            "pkg:cargo/namespace/example@1.0.0",
            "pkg:npm/example@",
        ] {
            assert!(parse_package_purl(purl).is_none(), "accepted {purl}");
        }
    }

    #[test]
    fn maven_repository_identity_is_url_aware() {
        let central = parse_package_purl(
            "pkg:maven/org.example/core@1?REPOSITORY_URL=HTTPS%3A%2F%2FREPO.MAVEN.APACHE.ORG%2Fmaven2%2F",
        )
        .unwrap();
        assert_eq!(central.ecosystem, "Maven");
        assert_eq!(central.identity_purl, "pkg:maven/org.example/core");

        let remote = parse_package_purl(
            "pkg:maven/org.example/core@1?repository_url=HTTPS%3A%2F%2FRepo.Example%2FPath%2F",
        )
        .unwrap();
        assert_eq!(remote.ecosystem, "Maven:https://repo.example/Path");
        assert_eq!(
            remote.identity_purl,
            "pkg:maven/org.example/core?repository_url=https:%2F%2Frepo.example%2FPath"
        );
        assert_eq!(
            ecosystem_identity_key("MAVEN:HTTPS://Repo.Example/Path/"),
            "maven:https://repo.example/Path"
        );
        assert_eq!(
            ecosystem_identity_key("Maven:https://repo.maven.apache.org/maven2/"),
            "maven"
        );
    }

    #[test]
    fn github_and_pub_purls_use_ecosystem_name_rules() {
        assert_eq!(
            parse_package_purl("pkg:github/Owner/Repository@v1")
                .unwrap()
                .identity_purl,
            "pkg:github/owner/repository"
        );
        assert_eq!(
            parse_package_purl("pkg:pub/Friendly-Package@1.0.0")
                .unwrap()
                .identity_purl,
            "pkg:pub/friendly_package"
        );
    }

    #[test]
    fn purl_identity_parsing_is_ecosystem_aware() {
        assert_eq!(
            package_identity_from_purl("pkg://npm/%40scope/name@1.2.3?arch=x64#lib"),
            Some(("npm".to_owned(), "@scope/name".to_owned()))
        );
        assert_eq!(
            package_identity_from_purl(
                "pkg:maven/org.example/core@1?repository_url=https%3A%2F%2Frepo.example%2Fmaven"
            ),
            Some((
                "Maven:https://repo.example/maven".to_owned(),
                "org.example:core".to_owned()
            ))
        );
        assert!(package_identity_from_purl("npm/name@1").is_none());
        assert!(package_identity_from_purl("pkg:maven/org.example%2Fcore@1").is_none());
    }

    #[test]
    fn semver_range_distinguishes_confirmed_and_candidate_status() {
        let range = OsvRange {
            range_type: "SEMVER".to_owned(),
            events: vec![
                ("introduced".to_owned(), "1.0.0".to_owned()),
                ("fixed".to_owned(), "2.0.0".to_owned()),
            ],
        };
        assert_eq!(
            evaluate_version("crates.io", "1.5.0", std::slice::from_ref(&range)).status,
            "affected"
        );
        assert_eq!(
            evaluate_version("crates.io", "2.0.0", std::slice::from_ref(&range)).status,
            "not_affected"
        );
        let inclusive = OsvRange {
            range_type: "SEMVER".to_owned(),
            events: vec![
                ("introduced".to_owned(), "1.0.0".to_owned()),
                ("last_affected".to_owned(), "1.5.0".to_owned()),
            ],
        };
        assert_eq!(
            evaluate_version("crates.io", "1.5.0", std::slice::from_ref(&inclusive)).status,
            "affected"
        );
        assert_eq!(
            evaluate_version("crates.io", "1.5.1", &[inclusive]).status,
            "not_affected"
        );
        assert_eq!(
            evaluate_version("crates.io", "invalid", &[]).status,
            "unknown"
        );
        for ecosystem in ["npm", "Go", "NuGet", "Pub"] {
            assert_eq!(
                evaluate_version(ecosystem, "1.5.0", std::slice::from_ref(&range)).status,
                "affected"
            );
        }
    }

    #[test]
    fn go_and_rust_semver_ranges_are_evaluated() {
        let range = OsvRange {
            range_type: "SEMVER".to_owned(),
            events: vec![
                ("introduced".to_owned(), "0".to_owned()),
                ("fixed".to_owned(), "1.2.0".to_owned()),
            ],
        };
        // Go module versions conventionally carry a leading v and may use a
        // semver prerelease-shaped pseudo-version.
        assert_eq!(
            evaluate_version(
                "Go",
                "v1.1.0-20240101120000-abcdef123456",
                std::slice::from_ref(&range)
            )
            .status,
            "affected"
        );
        assert_eq!(
            evaluate_version("Go", "v1.2.0", std::slice::from_ref(&range)).status,
            "not_affected"
        );
        assert_eq!(
            evaluate_version("crates.io", "1.1.0", &[range]).status,
            "affected"
        );

        let range = OsvRange {
            range_type: "SEMVER".to_owned(),
            events: vec![("introduced".to_owned(), "0".to_owned())],
        };
        assert_eq!(
            evaluate_version("crates.io", "v1.1.0", std::slice::from_ref(&range)).status,
            "unknown"
        );
        assert_eq!(
            evaluate_version("Go", "vv1.1.0", &[range]).status,
            "unknown"
        );
    }

    #[test]
    fn pypi_ecosystem_ranges_use_pep440() {
        let range = OsvRange {
            range_type: "ECOSYSTEM".to_owned(),
            events: vec![
                ("introduced".to_owned(), "2.0rc1".to_owned()),
                ("fixed".to_owned(), "2.0.0.post1".to_owned()),
            ],
        };
        assert_eq!(
            evaluate_version("PyPI", "2.0", std::slice::from_ref(&range)).status,
            "affected"
        );
        assert_eq!(
            evaluate_version("PyPI", "2.0.post1", &[range]).status,
            "not_affected"
        );

        let semver = OsvRange {
            range_type: "SEMVER".to_owned(),
            events: vec![("introduced".to_owned(), "1.0.0".to_owned())],
        };
        assert_eq!(
            evaluate_version("PyPI", "1.5", &[semver]).status,
            "unknown",
            "SEMVER ranges must not silently use PEP 440 ordering"
        );
    }

    #[test]
    fn ecosystem_ranges_use_their_native_supported_ordering() {
        let action = OsvRange {
            range_type: "ECOSYSTEM".to_owned(),
            events: vec![
                ("introduced".to_owned(), "4.0.0".to_owned()),
                ("fixed".to_owned(), "4.1.3".to_owned()),
            ],
        };
        assert_eq!(
            evaluate_version("GitHub Actions", "v4.1.2", std::slice::from_ref(&action)).status,
            "affected"
        );
        assert_eq!(
            evaluate_version("GitHub Actions", "v4", &[action]).status,
            "unknown",
            "a moving major action tag cannot be mapped to an exact release"
        );

        let pub_range = OsvRange {
            range_type: "ECOSYSTEM".to_owned(),
            events: vec![
                ("introduced".to_owned(), "1.0.0".to_owned()),
                ("fixed".to_owned(), "2.0.0".to_owned()),
            ],
        };
        assert_eq!(
            evaluate_version("Pub", "1.5.0", &[pub_range]).status,
            "affected"
        );
        let pub_build = OsvRange {
            range_type: "ECOSYSTEM".to_owned(),
            events: vec![
                ("introduced".to_owned(), "1.0.0+2".to_owned()),
                ("fixed".to_owned(), "1.0.0+10".to_owned()),
            ],
        };
        assert_eq!(
            evaluate_version("Pub", "1.0.0+3", &[pub_build]).status,
            "affected"
        );

        for ecosystem in ["crates.io", "Go"] {
            let range = OsvRange {
                range_type: "ECOSYSTEM".to_owned(),
                events: vec![
                    ("introduced".to_owned(), "1.2.3-alpha.1".to_owned()),
                    ("fixed".to_owned(), "1.2.3".to_owned()),
                ],
            };
            let installed = if ecosystem == "Go" {
                "v1.2.3-alpha.2"
            } else {
                "1.2.3-alpha.2"
            };
            assert_eq!(
                evaluate_version(ecosystem, installed, &[range]).status,
                "affected"
            );
        }

        let maven = OsvRange {
            range_type: "ECOSYSTEM".to_owned(),
            events: vec![
                ("introduced".to_owned(), "1.0-rc1".to_owned()),
                ("fixed".to_owned(), "1.0".to_owned()),
            ],
        };
        assert_eq!(
            evaluate_version("Maven", "1.0-SNAPSHOT", &[maven]).status,
            "affected"
        );

        let nuget = OsvRange {
            range_type: "ECOSYSTEM".to_owned(),
            events: vec![
                ("introduced".to_owned(), "1.0.0-alpha.1".to_owned()),
                ("fixed".to_owned(), "1.0.0".to_owned()),
            ],
        };
        assert_eq!(
            evaluate_version("NuGet", "1.0.0-ALPHA.2", std::slice::from_ref(&nuget)).status,
            "affected"
        );
        assert_eq!(
            evaluate_version("NuGet", "1.0.0", &[nuget]).status,
            "not_affected"
        );

        let gem = OsvRange {
            range_type: "ECOSYSTEM".to_owned(),
            events: vec![
                ("introduced".to_owned(), "1.0.0.pre".to_owned()),
                ("fixed".to_owned(), "1.0.0".to_owned()),
            ],
        };
        assert_eq!(
            evaluate_version("RubyGems", "1.0.pre.2", std::slice::from_ref(&gem)).status,
            "affected"
        );
        assert_eq!(
            evaluate_version("RubyGems", "1.0", &[gem]).status,
            "not_affected"
        );
    }

    #[test]
    fn cve_list_versions_share_package_version_evaluation() {
        let bounded = CveVersionRange {
            version: Some("1.0.0".to_owned()),
            status: Some("affected".to_owned()),
            version_type: Some("semver".to_owned()),
            less_than: Some("2.0.0".to_owned()),
            less_than_or_equal: None,
            changes: Vec::new(),
        };
        assert_eq!(
            evaluate_cve_version_ranges("npm", "1.5.0", None, std::slice::from_ref(&bounded))
                .status,
            "affected"
        );
        assert_eq!(
            evaluate_cve_version_ranges("npm", "2.0.0", None, std::slice::from_ref(&bounded))
                .status,
            "unknown"
        );
        assert_eq!(
            evaluate_cve_version_ranges("npm", "2.0.0", Some("unaffected"), &[bounded]).status,
            "not_affected"
        );
        let all_versions = CveVersionRange {
            version: Some("0.0.0".to_owned()),
            status: Some("affected".to_owned()),
            version_type: Some("semver".to_owned()),
            less_than: Some("*".to_owned()),
            less_than_or_equal: None,
            changes: Vec::new(),
        };
        assert_eq!(
            evaluate_cve_version_ranges("npm", "1.5.0", None, &[all_versions]).status,
            "affected"
        );

        let maven = CveVersionRange {
            version: Some("1.0.0".to_owned()),
            status: Some("affected".to_owned()),
            version_type: Some("maven".to_owned()),
            less_than: Some("2.0.0".to_owned()),
            less_than_or_equal: None,
            changes: Vec::new(),
        };
        assert_eq!(
            evaluate_cve_version_ranges("Maven", "1.5.0", None, &[maven]).status,
            "affected"
        );
    }

    #[test]
    fn cve_native_version_types_are_dispatched_by_ecosystem_policy() {
        for (ecosystem, version_type, installed, lower, upper) in [
            ("Maven", "maven", "1.0-SNAPSHOT", "1.0-rc1", "1.0"),
            ("NuGet", "nuget", "1.0.0-rc.2", "1.0.0-rc.1", "1.0.0"),
            ("RubyGems", "ruby", "1.0.pre.2", "1.0.pre.1", "1.0"),
            ("Pub", "pub", "1.0.0+3", "1.0.0+2", "1.0.0+10"),
            ("Go", "go", "v1.2.3", "v1.0.0", "v2.0.0"),
            ("crates.io", "cargo", "1.2.3", "1.0.0", "2.0.0"),
        ] {
            let range = CveVersionRange {
                version: Some(lower.to_owned()),
                status: Some("affected".to_owned()),
                version_type: Some(version_type.to_owned()),
                less_than: Some(upper.to_owned()),
                less_than_or_equal: None,
                changes: Vec::new(),
            };
            assert_eq!(
                evaluate_cve_version_ranges(ecosystem, installed, None, &[range]).status,
                "affected",
                "{ecosystem}/{version_type}"
            );
        }
    }

    #[test]
    fn cve_exact_versions_defaults_changes_and_wildcards_follow_cve_rules() {
        let exact_custom = CveVersionRange {
            version: Some("1.0-final".to_owned()),
            status: Some("affected".to_owned()),
            version_type: Some("maven".to_owned()),
            less_than: None,
            less_than_or_equal: None,
            changes: Vec::new(),
        };
        assert_eq!(
            evaluate_cve_version_ranges(
                "Maven",
                "1.0-final",
                Some("unaffected"),
                std::slice::from_ref(&exact_custom)
            )
            .status,
            "affected"
        );
        assert_eq!(
            evaluate_cve_version_ranges("Maven", "2.0-final", Some("unaffected"), &[exact_custom])
                .status,
            "not_affected"
        );

        let exception = CveVersionRange {
            version: Some("1.0.0".to_owned()),
            status: Some("unaffected".to_owned()),
            version_type: Some("semver".to_owned()),
            less_than: Some("2.0.0".to_owned()),
            less_than_or_equal: None,
            changes: Vec::new(),
        };
        assert_eq!(
            evaluate_cve_version_ranges(
                "npm",
                "1.5.0",
                Some("affected"),
                std::slice::from_ref(&exception)
            )
            .status,
            "not_affected"
        );
        assert_eq!(
            evaluate_cve_version_ranges("npm", "2.5.0", Some("affected"), &[exception]).status,
            "affected"
        );

        let changes = CveVersionRange {
            version: Some("1.0.0".to_owned()),
            status: Some("unaffected".to_owned()),
            version_type: Some("semver".to_owned()),
            less_than: Some("4.0.0".to_owned()),
            less_than_or_equal: None,
            changes: vec![
                CveVersionChange {
                    at: "3.0.0".to_owned(),
                    status: "unaffected".to_owned(),
                },
                CveVersionChange {
                    at: "2.0.0".to_owned(),
                    status: "affected".to_owned(),
                },
            ],
        };
        assert_eq!(
            evaluate_cve_version_ranges(
                "npm",
                "2.5.0",
                Some("unaffected"),
                std::slice::from_ref(&changes)
            )
            .status,
            "affected"
        );
        assert_eq!(
            evaluate_cve_version_ranges("npm", "3.5.0", Some("unaffected"), &[changes]).status,
            "not_affected"
        );

        let wildcard = CveVersionRange {
            version: Some("1.0.0".to_owned()),
            status: Some("affected".to_owned()),
            version_type: Some("semver".to_owned()),
            less_than: Some("1.*".to_owned()),
            less_than_or_equal: None,
            changes: Vec::new(),
        };
        assert_eq!(
            evaluate_cve_version_ranges(
                "npm",
                "1.99.0",
                Some("unaffected"),
                std::slice::from_ref(&wildcard)
            )
            .status,
            "affected"
        );
        assert_eq!(
            evaluate_cve_version_ranges("npm", "2.0.0", Some("unaffected"), &[wildcard]).status,
            "not_affected"
        );
        assert_eq!(
            evaluate_cve_version_ranges("npm", "9.0.0", None, &[]).status,
            "unknown"
        );
    }

    #[test]
    fn cve_exact_and_wildcard_entries_follow_the_published_matching_algorithm() {
        let exact_wildcard = CveVersionRange {
            version: Some("*".to_owned()),
            status: Some("affected".to_owned()),
            version_type: None,
            less_than: None,
            less_than_or_equal: None,
            changes: Vec::new(),
        };
        assert_eq!(
            evaluate_cve_version_ranges("npm", "1.2.3", Some("unaffected"), &[exact_wildcard])
                .status,
            "not_affected",
            "an asterisk is special only as a lessThan upper limit"
        );

        let changes_without_range = CveVersionRange {
            version: Some("1.0.0".to_owned()),
            status: Some("affected".to_owned()),
            version_type: Some("semver".to_owned()),
            less_than: None,
            less_than_or_equal: None,
            changes: vec![CveVersionChange {
                at: "2.0.0".to_owned(),
                status: "unaffected".to_owned(),
            }],
        };
        assert_eq!(
            evaluate_cve_version_ranges(
                "npm",
                "1.5.0",
                Some("unaffected"),
                &[changes_without_range]
            )
            .status,
            "not_affected",
            "changes do not turn an exact entry into an unbounded range"
        );

        let semver_wildcard = CveVersionRange {
            version: Some("1.0.0".to_owned()),
            status: Some("affected".to_owned()),
            version_type: Some("semver".to_owned()),
            less_than: Some("1.*".to_owned()),
            less_than_or_equal: None,
            changes: Vec::new(),
        };
        assert_eq!(
            evaluate_cve_version_ranges(
                "npm",
                "2.0.0-alpha",
                Some("unaffected"),
                &[semver_wildcard]
            )
            .status,
            "not_affected",
            "a next-series prerelease is not part of the wildcard branch"
        );

        let pep440_wildcard = CveVersionRange {
            version: Some("1".to_owned()),
            status: Some("affected".to_owned()),
            version_type: Some("python".to_owned()),
            less_than: Some("1.*".to_owned()),
            less_than_or_equal: None,
            changes: Vec::new(),
        };
        assert_eq!(
            evaluate_cve_version_ranges("PyPI", "2.0a1", Some("unaffected"), &[pep440_wildcard])
                .status,
            "not_affected"
        );

        let missing_version_type = CveVersionRange {
            version: Some("1".to_owned()),
            status: Some("unaffected".to_owned()),
            version_type: None,
            less_than: Some("2".to_owned()),
            less_than_or_equal: None,
            changes: Vec::new(),
        };
        assert_eq!(
            evaluate_cve_version_ranges("PyPI", "1.5", Some("affected"), &[missing_version_type])
                .status,
            "unsupported_version_scheme",
            "a CVE range cannot be evaluated without its required versionType"
        );

        let inclusive_wildcard = CveVersionRange {
            version: Some("1.0.0".to_owned()),
            status: Some("affected".to_owned()),
            version_type: Some("semver".to_owned()),
            less_than: None,
            less_than_or_equal: Some("*".to_owned()),
            changes: Vec::new(),
        };
        assert_eq!(
            evaluate_cve_version_ranges("npm", "1.5.0", Some("unaffected"), &[inclusive_wildcard])
                .status,
            "unsupported_version_scheme"
        );
    }

    #[test]
    fn ecosystem_ranges_use_their_native_version_policy() {
        let range = OsvRange {
            range_type: "ECOSYSTEM".to_owned(),
            events: vec![
                ("introduced".to_owned(), "1.0.0".to_owned()),
                ("fixed".to_owned(), "2.0.0".to_owned()),
            ],
        };
        assert_eq!(
            evaluate_version("Maven", "1.5.0", std::slice::from_ref(&range)).status,
            "affected"
        );
        assert_eq!(
            evaluate_version("npm", "1.5.0", &[range]).status,
            "affected"
        );
    }

    #[test]
    fn malformed_empty_range_is_unknown_not_affected() {
        let range = OsvRange {
            range_type: "SEMVER".to_owned(),
            events: Vec::new(),
        };
        assert_eq!(evaluate_version("npm", "1.5.0", &[range]).status, "unknown");
    }

    #[test]
    fn multiple_osv_intervals_are_evaluated_independently() {
        let range = OsvRange {
            range_type: "SEMVER".to_owned(),
            events: vec![
                ("introduced".to_owned(), "1.0.0".to_owned()),
                ("fixed".to_owned(), "1.1.0".to_owned()),
                ("introduced".to_owned(), "1.2.0".to_owned()),
                ("fixed".to_owned(), "1.3.0".to_owned()),
            ],
        };
        assert_eq!(
            evaluate_version("npm", "1.0.5", std::slice::from_ref(&range)).status,
            "affected"
        );
        assert_eq!(
            evaluate_version("npm", "1.1.5", std::slice::from_ref(&range)).status,
            "not_affected"
        );
        assert_eq!(
            evaluate_version("npm", "1.2.5", &[range]).status,
            "affected"
        );
    }

    #[test]
    fn osv_events_are_evaluated_in_version_order() {
        let unsorted = OsvRange {
            range_type: "SEMVER".to_owned(),
            events: vec![
                ("fixed".to_owned(), "2.0.0".to_owned()),
                ("introduced".to_owned(), "1.0.0".to_owned()),
            ],
        };
        assert_eq!(
            evaluate_version("crates.io", "1.5.0", std::slice::from_ref(&unsorted)).status,
            "affected"
        );
        assert_eq!(
            evaluate_version("crates.io", "2.0.0", &[unsorted]).status,
            "not_affected"
        );
    }

    #[test]
    fn limit_events_bound_semver_ranges() {
        let range = OsvRange {
            range_type: "SEMVER".to_owned(),
            events: vec![
                ("introduced".to_owned(), "1.0.0".to_owned()),
                ("limit".to_owned(), "2.0.0".to_owned()),
            ],
        };
        assert_eq!(
            evaluate_version("crates.io", "1.9.9", std::slice::from_ref(&range)).status,
            "affected"
        );
        assert_eq!(
            evaluate_version("crates.io", "2.0.0", &[range]).status,
            "not_affected"
        );

        let multiple_limits = OsvRange {
            range_type: "SEMVER".to_owned(),
            events: vec![
                ("introduced".to_owned(), "1.0.0".to_owned()),
                ("limit".to_owned(), "2.0.0".to_owned()),
                ("limit".to_owned(), "4.0.0".to_owned()),
            ],
        };
        assert_eq!(
            evaluate_version("crates.io", "3.0.0", &[multiple_limits]).status,
            "affected",
            "OSV limits are alternative branch ceilings"
        );
        let infinite_limit = OsvRange {
            range_type: "SEMVER".to_owned(),
            events: vec![
                ("introduced".to_owned(), "1.0.0".to_owned()),
                ("limit".to_owned(), "2.*".to_owned()),
            ],
        };
        assert_eq!(
            evaluate_version("crates.io", "99.0.0", &[infinite_limit]).status,
            "affected"
        );
    }

    #[test]
    fn malformed_range_without_introduced_is_unknown() {
        let range = OsvRange {
            range_type: "SEMVER".to_owned(),
            events: vec![("fixed".to_owned(), "2.0.0".to_owned())],
        };
        assert_eq!(evaluate_version("npm", "1.0.0", &[range]).status, "unknown");
    }

    #[test]
    fn a_confirmed_affected_range_wins_over_malformed_siblings() {
        let affected_range = OsvRange {
            range_type: "SEMVER".to_owned(),
            events: vec![("introduced".to_owned(), "1.0.0".to_owned())],
        };
        let malformed = OsvRange {
            range_type: "SEMVER".to_owned(),
            events: vec![("fixed".to_owned(), "2.0.0".to_owned())],
        };
        for ranges in [
            vec![affected_range.clone(), malformed.clone()],
            vec![malformed.clone(), affected_range.clone()],
        ] {
            assert_eq!(evaluate_version("npm", "1.5.0", &ranges).status, "affected");
        }
    }

    #[test]
    fn native_maven_range_combines_with_semver_ranges() {
        let supported = OsvRange {
            range_type: "SEMVER".to_owned(),
            events: vec![
                ("introduced".to_owned(), "1.0.0".to_owned()),
                ("fixed".to_owned(), "2.0.0".to_owned()),
            ],
        };
        let unsupported = OsvRange {
            range_type: "ECOSYSTEM".to_owned(),
            events: vec![("introduced".to_owned(), "3.0-final".to_owned())],
        };
        assert_eq!(
            evaluate_version("Maven", "3.0.0", &[supported.clone(), unsupported.clone()]).status,
            "affected"
        );
        assert_eq!(
            evaluate_version("Maven", "1.5.0", &[supported, unsupported]).status,
            "affected"
        );
    }

    #[test]
    fn semver_prerelease_and_build_precedence_is_respected() {
        let range = OsvRange {
            range_type: "SEMVER".to_owned(),
            events: vec![
                ("introduced".to_owned(), "1.0.0-alpha".to_owned()),
                ("fixed".to_owned(), "1.0.0".to_owned()),
            ],
        };
        assert_eq!(
            evaluate_version("npm", "1.0.0-alpha.2+build.7", std::slice::from_ref(&range)).status,
            "affected"
        );
        assert_eq!(
            evaluate_version("npm", "1.0.0+build.8", &[range]).status,
            "not_affected"
        );

        let build_boundary = OsvRange {
            range_type: "SEMVER".to_owned(),
            events: vec![
                ("introduced".to_owned(), "0".to_owned()),
                ("fixed".to_owned(), "1.0.0+zzz".to_owned()),
            ],
        };
        assert_eq!(
            evaluate_version("npm", "1.0.0+aaa", &[build_boundary]).status,
            "not_affected",
            "SemVer build metadata does not participate in precedence"
        );
    }
}
