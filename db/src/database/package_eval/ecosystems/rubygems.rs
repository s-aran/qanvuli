use super::{
    CveConstraintEvaluation, CveVersionRange, EcosystemPolicy, OsvRange, RangeEvaluation,
    canonical_single_segment, evaluate_default_cve_range, evaluate_ordered_cve_range,
    evaluate_parsed_range,
};
use std::cmp::Ordering;

pub(super) static POLICY: RubyGemsPolicy = RubyGemsPolicy;

pub(super) struct RubyGemsPolicy;

impl EcosystemPolicy for RubyGemsPolicy {
    fn ecosystem_name(&self) -> &'static str {
        "RubyGems"
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
        evaluate_parsed_range(installed, range, version_key, |left, right| {
            compare_versions(left, right)
        })
    }

    fn evaluate_cve_range(
        &self,
        installed: &str,
        version: &CveVersionRange,
    ) -> CveConstraintEvaluation {
        if version.version_type.as_deref().is_some_and(|value| {
            value.eq_ignore_ascii_case("ruby") || value.eq_ignore_ascii_case("rubygems")
        }) {
            evaluate_ordered_cve_range(
                installed,
                version,
                version_key,
                |left, right| compare_versions(left, right),
                |value, pattern| rubygems_matches_wildcard(value, pattern),
            )
        } else {
            evaluate_default_cve_range(self, installed, version)
        }
    }
}

fn rubygems_matches_wildcard(version: &[VersionPart], pattern: &str) -> Option<bool> {
    if pattern.matches('*').count() != 1 || !pattern.ends_with('*') {
        return None;
    }
    let prefix = pattern.trim_end_matches('*').trim_end_matches(['.', '-']);
    if prefix.is_empty() {
        return Some(true);
    }
    Some(version.starts_with(&version_key(prefix)?))
}

fn version_key(version: &str) -> Option<Vec<VersionPart>> {
    let version = version.trim();
    if version.is_empty()
        || !version.starts_with(|character: char| character.is_ascii_digit())
        || !version
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '.' | '-'))
    {
        return None;
    }
    let normalized = version.replace('-', ".pre.");
    if normalized.split('.').any(str::is_empty) {
        return None;
    }
    let mut segments = Vec::new();
    for component in normalized.split('.') {
        let bytes = component.as_bytes();
        let mut start = 0;
        while start < bytes.len() {
            let digits = bytes[start].is_ascii_digit();
            let mut end = start + 1;
            while end < bytes.len() && bytes[end].is_ascii_digit() == digits {
                end += 1;
            }
            let part = &component[start..end];
            segments.push(if digits {
                VersionPart::Numeric(decimal(part)?)
            } else {
                VersionPart::Text(part.to_owned())
            });
            start = end;
        }
    }
    if let Some(first_text) = segments
        .iter()
        .position(|part| matches!(part, VersionPart::Text(_)))
    {
        let mut zero_start = first_text;
        while zero_start > 0
            && segments.get(zero_start - 1) == Some(&VersionPart::Numeric("0".to_owned()))
        {
            zero_start -= 1;
        }
        segments.drain(zero_start..first_text);
    }
    while segments.len() > 1 && segments.last() == Some(&VersionPart::Numeric("0".to_owned())) {
        segments.pop();
    }
    Some(segments)
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum VersionPart {
    Numeric(String),
    Text(String),
}

fn compare_versions(left: &[VersionPart], right: &[VersionPart]) -> Ordering {
    for (left, right) in left.iter().zip(right) {
        let ordering = match (left, right) {
            (VersionPart::Numeric(left), VersionPart::Numeric(right)) => {
                compare_decimal(left, right)
            }
            (VersionPart::Text(left), VersionPart::Text(right)) => left.cmp(right),
            (VersionPart::Text(_), VersionPart::Numeric(_)) => Ordering::Less,
            (VersionPart::Numeric(_), VersionPart::Text(_)) => Ordering::Greater,
        };
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    if left.len() == right.len() {
        return Ordering::Equal;
    }
    if left.len() < right.len() {
        for remaining in &right[left.len()..] {
            match remaining {
                VersionPart::Text(_) => return Ordering::Greater,
                VersionPart::Numeric(value) if value != "0" => return Ordering::Less,
                VersionPart::Numeric(_) => {}
            }
        }
    } else {
        for remaining in &left[right.len()..] {
            match remaining {
                VersionPart::Text(_) => return Ordering::Less,
                VersionPart::Numeric(value) if value != "0" => return Ordering::Greater,
                VersionPart::Numeric(_) => {}
            }
        }
    }
    Ordering::Equal
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
