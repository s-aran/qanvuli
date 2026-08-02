use super::{
    CveConstraintEvaluation, CveVersionRange, EcosystemPolicy, OsvRange, RangeEvaluation,
    evaluate_default_cve_range, evaluate_ordered_cve_range, evaluate_parsed_range,
};
use std::{cmp::Ordering, fmt};
use url::Url;

const CENTRAL_REPOSITORY: &str = "https://repo.maven.apache.org/maven2";

pub(super) static POLICY: MavenPolicy = MavenPolicy;

pub(super) struct MavenPolicy;

impl EcosystemPolicy for MavenPolicy {
    fn ecosystem_name(&self) -> &'static str {
        "Maven"
    }

    fn canonical_purl_name(&self, segments: Vec<String>) -> Option<(String, Vec<String>)> {
        if segments.len() != 2 {
            return None;
        }
        Some((format!("{}:{}", segments[0], segments[1]), segments))
    }

    fn versions_equivalent(&self, left: &str, right: &str) -> bool {
        maven_version(left)
            .zip(maven_version(right))
            .is_some_and(|(left, right)| compare_items(&left, &right) == Ordering::Equal)
    }

    fn is_concrete_version(&self, version: &str) -> bool {
        maven_version(version).is_some()
    }

    fn evaluate_ecosystem_range(&self, installed: &str, range: &OsvRange) -> RangeEvaluation {
        evaluate_parsed_range(installed, range, maven_version, |left, right| {
            compare_items(left, right)
        })
    }

    fn evaluate_cve_range(
        &self,
        installed: &str,
        version: &CveVersionRange,
    ) -> CveConstraintEvaluation {
        if version
            .version_type
            .as_deref()
            .is_some_and(|value| value.eq_ignore_ascii_case("maven"))
        {
            evaluate_ordered_cve_range(
                installed,
                version,
                maven_version,
                |left, right| compare_items(left, right),
                |value, pattern| maven_matches_wildcard(value, pattern),
            )
        } else {
            evaluate_default_cve_range(self, installed, version)
        }
    }

    fn ecosystem_identity_key(&self, base: &str, suffix: Option<&str>) -> String {
        let base = base.to_ascii_lowercase();
        let Some(suffix) = suffix else {
            return base;
        };
        match canonical_repository_url(suffix) {
            Some(repository) if repository == CENTRAL_REPOSITORY => base,
            Some(repository) => format!("{base}:{repository}"),
            None => format!("{base}:{suffix}"),
        }
    }

    fn supports_repository_url(&self) -> bool {
        true
    }

    fn canonical_repository_url(&self, value: &str) -> Option<String> {
        canonical_repository_url(value)
    }

    fn is_default_repository(&self, value: &str) -> bool {
        value == CENTRAL_REPOSITORY
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Item {
    Number(String),
    Qualifier(String),
    Hyphen,
}

fn maven_version(version: &str) -> Option<Vec<Item>> {
    let version = version.trim().to_ascii_lowercase();
    if version.is_empty()
        || !version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return None;
    }

    let mut items = Vec::new();
    let bytes = version.as_bytes();
    let mut start = 0;
    let mut digit = bytes[0].is_ascii_digit();
    for index in 0..bytes.len() {
        let byte = bytes[index];
        if matches!(byte, b'.' | b'_' | b'-') {
            push_token(&mut items, &version[start..index], digit, false);
            if byte == b'-' {
                items.push(Item::Hyphen);
            }
            start = index + 1;
            digit = bytes.get(start).is_some_and(u8::is_ascii_digit);
        } else if byte.is_ascii_digit() != digit {
            push_token(&mut items, &version[start..index], digit, !digit);
            items.push(Item::Hyphen);
            start = index;
            digit = byte.is_ascii_digit();
        }
    }
    push_token(&mut items, &version[start..], digit, false);
    normalize_items(&mut items);
    Some(items)
}

fn push_token(items: &mut Vec<Item>, token: &str, digit: bool, followed_by_digit: bool) {
    if token.is_empty() {
        items.push(Item::Number("0".to_owned()));
    } else if digit {
        let normalized = token.trim_start_matches('0');
        items.push(Item::Number(
            if normalized.is_empty() {
                "0"
            } else {
                normalized
            }
            .to_owned(),
        ));
    } else {
        let token = match token {
            "a" if followed_by_digit => "alpha",
            "b" if followed_by_digit => "beta",
            "m" if followed_by_digit => "milestone",
            "ga" | "final" | "release" => "",
            "cr" => "rc",
            value => value,
        };
        items.push(Item::Qualifier(token.to_owned()));
    }
}

fn normalize_items(items: &mut Vec<Item>) {
    let mut segments = Vec::<Vec<Item>>::new();
    let mut segment = Vec::new();
    for item in items.drain(..) {
        if item == Item::Hyphen {
            while segment.last().is_some_and(is_null_item) {
                segment.pop();
            }
            segments.push(segment);
            segment = Vec::new();
        } else {
            segment.push(item);
        }
    }
    while segment.last().is_some_and(is_null_item) {
        segment.pop();
    }
    segments.push(segment);
    while segments.last().is_some_and(Vec::is_empty) {
        segments.pop();
    }
    for (index, segment) in segments.into_iter().enumerate() {
        if index > 0 {
            items.push(Item::Hyphen);
        }
        items.extend(segment);
    }
}

fn is_null_item(item: &Item) -> bool {
    matches!(item, Item::Number(value) if value == "0")
        || matches!(item, Item::Qualifier(value) if comparable_qualifier(value) == "5")
}

fn compare_items(left: &[Item], right: &[Item]) -> Ordering {
    let length = left.len().max(right.len());
    for index in 0..length {
        let ordering = compare_item(left.get(index), right.get(index));
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    Ordering::Equal
}

fn compare_item(left: Option<&Item>, right: Option<&Item>) -> Ordering {
    match (left, right) {
        (None, None) => Ordering::Equal,
        (Some(Item::Number(left)), Some(Item::Number(right))) => compare_decimal(left, right),
        (Some(Item::Qualifier(left)), Some(Item::Qualifier(right))) => {
            comparable_qualifier(left).cmp(&comparable_qualifier(right))
        }
        (Some(Item::Hyphen), Some(Item::Hyphen)) => Ordering::Equal,
        (Some(Item::Number(_)), Some(_)) => Ordering::Greater,
        (Some(Item::Qualifier(_)), Some(_)) => Ordering::Less,
        (Some(Item::Hyphen), Some(Item::Number(_))) => Ordering::Less,
        (Some(Item::Hyphen), Some(Item::Qualifier(_))) => Ordering::Greater,
        (Some(Item::Number(value)), None) => {
            if value == "0" {
                Ordering::Equal
            } else {
                Ordering::Greater
            }
        }
        (Some(Item::Qualifier(value)), None) => comparable_qualifier(value).as_str().cmp("5"),
        (Some(Item::Hyphen), None) => Ordering::Equal,
        (None, Some(_)) => compare_item(right, left).reverse(),
    }
}

fn compare_decimal(left: &str, right: &str) -> Ordering {
    left.len().cmp(&right.len()).then_with(|| left.cmp(right))
}

fn maven_matches_wildcard(version: &[Item], pattern: &str) -> Option<bool> {
    if pattern.matches('*').count() != 1 || !pattern.ends_with('*') {
        return None;
    }
    let prefix = pattern
        .trim_end_matches('*')
        .trim_end_matches(['.', '-', '_']);
    if prefix.is_empty() {
        return Some(true);
    }
    let prefix = maven_version(prefix)?;
    Some(version.starts_with(&prefix))
}

fn comparable_qualifier(value: &str) -> String {
    match value {
        "alpha" => "0".to_owned(),
        "beta" => "1".to_owned(),
        "milestone" => "2".to_owned(),
        "rc" => "3".to_owned(),
        "snapshot" => "4".to_owned(),
        "" => "5".to_owned(),
        "sp" => "6".to_owned(),
        other => format!("7-{other}"),
    }
}

impl fmt::Display for Item {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Number(value) | Self::Qualifier(value) => formatter.write_str(value),
            Self::Hyphen => formatter.write_str("-"),
        }
    }
}

fn canonical_repository_url(value: &str) -> Option<String> {
    let mut url = Url::parse(value).ok()?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    let scheme = url.scheme().to_ascii_lowercase();
    let host = url.host_str()?.to_ascii_lowercase();
    url.set_scheme(&scheme).ok()?;
    url.set_host(Some(&host)).ok()?;
    let path = url.path().trim_end_matches('/').to_owned();
    url.set_path(if path.is_empty() { "/" } else { &path });
    let mut canonical = url.to_string();
    if canonical.ends_with('/') && url.path() != "/" {
        canonical.pop();
    }
    Some(canonical.trim_end_matches('/').to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apache_comparable_version_equalities() {
        for (left, right) in [
            ("1", "1.0.0"),
            ("1", "1-0"),
            ("1a1", "1-alpha-1"),
            ("1b2", "1-beta-2"),
            ("1m3", "1-milestone-3"),
            ("1ga", "1"),
            ("1FINAL", "1"),
            ("1Cr", "1Rc"),
            ("1a", "1.0.0-a"),
            ("1x", "1.0.0-x"),
            ("1.0", "1.0-0"),
            ("1m3", "1MILESTONE3"),
        ] {
            assert!(POLICY.versions_equivalent(left, right), "{left} != {right}");
        }
    }

    #[test]
    fn apache_comparable_version_ordering_and_unbounded_numbers() {
        for versions in [
            &[
                "1-alpha2snapshot",
                "1-alpha2",
                "1-alpha-123",
                "1-beta-2",
                "1-beta123",
                "1-m2",
                "1-m11",
                "1-rc",
                "1-cr2",
                "1-rc123",
                "1-SNAPSHOT",
                "1",
                "1-sp",
                "1-sp2",
                "1-sp123",
                "1-abc",
                "1-def",
                "1-pom-1",
                "1-1-snapshot",
                "1-1",
                "1-2",
                "1-123",
            ][..],
            &[
                "2.0", "2-1", "2.0.a", "2.0.0.a", "2.0.2", "2.0.123", "2.1.0", "2.1-a", "2.1b",
                "2.1-c", "2.1-1", "2.1.0.1", "2.2", "2.123", "11.a2", "11.a11", "11.b2", "11.b11",
                "11.m2", "11.m11", "11", "11.a", "11b", "11c", "11m",
            ][..],
        ] {
            for pair in versions.windows(2) {
                let left = maven_version(pair[0]).unwrap();
                let right = maven_version(pair[1]).unwrap();
                assert_eq!(
                    compare_items(&left, &right),
                    Ordering::Less,
                    "{} !< {}",
                    pair[0],
                    pair[1]
                );
            }
        }
        let left = maven_version("1.999999999999999999999999999999").unwrap();
        let right = maven_version("1.1000000000000000000000000000000").unwrap();
        assert_eq!(compare_items(&left, &right), Ordering::Less);
    }
}
