//! DB-independent OSV range evaluation used by SQLx package queries.

use serde::Serialize;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OsvRange {
    pub range_type: String,
    pub events: Vec<(String, String)>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct VersionMatch {
    pub status: String,
    pub confidence: String,
}

pub fn evaluate_version(ecosystem: &str, installed: &str, ranges: &[OsvRange]) -> VersionMatch {
    if !ecosystem.eq_ignore_ascii_case("crates.io") {
        return unsupported();
    }
    let Ok(installed) = semver::Version::parse(installed) else {
        return unknown();
    };
    if ranges.is_empty() {
        return unknown();
    }
    let mut affected = false;
    for range in ranges {
        if !range.range_type.eq_ignore_ascii_case("SEMVER") {
            return unsupported();
        }
        let mut introduced = semver::Version::new(0, 0, 0);
        let mut fixed = None;
        let mut last_affected = None;
        for (event_type, value) in &range.events {
            match event_type.as_str() {
                "introduced" if value != "0" => {
                    if let Ok(version) = semver::Version::parse(value) {
                        introduced = version;
                    }
                }
                "fixed" => {
                    if let Ok(version) = semver::Version::parse(value) {
                        fixed = Some(version);
                    }
                }
                "last_affected" => {
                    if let Ok(version) = semver::Version::parse(value) {
                        last_affected = Some(version);
                    }
                }
                _ => {}
            }
        }
        if installed >= introduced
            && fixed.as_ref().is_none_or(|fixed| installed < *fixed)
            && last_affected.as_ref().is_none_or(|last| installed <= *last)
        {
            affected = true;
        }
    }
    VersionMatch {
        status: if affected { "affected" } else { "not_affected" }.to_owned(),
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
            evaluate_version("crates.io", "2.0.0", &[range]).status,
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
        assert_eq!(
            evaluate_version("npm", "1.5.0", &[]).status,
            "unsupported_version_scheme"
        );
    }
}
