//! DB-independent OSV range evaluation used by SQLx package queries.

use pep440_rs::Version as Pep440Version;
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
    if ranges.is_empty() {
        return unknown();
    }
    if ecosystem.eq_ignore_ascii_case("PyPI") {
        return evaluate_pep440(installed, ranges);
    }
    evaluate_semver(ecosystem, installed, ranges)
}

fn evaluate_semver(ecosystem: &str, installed: &str, ranges: &[OsvRange]) -> VersionMatch {
    let Ok(installed) = semver::Version::parse(installed.trim_start_matches('v')) else {
        return unknown();
    };
    evaluate_ranges(
        &installed,
        ranges,
        |range_type| {
            range_type.eq_ignore_ascii_case("SEMVER")
                // npm's OSV ECOSYSTEM ranges have node-semver semantics. Other
                // ecosystems must not be guessed as semver merely because their
                // strings happen to parse successfully.
                || (ecosystem.eq_ignore_ascii_case("npm")
                    && range_type.eq_ignore_ascii_case("ECOSYSTEM"))
        },
        |version| semver::Version::parse(version.trim_start_matches('v')).ok(),
    )
}

fn evaluate_pep440(installed: &str, ranges: &[OsvRange]) -> VersionMatch {
    let Ok(installed) = installed.parse::<Pep440Version>() else {
        return unknown();
    };
    evaluate_ranges(
        &installed,
        ranges,
        |range_type| {
            range_type.eq_ignore_ascii_case("ECOSYSTEM")
                || range_type.eq_ignore_ascii_case("SEMVER")
        },
        |version| version.parse::<Pep440Version>().ok(),
    )
}

/// Evaluate OSV's alternating introduced/fixed/last_affected event sequence.
/// A range can contain multiple affected intervals, not merely one lower/upper bound.
fn evaluate_ranges<T: Ord>(
    installed: &T,
    ranges: &[OsvRange],
    accepts_range_type: impl Fn(&str) -> bool,
    parse: impl Fn(&str) -> Option<T>,
) -> VersionMatch {
    let mut affected = false;
    let mut evaluated = false;
    for range in ranges {
        if !accepts_range_type(&range.range_type) {
            continue;
        }
        evaluated = true;
        // OSV ranges begin affected from version zero unless an event has closed
        // that interval. `introduced: "0"` is the explicit spelling of this.
        let mut open = true;
        let mut introduced: Option<T> = None;
        let mut has_version_event = false;
        for (event_type, value) in &range.events {
            match event_type.as_str() {
                "introduced" => {
                    has_version_event = true;
                    introduced = if value == "0" {
                        None
                    } else {
                        let Some(start) = parse(value) else {
                            return unknown();
                        };
                        Some(start)
                    };
                    open = true;
                }
                "fixed" | "last_affected" => {
                    has_version_event = true;
                    let Some(end) = parse(value) else {
                        return unknown();
                    };
                    let starts_before_or_at =
                        introduced.as_ref().is_none_or(|start| installed >= start);
                    let ends_after = if event_type == "fixed" {
                        installed < &end
                    } else {
                        installed <= &end
                    };
                    if starts_before_or_at && ends_after {
                        affected = true;
                    }
                    open = false;
                    introduced = None;
                }
                _ => {}
            }
        }
        if !has_version_event {
            return unknown();
        }
        if open && introduced.as_ref().is_none_or(|start| installed >= start) {
            affected = true;
        }
    }
    if !evaluated {
        return unsupported();
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
    }

    #[test]
    fn unsupported_ecosystem_ranges_are_not_guessed_as_semver() {
        let range = OsvRange {
            range_type: "ECOSYSTEM".to_owned(),
            events: vec![
                ("introduced".to_owned(), "1.0.0".to_owned()),
                ("fixed".to_owned(), "2.0.0".to_owned()),
            ],
        };
        assert_eq!(
            evaluate_version("Maven", "1.5.0", std::slice::from_ref(&range)).status,
            "unsupported_version_scheme"
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
}
