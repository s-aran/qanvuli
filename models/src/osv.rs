use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

pub const OSV_SCHEMA_VERSION: &str = "1.7.5";

/// OSV source database prefixes published by the official OSV schema docs.
///
/// OSV IDs have the form `<DB>-<ENTRYID>`, where `<DB>` is one of these
/// source database identifiers.
pub const OSV_DATABASE_SOURCE_PREFIXES: &[&str] = &[
    "ALBA",
    "ALEA",
    "ALPINE",
    "ALSA",
    "ASB-A",
    "BELL",
    "BIT",
    "CGA",
    "CLEANSTART",
    "CURL",
    "CVE",
    "DEBIAN",
    "DHI",
    "DLA",
    "DRUPAL",
    "DSA",
    "DTSA",
    "ECHO",
    "EEF",
    "ELA",
    "GHSA",
    "GO",
    "GSD",
    "HSEC",
    "JLSEC",
    "KUBE",
    "LBSEC",
    "LSN",
    "MAL",
    "MGASA",
    "MINI",
    "OESA",
    "OPENSUSE-SU",
    "OSEC",
    "OSV",
    "PHSA",
    "PSF",
    "PUB-A",
    "PYSEC",
    "RHBA",
    "RHEA",
    "RHSA",
    "RLSA",
    "ROOT",
    "RSEC",
    "RUSTSEC",
    "RXSA",
    "SUSE-FU",
    "SUSE-OU",
    "SUSE-RU",
    "SUSE-SU",
    "UBUNTU",
    "USN",
    "V8",
];

pub fn is_known_osv_database_prefix(prefix: &str) -> bool {
    let prefix = prefix.trim().trim_end_matches('-').to_ascii_uppercase();
    OSV_DATABASE_SOURCE_PREFIXES.contains(&prefix.as_str())
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OsvAdvisory {
    #[serde(default)]
    pub schema_version: Option<String>,
    pub id: String,
    #[serde(default)]
    pub modified: Option<String>,
    #[serde(default)]
    pub published: Option<String>,
    #[serde(default)]
    pub withdrawn: Option<String>,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub upstream: Vec<String>,
    #[serde(default)]
    pub related: Vec<String>,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub details: Option<String>,
    #[serde(default)]
    pub severity: Vec<OsvSeverity>,
    #[serde(default)]
    pub affected: Vec<OsvAffected>,
    #[serde(default)]
    pub references: Vec<OsvReference>,
    #[serde(default)]
    pub credits: Vec<OsvCredit>,
    #[serde(default)]
    pub database_specific: Option<Value>,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

impl OsvAdvisory {
    pub fn parse_json(bytes: &[u8]) -> Result<Self, simd_json::Error> {
        let mut bytes = bytes.to_vec();
        simd_json::from_slice(&mut bytes)
    }

    pub fn validate_schema_shape(&self) -> Result<(), OsvSchemaError> {
        if self.id.trim().is_empty() {
            return Err(OsvSchemaError::MissingRequiredField("id"));
        }
        match self.modified.as_deref().map(str::trim) {
            Some(modified) if !modified.is_empty() => {}
            _ => return Err(OsvSchemaError::MissingRequiredField("modified")),
        }
        for (affected_index, affected) in self.affected.iter().enumerate() {
            for (range_index, range) in affected.ranges.iter().enumerate() {
                for (event_index, event) in range.events.iter().enumerate() {
                    event
                        .validate_oneof()
                        .map_err(|reason| OsvSchemaError::InvalidRangeEvent {
                            affected_index,
                            range_index,
                            event_index,
                            reason,
                        })?;
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum OsvSchemaError {
    #[error("OSV record is missing required field `{0}`")]
    MissingRequiredField(&'static str),
    #[error(
        "OSV affected[{affected_index}].ranges[{range_index}].events[{event_index}] is invalid: {reason}"
    )]
    InvalidRangeEvent {
        affected_index: usize,
        range_index: usize,
        event_index: usize,
        reason: OsvRangeEventError,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OsvSeverity {
    #[serde(rename = "type")]
    pub severity_type: String,
    pub score: String,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OsvAffected {
    #[serde(default)]
    pub package: Option<OsvPackage>,
    #[serde(default)]
    pub severity: Vec<OsvSeverity>,
    #[serde(default)]
    pub ranges: Vec<OsvRange>,
    #[serde(default)]
    pub versions: Vec<String>,
    #[serde(default)]
    pub ecosystem_specific: Option<Value>,
    #[serde(default)]
    pub database_specific: Option<Value>,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OsvPackage {
    #[serde(default)]
    pub ecosystem: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub purl: Option<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OsvRange {
    #[serde(rename = "type", default)]
    pub range_type: Option<String>,
    #[serde(default)]
    pub repo: Option<String>,
    #[serde(default)]
    pub events: Vec<OsvRangeEvent>,
    #[serde(default)]
    pub database_specific: Option<Value>,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OsvRangeEvent {
    #[serde(default)]
    pub introduced: Option<String>,
    #[serde(default)]
    pub fixed: Option<String>,
    #[serde(default)]
    pub last_affected: Option<String>,
    #[serde(default)]
    pub limit: Option<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

impl OsvRangeEvent {
    pub fn event_pairs(&self) -> Vec<(&'static str, &str)> {
        let mut pairs = Vec::new();
        if let Some(value) = self.introduced.as_deref() {
            pairs.push(("introduced", value));
        }
        if let Some(value) = self.fixed.as_deref() {
            pairs.push(("fixed", value));
        }
        if let Some(value) = self.last_affected.as_deref() {
            pairs.push(("last_affected", value));
        }
        if let Some(value) = self.limit.as_deref() {
            pairs.push(("limit", value));
        }
        pairs
    }

    pub fn validate_oneof(&self) -> Result<(), OsvRangeEventError> {
        let known = self.event_pairs().len();
        if known != 1 {
            return Err(OsvRangeEventError::ExpectedExactlyOneKnownKey { actual: known });
        }
        if !self.extra.is_empty() {
            return Err(OsvRangeEventError::UnknownEventKeys {
                keys: self.extra.keys().cloned().collect(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum OsvRangeEventError {
    #[error("expected exactly one of introduced, fixed, last_affected, or limit; found {actual}")]
    ExpectedExactlyOneKnownKey { actual: usize },
    #[error("unknown event keys are not valid in OSV range events: {keys:?}")]
    UnknownEventKeys { keys: Vec<String> },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OsvReference {
    #[serde(rename = "type", default)]
    pub reference_type: Option<String>,
    pub url: String,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OsvCredit {
    pub name: String,
    #[serde(default)]
    pub contact: Vec<String>,
    #[serde(rename = "type", default)]
    pub credit_type: Option<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_official_osv_database_prefixes_case_insensitively() {
        assert!(is_known_osv_database_prefix("ghsa"));
        assert!(is_known_osv_database_prefix("RUSTSEC"));
        assert!(is_known_osv_database_prefix("PySeC"));
        assert!(is_known_osv_database_prefix("suse-su"));
        assert!(is_known_osv_database_prefix("openSUSE-SU"));
        assert!(!is_known_osv_database_prefix("NOT-A-SOURCE"));
    }

    #[test]
    fn validates_official_osv_required_shape() {
        let advisory = OsvAdvisory {
            schema_version: Some(OSV_SCHEMA_VERSION.to_owned()),
            id: "RUSTSEC-2099-0001".to_owned(),
            modified: Some("2099-01-02T00:00:00Z".to_owned()),
            published: None,
            withdrawn: None,
            aliases: vec!["CVE-2099-0001".to_owned()],
            upstream: Vec::new(),
            related: Vec::new(),
            summary: None,
            details: None,
            severity: Vec::new(),
            affected: vec![OsvAffected {
                package: Some(OsvPackage {
                    ecosystem: Some("crates.io".to_owned()),
                    name: Some("foo".to_owned()),
                    purl: None,
                    extra: HashMap::new(),
                }),
                severity: Vec::new(),
                ranges: vec![OsvRange {
                    range_type: Some("SEMVER".to_owned()),
                    repo: None,
                    events: vec![
                        OsvRangeEvent {
                            introduced: Some("1.0.0".to_owned()),
                            fixed: None,
                            last_affected: None,
                            limit: None,
                            extra: HashMap::new(),
                        },
                        OsvRangeEvent {
                            introduced: None,
                            fixed: Some("1.2.5".to_owned()),
                            last_affected: None,
                            limit: None,
                            extra: HashMap::new(),
                        },
                    ],
                    database_specific: None,
                    extra: HashMap::new(),
                }],
                versions: Vec::new(),
                ecosystem_specific: None,
                database_specific: None,
                extra: HashMap::new(),
            }],
            references: Vec::new(),
            credits: Vec::new(),
            database_specific: None,
            extra: HashMap::new(),
        };

        advisory.validate_schema_shape().unwrap();
    }

    #[test]
    fn rejects_range_event_with_multiple_event_keys() {
        let event = OsvRangeEvent {
            introduced: Some("1.0.0".to_owned()),
            fixed: Some("1.2.5".to_owned()),
            last_affected: None,
            limit: None,
            extra: HashMap::new(),
        };

        assert!(event.validate_oneof().is_err());
    }

    #[test]
    fn rejects_missing_modified() {
        let advisory = OsvAdvisory {
            schema_version: Some(OSV_SCHEMA_VERSION.to_owned()),
            id: "RUSTSEC-2099-0001".to_owned(),
            modified: None,
            published: None,
            withdrawn: None,
            aliases: Vec::new(),
            upstream: Vec::new(),
            related: Vec::new(),
            summary: None,
            details: None,
            severity: Vec::new(),
            affected: Vec::new(),
            references: Vec::new(),
            credits: Vec::new(),
            database_specific: None,
            extra: HashMap::new(),
        };

        assert!(matches!(
            advisory.validate_schema_shape(),
            Err(OsvSchemaError::MissingRequiredField("modified"))
        ));
    }
}
