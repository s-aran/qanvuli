#![allow(clippy::large_enum_variant)]

pub mod cve;
pub mod cwe;
pub mod epss;
pub mod kev;
pub mod osv;

use anyhow::{Error, Result, anyhow};
use cve::{
    published::root::CveRoot as PublishedCveRoot, rejected::root::CveRoot as RejectedCveRoot,
};
use qanvuli_utils::datetime_deserialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

#[derive(Debug)]
pub enum CveStatusData {
    Published(PublishedCveRoot),
    Rejected(RejectedCveRoot),
}

#[derive(Debug, Clone)]
pub struct RawCveRecord<T> {
    pub content: T,
    pub raw_json: Value,
}

pub type RawPublishedCveRecord = RawCveRecord<PublishedCveRoot>;
pub type RawRejectedCveRecord = RawCveRecord<RejectedCveRoot>;
pub type RawCveStatusRecord = RawCveRecord<CveStatusData>;

impl<T> RawCveRecord<T> {
    pub fn content(&self) -> &T {
        &self.content
    }

    pub fn raw_json(&self) -> &Value {
        &self.raw_json
    }

    pub fn into_parts(self) -> (T, Value) {
        (self.content, self.raw_json)
    }
}

pub fn parse_with_raw<T>(bytes: &[u8]) -> Result<RawCveRecord<T>, simd_json::Error>
where
    T: DeserializeOwned,
{
    let mut content_bytes = bytes.to_vec();
    let content: T = simd_json::from_slice(&mut content_bytes)?;
    let mut bytes = bytes.to_vec();
    let raw_json: Value = simd_json::from_slice(&mut bytes)?;

    Ok(RawCveRecord { content, raw_json })
}

pub fn parse_str_with_raw<T>(s: &str) -> Result<RawCveRecord<T>, simd_json::Error>
where
    T: DeserializeOwned,
{
    parse_with_raw(s.as_bytes())
}

pub fn parse_json(src: impl Into<String>) -> Result<CveStatusData, Error> {
    Ok(parse_json_with_raw(src)?.content)
}

pub fn parse_json_with_raw(src: impl Into<String>) -> Result<RawCveStatusRecord, Error> {
    parse_json_bytes_with_raw(src.into().into_bytes())
}

pub fn parse_json_bytes_with_raw(mut bytes: Vec<u8>) -> Result<RawCveStatusRecord, Error> {
    let raw_json: Value = simd_json::from_slice(&mut bytes)?;
    parse_value_with_raw(raw_json)
}

pub fn parse_json_value_bytes(mut bytes: Vec<u8>) -> Result<Value, Error> {
    Ok(simd_json::from_slice(&mut bytes)?)
}

pub fn parse_value_with_raw(raw_json: Value) -> Result<RawCveStatusRecord, Error> {
    match raw_json
        .get("cveMetadata")
        .and_then(Value::as_object)
        .and_then(|metadata| metadata.get("state"))
        .and_then(Value::as_str)
    {
        Some("PUBLISHED") => {
            let deserialized = match serde_json::from_value::<PublishedCveRoot>(raw_json.clone()) {
                Ok(r) => r,
                Err(e) => return Err(anyhow!(e)),
            };
            Ok(RawCveRecord {
                content: CveStatusData::Published(deserialized),
                raw_json,
            })
        }
        Some("REJECTED") => {
            let deserialized = match serde_json::from_value::<RejectedCveRoot>(raw_json.clone()) {
                Ok(r) => r,
                Err(e) => return Err(anyhow!(e)),
            };
            Ok(RawCveRecord {
                content: CveStatusData::Rejected(deserialized),
                raw_json,
            })
        }
        Some("RESERVED") => Err(anyhow!("unexpected reserved state.")),
        Some(state) => Err(anyhow!("unexpected CVE state: {state}")),
        None => Err(anyhow!("missing cveMetadata.state")),
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct RawCvssValue {
    pub metric_index: usize,
    pub cvss_key: String,
    pub raw_json: Value,
}

pub fn cna_affected_raw_values(raw_json: &Value) -> Vec<Value> {
    cna_value(raw_json)
        .and_then(|cna| cna.get("affected"))
        .and_then(Value::as_array)
        .map(|affected| affected.to_vec())
        .unwrap_or_default()
}

pub fn cna_cvss_raw_values(raw_json: &Value) -> Vec<RawCvssValue> {
    let Some(metrics) = cna_value(raw_json)
        .and_then(|cna| cna.get("metrics"))
        .and_then(Value::as_array)
    else {
        return Vec::new();
    };

    metrics
        .iter()
        .enumerate()
        .flat_map(|(metric_index, metric)| {
            ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"]
                .into_iter()
                .filter_map(move |cvss_key| {
                    metric.get(cvss_key).map(|raw_json| RawCvssValue {
                        metric_index,
                        cvss_key: cvss_key.to_owned(),
                        raw_json: raw_json.clone(),
                    })
                })
        })
        .collect()
}

pub fn cna_cwe_raw_values(raw_json: &Value) -> Vec<Value> {
    cna_value(raw_json)
        .and_then(|cna| cna.get("problemTypes"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .flat_map(|problem_type| {
            problem_type
                .get("descriptions")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
        })
        .filter(|description| description.get("cweId").is_some())
        .cloned()
        .collect()
}

fn cna_value(raw_json: &Value) -> Option<&Value> {
    raw_json
        .get("containers")
        .and_then(Value::as_object)
        .and_then(|containers| containers.get("cna"))
}

#[cfg(test)]
mod tests {
    use crate::cve::base::cve_metadata::CveState;
    use crate::cve::base::root::CveRoot;
    use crate::cve::published::root::CveRoot as PublishedCveRoot;
    use crate::cve::rejected::root::CveRoot as RejectedCveRoot;

    use super::*;

    use glob::MatchOptions;
    use glob::glob_with;
    use std::fs::File;
    use std::io::Read;

    const CVE_JSON: &str = r#"{
        "dataType": "CVE_RECORD",
        "dataVersion": "5.1.0",
        "cveMetadata": {
            "cveId": "CVE-2024-0001",
            "assignerOrgId": "00000000-0000-4000-8000-000000000000",
            "state": "PUBLISHED"
        },
        "containers": {
            "cna": {
                "providerMetadata": {
                    "orgId": "00000000-0000-4000-8000-000000000000"
                },
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "Example vulnerability."
                    }
                ],
                "affected": [
                    {
                        "vendor": "Example Vendor",
                        "product": "Example Product"
                    }
                ],
                "references": [
                    {
                        "url": "https://example.com/advisory"
                    }
                ]
            }
        }
    }"#;

    #[test]
    fn test_parse_json_with_raw_json() {
        let parsed = parse_str_with_raw::<PublishedCveRoot>(CVE_JSON).unwrap();

        assert_eq!(parsed.raw_json()["cveMetadata"]["cveId"], "CVE-2024-0001");
        assert_eq!(parsed.content().cve_metadata.cve_id, "CVE-2024-0001");
    }

    #[test]
    fn test_raw_json_getter_returns_original_json_value() {
        let parsed = parse_str_with_raw::<PublishedCveRoot>(CVE_JSON).unwrap();
        let expected_raw_json: Value = serde_json::from_str(CVE_JSON).unwrap();

        assert_eq!(parsed.raw_json(), &expected_raw_json);
        assert_eq!(
            parsed.raw_json()["containers"]["cna"]["affected"][0]["vendor"],
            "Example Vendor"
        );
    }

    #[test]
    fn test_raw_parse_str_with_raw() {
        let parsed = parse_str_with_raw::<PublishedCveRoot>(CVE_JSON).unwrap();
        let (content, raw_json) = parsed.into_parts();

        assert_eq!(content.cve_metadata.cve_id, "CVE-2024-0001");
        assert_eq!(raw_json["cveMetadata"]["cveId"], "CVE-2024-0001");
    }

    #[test]
    fn test_parse_json_with_raw() {
        let parsed = parse_json_with_raw(CVE_JSON).unwrap();

        assert_eq!(parsed.raw_json()["cveMetadata"]["cveId"], "CVE-2024-0001");
        assert!(matches!(parsed.content(), CveStatusData::Published(_)));
    }

    #[test]
    fn test_extracts_cna_child_raw_json_values() {
        let src = r#"{
            "containers": {
                "cna": {
                    "affected": [
                        {
                            "vendor": "Example Vendor",
                            "product": "Example Product"
                        }
                    ],
                    "metrics": [
                        {
                            "format": "CVSS",
                            "cvssV3_1": {
                                "version": "3.1",
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                            }
                        }
                    ],
                    "problemTypes": [
                        {
                            "descriptions": [
                                {
                                    "lang": "en",
                                    "cweId": "CWE-79",
                                    "description": "Cross-site Scripting"
                                }
                            ]
                        }
                    ]
                }
            }
        }"#;
        let raw_json: Value = serde_json::from_str(src).unwrap();

        let affected = cna_affected_raw_values(&raw_json);
        assert_eq!(affected.len(), 1);
        assert_eq!(affected[0]["vendor"], "Example Vendor");

        let cvss = cna_cvss_raw_values(&raw_json);
        assert_eq!(cvss.len(), 1);
        assert_eq!(cvss[0].metric_index, 0);
        assert_eq!(cvss[0].cvss_key, "cvssV3_1");
        assert_eq!(cvss[0].raw_json["version"], "3.1");

        let cwe = cna_cwe_raw_values(&raw_json);
        assert_eq!(cwe.len(), 1);
        assert_eq!(cwe[0]["cweId"], "CWE-79");
    }

    #[test]
    fn test_json() {
        const DIR: &str = "deltaCves";
        let mut glob_options = MatchOptions::new();
        glob_options.case_sensitive = false;

        let base_path = format!("{}/*.json", DIR);
        let files = glob_with(base_path.as_str(), glob_options).unwrap();

        for path in files {
            let p = path.unwrap().to_string_lossy().to_string();
            println!("{}", p);
            let mut file = File::open(p).expect("maybe not found");
            let mut buf = String::new();
            let _ = file.read_to_string(&mut buf);

            let _: cve::published::root::CveRoot = serde_json::from_str(&buf).unwrap();
        }
    }

    #[test]
    fn test_json_2() {
        const DIR: &str = "cves";
        let mut glob_options = MatchOptions::new();
        glob_options.case_sensitive = false;

        let base_path = format!("{}/**/CVE-*.json", DIR);
        let files = glob_with(base_path.as_str(), glob_options).unwrap();

        for path in files {
            let p = path.unwrap().to_string_lossy().to_string();
            println!("{}", p);
            let mut file = File::open(p).expect("maybe not found");
            let mut buf = String::new();
            let _ = file.read_to_string(&mut buf);

            let cve: CveRoot = serde_json::from_str(&buf).unwrap();
            match cve.cve_metadata.state {
                CveState::Published => {
                    let _ = serde_json::from_str::<PublishedCveRoot>(&buf).unwrap();
                }
                CveState::Rejected => {
                    let _ = serde_json::from_str::<RejectedCveRoot>(&buf).unwrap();
                }
                CveState::Reserved => assert!(false),
            }
        }
    }
}
