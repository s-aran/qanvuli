use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use thiserror::Error;

pub const CISA_KEV_SCHEMA_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities_schema.json";

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct KevCatalog {
    pub title: String,
    #[serde(rename = "catalogVersion")]
    pub catalog_version: String,
    #[serde(rename = "dateReleased")]
    pub date_released: String,
    pub count: u64,
    #[serde(default)]
    pub vulnerabilities: Vec<KevEntry>,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct KevEntry {
    #[serde(rename = "cveID")]
    pub cve_id: String,
    #[serde(rename = "vendorProject")]
    pub vendor_project: String,
    pub product: String,
    #[serde(rename = "vulnerabilityName")]
    pub vulnerability_name: String,
    #[serde(rename = "dateAdded")]
    pub date_added: String,
    #[serde(rename = "shortDescription")]
    pub short_description: String,
    #[serde(rename = "requiredAction")]
    pub required_action: String,
    #[serde(rename = "dueDate")]
    pub due_date: String,
    #[serde(rename = "knownRansomwareCampaignUse")]
    pub known_ransomware_campaign_use: String,
    pub notes: String,
    #[serde(default, rename = "cwes")]
    pub cwes: Vec<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

#[derive(Debug, Error)]
pub enum KevSchemaError {
    #[error("KEV catalog count {count} does not match vulnerabilities length {actual}")]
    CountMismatch { count: u64, actual: usize },
    #[error("KEV entry {index} cveID `{value}` is not a CVE identifier")]
    InvalidCveId { index: usize, value: String },
}

impl KevCatalog {
    pub fn parse_json(bytes: &[u8]) -> Result<Self, simd_json::Error> {
        let mut bytes = bytes.to_vec();
        simd_json::from_slice(&mut bytes)
    }

    pub fn validate_schema_shape(&self) -> Result<(), KevSchemaError> {
        if self.count != self.vulnerabilities.len() as u64 {
            return Err(KevSchemaError::CountMismatch {
                count: self.count,
                actual: self.vulnerabilities.len(),
            });
        }
        for (index, entry) in self.vulnerabilities.iter().enumerate() {
            entry.validate_schema_shape(index)?;
        }
        Ok(())
    }
}

impl KevEntry {
    fn validate_schema_shape(&self, index: usize) -> Result<(), KevSchemaError> {
        if !self.cve_id.starts_with("CVE-") {
            return Err(KevSchemaError::InvalidCveId {
                index,
                value: self.cve_id.clone(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEV_JSON: &str = r#"{
      "title": "CISA Known Exploited Vulnerabilities Catalog",
      "catalogVersion": "2099.01.01",
      "dateReleased": "2099-01-01T00:00:00Z",
      "count": 1,
      "vulnerabilities": [
        {
          "cveID": "CVE-2099-0001",
          "vendorProject": "Fixture Vendor",
          "product": "foo",
          "vulnerabilityName": "Fixture foo vulnerability",
          "dateAdded": "2099-01-02",
          "shortDescription": "Fixture KEV entry.",
          "requiredAction": "Apply updates per vendor instructions.",
          "dueDate": "2099-02-01",
          "knownRansomwareCampaignUse": "Known",
          "notes": "Fixture note.",
          "futureField": "preserved"
        }
      ],
      "futureCatalogField": true
    }"#;

    #[test]
    fn kev_catalog_parses_with_simd_json_and_preserves_unknown_fields() {
        let parsed = KevCatalog::parse_json(KEV_JSON.as_bytes()).unwrap();
        parsed.validate_schema_shape().unwrap();
        assert_eq!(parsed.catalog_version, "2099.01.01");
        assert!(parsed.extra.contains_key("futureCatalogField"));
        assert!(parsed.vulnerabilities[0].extra.contains_key("futureField"));
    }

    #[test]
    fn kev_catalog_rejects_count_mismatch() {
        let mut parsed = KevCatalog::parse_json(KEV_JSON.as_bytes()).unwrap();
        parsed.count = 2;
        assert!(matches!(
            parsed.validate_schema_shape(),
            Err(KevSchemaError::CountMismatch { .. })
        ));
    }
}
