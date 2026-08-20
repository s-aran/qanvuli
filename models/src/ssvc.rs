//! CISA SSVC decision-point models embedded in CVE ADP containers.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, fmt, str::FromStr};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SsvcExploitation {
    None,
    #[serde(rename = "poc")]
    PublicPoc,
    Active,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SsvcAutomatable {
    No,
    Yes,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SsvcTechnicalImpact {
    Partial,
    Total,
}

macro_rules! impl_ssvc_value {
    ($type:ty, {$($variant:ident => $value:literal),+ $(,)?}) => {
        impl $type {
            pub const fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $value),+ }
            }
        }

        impl fmt::Display for $type {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }

        impl FromStr for $type {
            type Err = String;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                match value.trim().to_ascii_lowercase().as_str() {
                    $($value => Ok(Self::$variant),)+
                    _ => Err(format!("unsupported SSVC value `{value}`")),
                }
            }
        }
    };
}

impl_ssvc_value!(SsvcExploitation, {
    None => "none",
    PublicPoc => "poc",
    Active => "active",
});
impl_ssvc_value!(SsvcAutomatable, { No => "no", Yes => "yes" });
impl_ssvc_value!(SsvcTechnicalImpact, {
    Partial => "partial",
    Total => "total",
});

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SsvcAssessment {
    pub cve_id: String,
    pub provider: String,
    pub role: String,
    pub version: String,
    pub assessed_at: String,
    pub exploitation: Option<SsvcExploitation>,
    pub automatable: Option<SsvcAutomatable>,
    pub technical_impact: Option<SsvcTechnicalImpact>,
    pub raw_json: String,
}

#[derive(Debug, Deserialize)]
struct SsvcContent {
    id: String,
    role: String,
    version: String,
    timestamp: String,
    #[serde(default)]
    options: Vec<BTreeMap<String, String>>,
}

/// Extracts every SSVC metric from a CVE record's ADP containers.
pub fn assessments_from_cve(value: &Value) -> Result<Vec<SsvcAssessment>, String> {
    let record_id = value
        .pointer("/cveMetadata/cveId")
        .and_then(Value::as_str)
        .ok_or_else(|| "CVE record has no cveMetadata.cveId".to_owned())?;
    let Some(containers) = value.pointer("/containers/adp").and_then(Value::as_array) else {
        return Ok(Vec::new());
    };
    let mut assessments = Vec::new();
    for container in containers {
        let provider = container
            .pointer("/providerMetadata/shortName")
            .or_else(|| container.pointer("/providerMetadata/orgId"))
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_owned();
        let Some(metrics) = container.get("metrics").and_then(Value::as_array) else {
            continue;
        };
        for metric in metrics {
            let Some(other) = metric.get("other") else {
                continue;
            };
            if !other
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(|kind| kind.eq_ignore_ascii_case("ssvc"))
            {
                continue;
            }
            let raw_content = other
                .get("content")
                .ok_or_else(|| format!("{record_id}: SSVC metric has no content"))?;
            let content: SsvcContent = serde_json::from_value(raw_content.clone())
                .map_err(|error| format!("{record_id}: invalid SSVC content: {error}"))?;
            if !content.id.eq_ignore_ascii_case(record_id) {
                return Err(format!(
                    "{record_id}: SSVC content identifies a different CVE `{}`",
                    content.id
                ));
            }
            let mut exploitation = None;
            let mut automatable = None;
            let mut technical_impact = None;
            for option in &content.options {
                for (name, value) in option {
                    match name.as_str() {
                        "Exploitation" => exploitation = Some(value.parse()?),
                        "Automatable" => automatable = Some(value.parse()?),
                        "Technical Impact" => technical_impact = Some(value.parse()?),
                        _ => {}
                    }
                }
            }
            assessments.push(SsvcAssessment {
                cve_id: record_id.to_owned(),
                provider: provider.clone(),
                role: content.role,
                version: content.version,
                assessed_at: content.timestamp,
                exploitation,
                automatable,
                technical_impact,
                raw_json: serde_json::to_string(raw_content)
                    .map_err(|error| format!("{record_id}: cannot encode SSVC content: {error}"))?,
            });
        }
    }
    Ok(assessments)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_cisa_ssvc_metric() {
        let value = serde_json::json!({
            "cveMetadata": {"cveId": "CVE-2026-1234"},
            "containers": {
                "adp": [
                    {
                        "providerMetadata": {"shortName": "CISA-ADP"},
                        "metrics": [
                            {
                                "other": {
                                    "type": "ssvc",
                                    "content": {
                                        "id": "CVE-2026-1234",
                                        "role": "CISA Coordinator",
                                        "version": "2.0.3",
                                        "timestamp": "2026-01-02T03:04:05Z",
                                        "options": [
                                            {"Exploitation": "poc"},
                                            {"Automatable": "yes"},
                                            {"Technical Impact": "total"}
                                        ]
                                    }
                                }
                            }
                        ]
                    }
                ]
            }
        });
        let assessment = assessments_from_cve(&value).unwrap().pop().unwrap();
        assert_eq!(assessment.cve_id, "CVE-2026-1234");
        assert_eq!(assessment.provider, "CISA-ADP");
        assert_eq!(assessment.exploitation, Some(SsvcExploitation::PublicPoc));
        assert_eq!(assessment.automatable, Some(SsvcAutomatable::Yes));
        assert_eq!(
            assessment.technical_impact,
            Some(SsvcTechnicalImpact::Total)
        );
    }

    #[test]
    fn records_without_ssvc_are_empty() {
        let value = serde_json::json!({
            "cveMetadata": {"cveId": "CVE-2026-1234"},
            "containers": {"cna": {}}
        });
        assert!(assessments_from_cve(&value).unwrap().is_empty());
    }

    #[test]
    fn rejects_unknown_decision_point_values() {
        let value = serde_json::json!({
            "cveMetadata": {"cveId": "CVE-2026-1234"},
            "containers": {
                "adp": [
                    {
                        "metrics": [
                            {
                                "other": {
                                    "type": "ssvc",
                                    "content": {
                                        "id": "CVE-2026-1234",
                                        "role": "coordinator",
                                        "version": "2",
                                        "timestamp": "2026-01-01T00:00:00Z",
                                        "options": [{"Exploitation": "unknown"}]
                                    }
                                }
                            }
                        ]
                    }
                ]
            }
        });
        assert!(
            assessments_from_cve(&value)
                .unwrap_err()
                .contains("unsupported SSVC value")
        );
    }
}
