use super::{cvss_v2_0::*, cvss_v3_0::*, cvss_v3_1::*, cvss_v4_0::*};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CvssVectorMetric {
    pub name: String,
    pub value: String,
}

pub fn explain_cvss_vector(version: &str, vector: &str) -> Vec<CvssVectorMetric> {
    let vector_version = vector
        .strip_prefix("CVSS:")
        .and_then(|vector| vector.split('/').next())
        .unwrap_or("");
    let version = if vector_version.is_empty() {
        version
    } else {
        vector_version
    };
    let skip_header = usize::from(vector.starts_with("CVSS:"));

    vector
        .split('/')
        .skip(skip_header)
        .filter_map(|metric| metric.split_once(':'))
        .map(|(key, raw_value)| {
            let name = metric_name(version, key).unwrap_or(key).to_owned();
            let value =
                metric_value(version, key, raw_value).unwrap_or_else(|| raw_value.to_owned());
            CvssVectorMetric { name, value }
        })
        .collect()
}

fn metric_name(version: &str, metric: &str) -> Option<&'static str> {
    match metric {
        "AV" | "MAV" => Some(if version.starts_with('2') {
            "Access Vector"
        } else {
            "Attack Vector"
        }),
        "AC" | "MAC" => Some(if version.starts_with('2') {
            "Access Complexity"
        } else {
            "Attack Complexity"
        }),
        "AT" | "MAT" => Some("Attack Requirements"),
        "Au" => Some("Authentication"),
        "PR" | "MPR" => Some("Privileges Required"),
        "UI" | "MUI" => Some("User Interaction"),
        "S" | "MS" if !version.starts_with('4') => Some("Scope"),
        "C" | "MC" => Some("Confidentiality Impact"),
        "I" | "MI" => Some("Integrity Impact"),
        "A" | "MA" => Some("Availability Impact"),
        "VC" | "MVC" => Some("Vulnerable System Confidentiality"),
        "VI" | "MVI" => Some("Vulnerable System Integrity"),
        "VA" | "MVA" => Some("Vulnerable System Availability"),
        "SC" | "MSC" => Some("Subsequent System Confidentiality"),
        "SI" | "MSI" => Some("Subsequent System Integrity"),
        "SA" | "MSA" => Some("Subsequent System Availability"),
        "E" => Some("Exploit Maturity"),
        "RL" => Some("Remediation Level"),
        "RC" => Some("Report Confidence"),
        "CR" => Some("Confidentiality Requirement"),
        "IR" => Some("Integrity Requirement"),
        "AR" => Some("Availability Requirement"),
        "CDP" => Some("Collateral Damage Potential"),
        "TD" => Some("Target Distribution"),
        "S" if version.starts_with('4') => Some("Safety"),
        "AU" => Some("Automatable"),
        "R" => Some("Recovery"),
        "V" => Some("Value Density"),
        "RE" => Some("Response Effort"),
        "U" => Some("Provider Urgency"),
        _ => None,
    }
}

fn model_value(value: impl AsRef<str>) -> String {
    match value.as_ref() {
        "PROOF_OF_CONCEPT" => "Proof-of-Concept".to_owned(),
        value => value
            .split('_')
            .map(|word| {
                let mut chars = word.chars();
                match chars.next() {
                    Some(first) => format!(
                        "{}{}",
                        first.to_ascii_uppercase(),
                        chars.as_str().to_ascii_lowercase()
                    ),
                    None => String::new(),
                }
            })
            .collect::<Vec<_>>()
            .join(" "),
    }
}

macro_rules! enum_value {
    ($value:expr, $enum:ty, { $($raw:literal => $variant:ident),+ $(,)? }) => {
        match $value {
            $($raw => Some(model_value(<$enum>::$variant)),)+
            _ => None,
        }
    };
}

fn metric_value(version: &str, metric: &str, value: &str) -> Option<String> {
    if value == "X" || value == "ND" {
        return Some("Not Defined".to_owned());
    }
    if version.starts_with('2') {
        return v2_value(metric, value);
    }
    if version == "3.0" {
        return v3_0_value(metric, value);
    }
    if version.starts_with('3') {
        return v3_1_value(metric, value);
    }
    if version.starts_with('4') {
        return v4_value(metric, value);
    }
    None
}

fn v2_value(metric: &str, value: &str) -> Option<String> {
    match metric {
        "AV" => {
            enum_value!(value, CvssV2_0AccessVector, { "N" => Network, "A" => AdjacentNetwork, "L" => Local })
        }
        "AC" => {
            enum_value!(value, CvssV2_0AccessComplexity, { "H" => High, "M" => Medium, "L" => Low })
        }
        "Au" => {
            enum_value!(value, CvssV2_0Authentication, { "M" => Multiple, "S" => Single, "N" => None })
        }
        "C" | "I" | "A" => {
            enum_value!(value, CvssV2_0ConfidentialityImpact, { "N" => None, "P" => Partial, "C" => Complete })
        }
        "E" => {
            enum_value!(value, CvssV2_0Exploitability, { "U" => Unproven, "POC" => ProofOfConcept, "F" => Functional, "H" => High })
        }
        "RL" => {
            enum_value!(value, CvssV2_0RemediationLevel, { "OF" => OfficialFix, "TF" => TemporaryFix, "W" => Workaround, "U" => Unavailable })
        }
        "RC" => {
            enum_value!(value, CvssV2_0ReportConfidence, { "UC" => Unconfirmed, "UR" => Uncorroborated, "C" => Confirmed })
        }
        "CDP" => {
            enum_value!(value, CvssV2_0CollateralDamagePotential, { "N" => None, "L" => Low, "LM" => LowMedium, "MH" => MediumHigh, "H" => High })
        }
        "TD" => {
            enum_value!(value, CvssV2_0TargetDistribution, { "N" => None, "L" => Low, "M" => Medium, "H" => High })
        }
        "CR" | "IR" | "AR" => {
            enum_value!(value, CvssV2_0ConfidentialityRequirement, { "L" => Low, "M" => Medium, "H" => High })
        }
        _ => None,
    }
}

fn v3_0_value(metric: &str, value: &str) -> Option<String> {
    match metric {
        "AV" => enum_value!(value, CvssV3_0AttackVector, { "N" => Network, "A" => AdjacentNetwork, "L" => Local, "P" => Physical }),
        "AC" => enum_value!(value, CvssV3_0AttackComplexity, { "H" => High, "L" => Low }),
        "PR" => enum_value!(value, CvssV3_0PrivilegesRequired, { "H" => High, "L" => Low, "N" => None }),
        "UI" => enum_value!(value, CvssV3_0UserInteraction, { "N" => None, "R" => Required }),
        "S" => enum_value!(value, CvssV3_0Scope, { "U" => Unchanged, "C" => Changed }),
        "C" | "I" | "A" => enum_value!(value, CvssV3_0ConfidentialityImpact, { "N" => None, "L" => Low, "H" => High }),
        "E" => enum_value!(value, CvssV3_0ExploitMaturity, { "U" => Unproven, "P" => ProofOfConcept, "F" => Functional, "H" => High }),
        "RL" => enum_value!(value, CvssV3_0RemediationLevel, { "O" => OfficialFix, "T" => TemporaryFix, "W" => Workaround, "U" => Unavailable }),
        "RC" => enum_value!(value, CvssV3_0ReportConfidence, { "U" => Unknown, "R" => Reasonable, "C" => Confirmed }),
        "CR" | "IR" | "AR" => enum_value!(value, CvssV3_0ConfidentialityRequirement, { "L" => Low, "M" => Medium, "H" => High }),
        "MAV" => enum_value!(value, CvssV3_0ModifiedAttackVector, { "N" => Network, "A" => Adjacent, "L" => Local, "P" => Physical }),
        "MAC" => enum_value!(value, CvssV3_0ModifiedAttackComplexity, { "H" => High, "M" => Medium, "L" => Low }),
        "MPR" => enum_value!(value, CvssV3_0ModifiedPrivilegesRequired, { "H" => High, "M" => Medium, "L" => Low }).or_else(|| (value == "N").then(|| "None".to_owned())),
        "MUI" => enum_value!(value, CvssV3_0ModifiedUserInteraction, { "N" => None }).or_else(|| (value == "R").then(|| "Required".to_owned())),
        "MS" => enum_value!(value, CvssV3_0ModifiedScope, { "U" => Unchanged, "C" => Changed }),
        "MC" | "MI" | "MA" => enum_value!(value, CvssV3_0ModifiedVulnConfidentialityImpact, { "N" => None, "L" => Low, "H" => High }),
        _ => None,
    }
}

fn v3_1_value(metric: &str, value: &str) -> Option<String> {
    match metric {
        "AV" => enum_value!(value, CvssV3_1AttackVector, { "N" => Network, "A" => AdjacentNetwork, "L" => Local, "P" => Physical }),
        "AC" => enum_value!(value, CvssV3_1AttackComplexity, { "H" => High, "L" => Low }),
        "PR" => enum_value!(value, CvssV3_1PrivilegesRequired, { "H" => High, "L" => Low, "N" => None }),
        "UI" => enum_value!(value, CvssV3_1UserInteraction, { "N" => None, "R" => Required }),
        "S" => enum_value!(value, CvssV3_1Scope, { "U" => Unchanged, "C" => Changed }),
        "C" | "I" | "A" => enum_value!(value, CvssV3_1ConfidentialityImpact, { "N" => None, "L" => Low, "H" => High }),
        "E" => enum_value!(value, CvssV3_1ExploitMaturity, { "U" => Unproven, "P" => ProofOfConcept, "F" => Functional, "H" => High }),
        "RL" => enum_value!(value, CvssV3_1RemediationLevel, { "O" => OfficialFix, "T" => TemporaryFix, "W" => Workaround, "U" => Unavailable }),
        "RC" => enum_value!(value, CvssV3_1ReportConfidence, { "U" => Unknown, "R" => Reasonable, "C" => Confirmed }),
        "CR" | "IR" | "AR" => enum_value!(value, CvssV3_1ConfidentialityRequirement, { "L" => Low, "M" => Medium, "H" => High }),
        "MAV" => enum_value!(value, CvssV3_1ModifiedAttackVector, { "N" => Network, "A" => Adjacent, "L" => Local, "P" => Physical }),
        "MAC" => enum_value!(value, CvssV3_1ModifiedAttackComplexity, { "H" => High, "M" => Medium, "L" => Low }),
        "MPR" => enum_value!(value, CvssV3_1ModifiedPrivilegesRequired, { "H" => High, "M" => Medium, "L" => Low }).or_else(|| (value == "N").then(|| "None".to_owned())),
        "MUI" => enum_value!(value, CvssV3_1ModifiedUserInteraction, { "N" => None }).or_else(|| (value == "R").then(|| "Required".to_owned())),
        "MS" => enum_value!(value, CvssV3_1ModifiedScope, { "U" => Unchanged, "C" => Changed }),
        "MC" | "MI" | "MA" => enum_value!(value, CvssV3_1ModifiedVulnConfidentialityImpact, { "N" => None, "L" => Low, "H" => High }),
        _ => None,
    }
}

fn v4_value(metric: &str, value: &str) -> Option<String> {
    match metric {
        "AV" => enum_value!(value, CvssV4_0AttackVector, { "N" => Network, "A" => Adjacent, "L" => Local, "P" => Physical }),
        "AC" => enum_value!(value, CvssV4_0AttackComplexity, { "H" => High, "L" => Low }),
        "AT" => enum_value!(value, CvssV4_0AttackRequirements, { "N" => None }).or_else(|| (value == "P").then(|| "Present".to_owned())),
        "PR" => enum_value!(value, CvssV4_0PrivilegesRequired, { "H" => High, "L" => Low, "N" => None }),
        "UI" => enum_value!(value, CvssV4_0UserInteraction, { "N" => None, "P" => Passive, "A" => Active }),
        "VC" | "VI" | "VA" => enum_value!(value, CvssV4_0VulnConfidentialityImpact, { "N" => None, "L" => Low, "H" => High }),
        "SC" | "SI" | "SA" => enum_value!(value, CvssV4_0SubConfidentialityImpact, { "N" => None, "L" => Low, "H" => High }),
        "E" => enum_value!(value, CvssV4_0ExploitMaturity, { "U" => Unreported, "P" => ProofOfConcept, "A" => Attacked }),
        "CR" | "IR" | "AR" => enum_value!(value, CvssV4_0ConfidentialityRequirement, { "L" => Low, "M" => Medium, "H" => High }),
        "MAV" => enum_value!(value, CvssV4_0ModifiedAttackVector, { "N" => Network, "A" => Adjacent, "L" => Local, "P" => Physical }),
        "MAC" => enum_value!(value, CvssV4_0ModifiedAttackComplexity, { "H" => High, "M" => Medium, "L" => Low }),
        "MAT" => enum_value!(value, CvssV4_0AttackRequirements, { "N" => None }).or_else(|| (value == "P").then(|| "Present".to_owned())),
        "MPR" => enum_value!(value, CvssV4_0ModifiedPrivilegesRequired, { "H" => High, "M" => Medium, "L" => Low }).or_else(|| (value == "N").then(|| "None".to_owned())),
        "MUI" => enum_value!(value, CvssV4_0ModifiedUserInteraction, { "N" => None, "P" => Passive, "A" => Active }),
        "MVC" | "MVI" | "MVA" => enum_value!(value, CvssV4_0ModifiedVulnConfidentialityImpact, { "N" => None, "L" => Low, "H" => High }),
        "MSC" => enum_value!(value, CvssV4_0ModifiedSubConfidentialityImpact, { "N" => None, "L" => Low, "H" => High }),
        "MSI" | "MSA" => enum_value!(value, CvssV4_0ModifiedSubIntegrityImpact, { "N" => None, "L" => Low, "H" => High, "S" => Safety }),
        "S" => enum_value!(value, CvssV4_0Safety, { "N" => Negligible, "P" => Present }),
        "AU" => enum_value!(value, CvssV4_0Automatable, { "N" => No, "Y" => Yes }),
        "R" => enum_value!(value, CvssV4_0Recovery, { "A" => Automatic, "U" => User, "I" => Irrecoverable }),
        "V" => enum_value!(value, CvssV4_0ValueDensity, { "D" => Diffuse, "C" => Concentrated }),
        "RE" => enum_value!(value, CvssV4_0VulnerabilityResponseEffort, { "L" => Low, "M" => Moderate, "H" => High }),
        "U" => enum_value!(value, CvssV4_0ProviderUrgency, { "Clear" => Clear, "Green" => Green, "Amber" => Amber, "Red" => Red }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explains_v3_1_base_vector_using_model_values() {
        let metrics = explain_cvss_vector("3.1", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");

        assert_eq!(
            metrics[0],
            CvssVectorMetric {
                name: "Attack Vector".to_owned(),
                value: "Network".to_owned()
            }
        );
        assert_eq!(
            metrics[4],
            CvssVectorMetric {
                name: "Scope".to_owned(),
                value: "Changed".to_owned()
            }
        );
    }

    #[test]
    fn explains_v2_vector_without_version_prefix() {
        let metrics = explain_cvss_vector("2.0", "AV:A/AC:M/Au:S/C:P");

        assert_eq!(metrics[0].value, "Adjacent Network");
        assert_eq!(metrics[1].value, "Medium");
        assert_eq!(metrics[2].value, "Single");
        assert_eq!(metrics[3].value, "Partial");
    }

    #[test]
    fn preserves_unknown_metrics() {
        assert_eq!(
            explain_cvss_vector("9.9", "CVSS:9.9/ZZ:Q"),
            vec![CvssVectorMetric {
                name: "ZZ".to_owned(),
                value: "Q".to_owned()
            }]
        );
    }
}
