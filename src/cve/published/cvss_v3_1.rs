use serde::Deserialize;
use strum::{AsRefStr, EnumString};

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CvssV3_1BaseSeverity {
    #[strum(serialize = "NONE")]
    None,
    #[strum(serialize = "LOW")]
    Low,
    #[strum(serialize = "MEDIUM")]
    Medium,
    #[strum(serialize = "HIGH")]
    High,
    #[strum(serialize = "CRITICAL")]
    Critical,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CvssV3_1AttackVector {
    #[strum(serialize = "NETWORK")]
    Network,
    #[strum(serialize = "ADJACENT_NETWORK")]
    AdjacentNetwork,
    #[strum(serialize = "LOCAL")]
    Local,
    #[strum(serialize = "PHYSICAL")]
    Physical,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CvssV3_1AttackComplexity {
    #[strum(serialize = "HIGH")]
    High,
    #[strum(serialize = "LOW")]
    Low,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CvssV3_1PrivilegesRequired {
    #[strum(serialize = "HIGH")]
    High,
    #[strum(serialize = "LOW")]
    Low,
    #[strum(serialize = "NONE")]
    None,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CvssV3_1UserInteraction {
    #[strum(serialize = "NONE")]
    None,
    #[strum(serialize = "REQUIRED")]
    Required,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CvssV3_1Scope {
    #[strum(serialize = "UNCHANGED")]
    Unchanged,
    #[strum(serialize = "CHANGED")]
    Changed,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CvssV3_1ConfidentialityImpact {
    #[strum(serialize = "NONE")]
    None,
    #[strum(serialize = "LOW")]
    Low,
    #[strum(serialize = "HIGH")]
    High,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CvssV3_1ExploitMaturity {
    #[strum(serialize = "UNPROVEN")]
    Unproven,
    #[strum(serialize = "PROOF_OF_CONCEPT")]
    ProofOfConcept,
    #[strum(serialize = "FUNCTIONAL")]
    Functional,
    #[strum(serialize = "HIGH")]
    High,
    #[strum(serialize = "NOT_DEFINED")]
    NotDefined,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CvssV3_1RemediationLevel {
    #[strum(serialize = "OFFICIAL_FIX")]
    OfficialFix,
    #[strum(serialize = "TEMPORARY_FIX")]
    TemporaryFix,
    #[strum(serialize = "Workaround")]
    Workaround,
    #[strum(serialize = "Unavailable")]
    Unavailable,
    #[strum(serialize = "NOT_DEFINED")]
    NotDefined,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CvssV3_1ReportConfidence {
    #[strum(serialize = "UNKNOWN")]
    Unknown,
    #[strum(serialize = "REASONABLE")]
    Reasonable,
    #[strum(serialize = "CONFIRMED")]
    Confirmed,
    #[strum(serialize = "NOT_DEFINED")]
    NotDefined,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CvssV3_1ConfidentialityRequirement {
    #[strum(serialize = "LOW")]
    Low,
    #[strum(serialize = "MEDIUM")]
    Medium,
    #[strum(serialize = "HIGH")]
    High,
    #[strum(serialize = "NOT_DEFINED")]
    NotDefined,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CvssV3_1ModifiedAttackVector {
    #[strum(serialize = "NETWORK")]
    Network,
    #[strum(serialize = "ADJACENT")]
    Adjacent,
    #[strum(serialize = "LOCAL")]
    Local,
    #[strum(serialize = "PHYSICAL")]
    Physical,
    #[strum(serialize = "NOT_DEFINED")]
    NotDefined,
}
#[derive(Debug, Deserialize, EnumString, AsRefStr)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CvssV3_1ModifiedAttackComplexity {
    #[strum(serialize = "HIGH")]
    High,
    #[strum(serialize = "MEDIUM")]
    Medium,
    #[strum(serialize = "LOW")]
    Low,
    #[strum(serialize = "NOT_DEFINED")]
    NotDefined,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CvssV3_1ModifiedPrivilegesRequired {
    #[strum(serialize = "HIGH")]
    High,
    #[strum(serialize = "MEDIUM")]
    Medium,
    #[strum(serialize = "LOW")]
    Low,
    #[strum(serialize = "NOT_DEFINED")]
    NotDefined,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CvssV3_1ModifiedUserInteraction {
    #[strum(serialize = "NONE")]
    None,
    #[strum(serialize = "PASSIVE")]
    Passive,
    #[strum(serialize = "ACTIVE")]
    Active,
    #[strum(serialize = "NOT_DEFINED")]
    NotDefined,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CvssV3_1ModifiedScope {
    #[strum(serialize = "UNCHANGED")]
    Unchanged,
    #[strum(serialize = "CHANGED")]
    Changed,
    #[strum(serialize = "NOT_DEFINED")]
    NotDefined,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CvssV3_1ModifiedVulnConfidentialityImpact {
    #[strum(serialize = "NONE")]
    None,
    #[strum(serialize = "LOW")]
    Low,
    #[strum(serialize = "HIGH")]
    High,
    #[strum(serialize = "NOT_DEFINED")]
    NotDefined,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CvssV3_1 {
    pub version: String,
    pub vector_string: String,
    pub attack_vector: Option<CvssV3_1AttackVector>,
    pub attack_complexity: Option<CvssV3_1AttackComplexity>,
    pub privileges_required: Option<CvssV3_1PrivilegesRequired>,
    pub user_interaction: Option<CvssV3_1UserInteraction>,
    pub scope: Option<CvssV3_1Scope>,
    pub confidentiality_impact: Option<CvssV3_1ConfidentialityImpact>,
    pub integrity_impact: Option<CvssV3_1ConfidentialityImpact>,
    pub availability_impact: Option<CvssV3_1ConfidentialityImpact>,
    pub base_score: f32,
    pub base_severity: CvssV3_1BaseSeverity,
    pub exploit_code_maturity: Option<CvssV3_1ExploitMaturity>,
    pub remediation_level: Option<CvssV3_1RemediationLevel>,
    pub report_confidence: Option<CvssV3_1ReportConfidence>,
    pub temporal_score: Option<f32>,
    pub temporal_severity: Option<CvssV3_1BaseSeverity>,
    pub confidentiality_requirement: Option<CvssV3_1ConfidentialityRequirement>,
    pub availability_requirement: Option<CvssV3_1ConfidentialityRequirement>,
    pub modified_attack_vector: Option<CvssV3_1ModifiedAttackVector>,
    pub modified_attack_complexity: Option<CvssV3_1ModifiedAttackComplexity>,
    pub modified_privileges_required: Option<CvssV3_1ModifiedPrivilegesRequired>,
    pub modified_user_interaction: Option<CvssV3_1ModifiedUserInteraction>,
    pub modified_scope: Option<CvssV3_1ModifiedScope>,
    pub modified_confidentiality_impact: Option<CvssV3_1ModifiedVulnConfidentialityImpact>,
    pub modified_integrity_impact: Option<CvssV3_1ModifiedVulnConfidentialityImpact>,
    pub modified_availability_impact: Option<CvssV3_1ModifiedVulnConfidentialityImpact>,
    pub environmental_score: Option<f32>,
    pub environmental_severity: Option<CvssV3_1BaseSeverity>,
}
