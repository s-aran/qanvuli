use serde::Deserialize;
use strum::{AsRefStr, EnumString};

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CvssV2_0BaseSeverity {
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
pub enum CvssV2_0AccessVector {
    #[strum(serialize = "NETWORK")]
    Network,
    #[strum(serialize = "ADJACENT_NETWORK")]
    AdjacentNetwork,
    #[strum(serialize = "LOCAL")]
    Local,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CvssV2_0AccessComplexity {
    #[strum(serialize = "HIGH")]
    High,
    #[strum(serialize = "MEDIUM")]
    Medium,
    #[strum(serialize = "LOW")]
    Low,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CvssV2_0Authentication {
    #[strum(serialize = "MULTIPLE")]
    Multiple,
    #[strum(serialize = "SINGLE")]
    Single,
    #[strum(serialize = "NONE")]
    None,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CvssV2_0UserInteraction {
    #[strum(serialize = "NONE")]
    None,
    #[strum(serialize = "REQUIRED")]
    Required,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CvssV2_0Scope {
    #[strum(serialize = "UNCHANGED")]
    Unchanged,
    #[strum(serialize = "CHANGED")]
    Changed,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CvssV2_0ConfidentialityImpact {
    #[strum(serialize = "NONE")]
    None,
    #[strum(serialize = "PARTIAL")]
    Partial,
    #[strum(serialize = "COMPLETE")]
    Complete,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CvssV2_0Exploitability {
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
pub enum CvssV2_0RemediationLevel {
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
pub enum CvssV2_0ReportConfidence {
    #[strum(serialize = "UNCONFIRMED")]
    Unconfirmed,
    #[strum(serialize = "UNCORROBORATED")]
    Uncorroborated,
    #[strum(serialize = "CONFIRMED")]
    Confirmed,
    #[strum(serialize = "NOT_DEFINED")]
    NotDefined,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CvssV2_0CollateralDamagePotential {
    #[strum(serialize = "NONE")]
    None,
    #[strum(serialize = "LOW")]
    Low,
    #[strum(serialize = "LOW_MEDIUM")]
    LowMedium,
    #[strum(serialize = "MEDIUM_HIGH")]
    MediumHigh,
    #[strum(serialize = "HIGH")]
    High,
    #[strum(serialize = "NOT_DEFINED")]
    NotDefined,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CvssV2_0TargetDistribution {
    #[strum(serialize = "NONE")]
    None,
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
pub enum CvssV2_0ConfidentialityRequirement {
    #[strum(serialize = "LOW")]
    Low,
    #[strum(serialize = "MEDIUM")]
    Medium,
    #[strum(serialize = "HIGH")]
    High,
    #[strum(serialize = "NOT_DEFINED")]
    NotDefined,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CvssV2_0 {
    pub version: String,
    pub vector_string: String,
    pub access_vector: Option<CvssV2_0AccessVector>,
    pub access_complexity: Option<CvssV2_0AccessComplexity>,
    pub authentication: Option<CvssV2_0Authentication>,
    pub confidentiality_impact: Option<CvssV2_0ConfidentialityImpact>,
    pub integrity_impact: Option<CvssV2_0ConfidentialityImpact>,
    pub availability_impact: Option<CvssV2_0ConfidentialityImpact>,
    pub base_score: f32,
    pub exploitability: Option<CvssV2_0Exploitability>,
    pub remediation_level: Option<CvssV2_0RemediationLevel>,
    pub report_confidence: Option<CvssV2_0ReportConfidence>,
    pub temporal_score: Option<f32>,
    pub collateral_damage_potential: Option<CvssV2_0CollateralDamagePotential>,
    pub target_distribution: Option<CvssV2_0TargetDistribution>,
    pub confidentiality_requirement: Option<CvssV2_0ConfidentialityRequirement>,
    pub integrity_requirement: Option<CvssV2_0ConfidentialityRequirement>,
    pub availability_requirement: Option<CvssV2_0ConfidentialityRequirement>,
    pub environmental_score: Option<f32>,
}
