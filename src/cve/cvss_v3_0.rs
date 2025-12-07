use serde::Deserialize;
use strum::{AsRefStr, EnumString};

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
pub enum CvssV3_0BaseSeverity {
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
pub enum CvssV3_0AttackVector {
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
pub enum CvssV3_0AttackComplexity {
    #[strum(serialize = "HIGH")]
    High,
    #[strum(serialize = "LOW")]
    Low,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
pub enum CvssV3_0PrivilegesRequired {
    #[strum(serialize = "HIGH")]
    High,
    #[strum(serialize = "LOW")]
    Low,
    #[strum(serialize = "NONE")]
    None,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
pub enum CvssV3_0UserInteraction {
    #[strum(serialize = "NONE")]
    None,
    #[strum(serialize = "REQUIRED")]
    Required,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
pub enum CvssV3_0Scope {
    #[strum(serialize = "UNCHANGED")]
    Unchanged,
    #[strum(serialize = "CHANGED")]
    Changed,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
pub enum CvssV3_0ConfidentialityImpact {
    #[strum(serialize = "NONE")]
    None,
    #[strum(serialize = "LOW")]
    Low,
    #[strum(serialize = "HIGH")]
    High,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
pub enum CvssV3_0ExploitMaturity {
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
pub enum CvssV3_0RemediationLevel {
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
pub enum CvssV3_0ReportConfidence {
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
pub enum CvssV3_0ConfidentialityRequirement {
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
pub enum CvssV3_0ModifiedAttackVector {
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
pub enum CvssV3_0ModifiedAttackComplexity {
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
pub enum CvssV3_0ModifiedPrivilegesRequired {
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
pub enum CvssV3_0ModifiedUserInteraction {
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
pub enum CvssV3_0ModifiedScope {
    #[strum(serialize = "UNCHANGED")]
    Unchanged,
    #[strum(serialize = "CHANGED")]
    Changed,
    #[strum(serialize = "NOT_DEFINED")]
    NotDefined,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
pub enum CvssV3_0ModifiedVulnConfidentialityImpact {
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
pub struct CvssV3_0 {
    pub version: String,
    pub vector_string: String,
    pub attack_vector: Option<CvssV3_0AttackVector>,
    pub attack_complexity: Option<CvssV3_0AttackComplexity>,
    pub privileges_required: Option<CvssV3_0PrivilegesRequired>,
    pub user_interaction: Option<CvssV3_0UserInteraction>,
    pub scope: Option<CvssV3_0Scope>,
    pub confidentiality_impact: Option<CvssV3_0ConfidentialityImpact>,
    pub integrity_impact: Option<CvssV3_0ConfidentialityImpact>,
    pub availability_impact: Option<CvssV3_0ConfidentialityImpact>,
    pub base_score: f32,
    pub base_severity: CvssV3_0BaseSeverity,
    pub exploit_code_maturity: Option<CvssV3_0ExploitMaturity>,
    pub remediation_level: Option<CvssV3_0RemediationLevel>,
    pub report_confidence: Option<CvssV3_0ReportConfidence>,
    pub temporal_score: Option<f32>,
    pub temporal_severity: Option<CvssV3_0BaseSeverity>,
    pub confidentiality_requirement: Option<CvssV3_0ConfidentialityRequirement>,
    pub availability_requirement: Option<CvssV3_0ConfidentialityRequirement>,
    pub modified_attack_vector: Option<CvssV3_0ModifiedAttackVector>,
    pub modified_attack_complexity: Option<CvssV3_0ModifiedAttackComplexity>,
    pub modified_privileges_required: Option<CvssV3_0ModifiedPrivilegesRequired>,
    pub modified_user_interaction: Option<CvssV3_0ModifiedUserInteraction>,
    pub modified_scope: Option<CvssV3_0ModifiedScope>,
    pub modified_confidentiality_impact: Option<CvssV3_0ModifiedVulnConfidentialityImpact>,
    pub modified_integrity_impact: Option<CvssV3_0ModifiedVulnConfidentialityImpact>,
    pub modified_availability_impact: Option<CvssV3_0ModifiedVulnConfidentialityImpact>,
    pub environmental_score: Option<f32>,
    pub environmental_severity: Option<CvssV3_0BaseSeverity>,
}
