use serde::Deserialize;
use strum::{AsRefStr, EnumString};

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CvssV4_0BaseSeverity {
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
pub enum CvssV4_0AttackVector {
    #[strum(serialize = "NETWORK")]
    Network,
    #[strum(serialize = "ADJACENT")]
    Adjacent,
    #[strum(serialize = "LOCAL")]
    Local,
    #[strum(serialize = "PHYSICAL")]
    Physical,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CvssV4_0AttackComplexity {
    #[strum(serialize = "HIGH")]
    High,
    #[strum(serialize = "LOW")]
    Low,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CvssV4_0AttackRequirements {
    #[strum(serialize = "NONE")]
    None,
    #[strum(serialize = "LOW")]
    Low,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CvssV4_0PrivilegesRequired {
    #[strum(serialize = "HIGH")]
    High,
    #[strum(serialize = "LOW")]
    Low,
    #[strum(serialize = "NONE")]
    None,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CvssV4_0UserInteraction {
    #[strum(serialize = "NONE")]
    None,
    #[strum(serialize = "PASSIVE")]
    Passive,
    #[strum(serialize = "ACTIVE")]
    Active,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CvssV4_0VulnConfidentialityImpact {
    #[strum(serialize = "NONE")]
    None,
    #[strum(serialize = "LOW")]
    Low,
    #[strum(serialize = "HIGH")]
    High,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CvssV4_0SubConfidentialityImpact {
    #[strum(serialize = "NONE")]
    None,
    #[strum(serialize = "LOW")]
    Low,
    #[strum(serialize = "HIGH")]
    High,
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CvssV4_0ExploitMaturity {
    #[strum(serialize = "UNREPORTED")]
    Unreported,
    #[strum(serialize = "PROOF_OF_CONCEPT")]
    ProofOfConcept,
    #[strum(serialize = "ATTACKED")]
    Attacked,
    #[strum(serialize = "NOT_DEFINED")]
    NotDefined,
}

impl Default for CvssV4_0ExploitMaturity {
    fn default() -> Self {
        CvssV4_0ExploitMaturity::NotDefined
    }
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CvssV4_0ConfidentialityRequirement {
    #[strum(serialize = "LOW")]
    Low,
    #[strum(serialize = "MEDIUM")]
    Medium,
    #[strum(serialize = "HIGH")]
    High,
    #[strum(serialize = "NOT_DEFINED")]
    NotDefined,
}

impl Default for CvssV4_0ConfidentialityRequirement {
    fn default() -> Self {
        CvssV4_0ConfidentialityRequirement::NotDefined
    }
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CvssV4_0ModifiedAttackVector {
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

impl Default for CvssV4_0ModifiedAttackVector {
    fn default() -> Self {
        CvssV4_0ModifiedAttackVector::NotDefined
    }
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CvssV4_0ModifiedAttackComplexity {
    #[strum(serialize = "HIGH")]
    High,
    #[strum(serialize = "MEDIUM")]
    Medium,
    #[strum(serialize = "LOW")]
    Low,
    #[strum(serialize = "NOT_DEFINED")]
    NotDefined,
}

impl Default for CvssV4_0ModifiedAttackComplexity {
    fn default() -> Self {
        CvssV4_0ModifiedAttackComplexity::NotDefined
    }
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CvssV4_0ModifiedPrivilegesRequired {
    #[strum(serialize = "HIGH")]
    High,
    #[strum(serialize = "MEDIUM")]
    Medium,
    #[strum(serialize = "LOW")]
    Low,
    #[strum(serialize = "NOT_DEFINED")]
    NotDefined,
}

impl Default for CvssV4_0ModifiedPrivilegesRequired {
    fn default() -> Self {
        CvssV4_0ModifiedPrivilegesRequired::NotDefined
    }
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CvssV4_0ModifiedUserInteraction {
    #[strum(serialize = "NONE")]
    None,
    #[strum(serialize = "PASSIVE")]
    Passive,
    #[strum(serialize = "ACTIVE")]
    Active,
    #[strum(serialize = "NOT_DEFINED")]
    NotDefined,
}

impl Default for CvssV4_0ModifiedUserInteraction {
    fn default() -> Self {
        CvssV4_0ModifiedUserInteraction::NotDefined
    }
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CvssV4_0ModifiedVulnConfidentialityImpact {
    #[strum(serialize = "NONE")]
    None,
    #[strum(serialize = "LOW")]
    Low,
    #[strum(serialize = "HIGH")]
    High,
    #[strum(serialize = "NOT_DEFINED")]
    NotDefined,
}

impl Default for CvssV4_0ModifiedVulnConfidentialityImpact {
    fn default() -> Self {
        CvssV4_0ModifiedVulnConfidentialityImpact::NotDefined
    }
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CvssV4_0ModifiedSubConfidentialityImpact {
    #[strum(serialize = "NONE")]
    None,
    #[strum(serialize = "LOW")]
    Low,
    #[strum(serialize = "HIGH")]
    High,
    #[strum(serialize = "NOT_DEFINED")]
    NotDefined,
}

impl Default for CvssV4_0ModifiedSubConfidentialityImpact {
    fn default() -> Self {
        CvssV4_0ModifiedSubConfidentialityImpact::NotDefined
    }
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CvssV4_0ModifiedSubIntegrityImpact {
    #[strum(serialize = "NONE")]
    None,
    #[strum(serialize = "LOW")]
    Low,
    #[strum(serialize = "HIGH")]
    High,
    #[strum(serialize = "SAFETY")]
    Safety,
    #[strum(serialize = "NOT_DEFINED")]
    NotDefined,
}

impl Default for CvssV4_0ModifiedSubIntegrityImpact {
    fn default() -> Self {
        CvssV4_0ModifiedSubIntegrityImpact::NotDefined
    }
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CvssV4_0Safety {
    #[strum(serialize = "NEGLIGIBLE")]
    Negligible,
    #[strum(serialize = "PRESENT")]
    Present,
    #[strum(serialize = "NOT_DEFINED")]
    NotDefined,
}

impl Default for CvssV4_0Safety {
    fn default() -> Self {
        CvssV4_0Safety::NotDefined
    }
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CvssV4_0Automatable {
    #[strum(serialize = "NO")]
    No,
    #[strum(serialize = "YES")]
    Yes,
    #[strum(serialize = "NOT_DEFINED")]
    NotDefined,
}

impl Default for CvssV4_0Automatable {
    fn default() -> Self {
        CvssV4_0Automatable::NotDefined
    }
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CvssV4_0Recovery {
    #[strum(serialize = "AUTOMATIC")]
    Automatic,
    #[strum(serialize = "USER")]
    User,
    #[strum(serialize = "IRRECOVERABLE")]
    Irrecoverable,
    #[strum(serialize = "NOT_DEFINED")]
    NotDefined,
}

impl Default for CvssV4_0Recovery {
    fn default() -> Self {
        CvssV4_0Recovery::NotDefined
    }
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CvssV4_0ValueDensity {
    #[strum(serialize = "DIFFUSE")]
    Diffuse,
    #[strum(serialize = "CONCENTRATED")]
    Concentrated,
    #[strum(serialize = "NOT_DEFINED")]
    NotDefined,
}

impl Default for CvssV4_0ValueDensity {
    fn default() -> Self {
        CvssV4_0ValueDensity::NotDefined
    }
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CvssV4_0VulnerabilityResponseEffort {
    #[strum(serialize = "LOW")]
    Low,
    #[strum(serialize = "MODERATE")]
    Moderate,
    #[strum(serialize = "HIGH")]
    High,
    #[strum(serialize = "NOT_DEFINED")]
    NotDefined,
}

impl Default for CvssV4_0VulnerabilityResponseEffort {
    fn default() -> Self {
        CvssV4_0VulnerabilityResponseEffort::NotDefined
    }
}

#[derive(Debug, Deserialize, EnumString, AsRefStr)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CvssV4_0ProviderUrgency {
    #[strum(serialize = "CLEAR")]
    Clear,
    #[strum(serialize = "GREEN")]
    Green,
    #[strum(serialize = "AMBER")]
    Amber,
    #[strum(serialize = "RED")]
    Red,
    #[strum(serialize = "NOT_DEFINED")]
    NotDefined,
}

impl Default for CvssV4_0ProviderUrgency {
    fn default() -> Self {
        CvssV4_0ProviderUrgency::NotDefined
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CvssV4_0 {
    pub version: String,
    pub vector_string: String,
    pub base_score: f32,
    pub base_severity: CvssV4_0BaseSeverity,
    pub attack_vector: Option<CvssV4_0AttackVector>,
    pub attack_complexity: Option<CvssV4_0AttackComplexity>,
    pub attack_requirements: Option<CvssV4_0AttackRequirements>,
    pub privileges_required: Option<CvssV4_0PrivilegesRequired>,
    pub user_interaction: Option<CvssV4_0UserInteraction>,
    pub vuln_confidentiality_impact: Option<CvssV4_0VulnConfidentialityImpact>,
    pub vuln_integrity_impact: Option<CvssV4_0VulnConfidentialityImpact>,
    pub vuln_availability_impact: Option<CvssV4_0VulnConfidentialityImpact>,
    pub sub_confidentiality_impact: Option<CvssV4_0SubConfidentialityImpact>,
    pub sub_integrity_impact: Option<CvssV4_0SubConfidentialityImpact>,
    pub sub_availability_impact: Option<CvssV4_0SubConfidentialityImpact>,
    #[serde(default = "default_exploit_maturity")]
    pub exploit_maturity: CvssV4_0ExploitMaturity,
    #[serde(default = "default_confidentiality_requirement")]
    pub confidentiality_requirement: CvssV4_0ConfidentialityRequirement,
    #[serde(default = "default_availability_requirement")]
    pub availability_requirement: CvssV4_0ConfidentialityRequirement,
    #[serde(default = "default_modified_attack_vector")]
    pub modified_attack_vector: CvssV4_0ModifiedAttackVector,
    #[serde(default = "default_modified_attack_complexity")]
    pub modified_attack_complexity: CvssV4_0ModifiedAttackComplexity,
    #[serde(default = "default_modified_privileges_required")]
    pub modified_privileges_required: CvssV4_0ModifiedPrivilegesRequired,
    #[serde(default = "default_modified_user_interaction")]
    pub modified_user_interaction: CvssV4_0ModifiedUserInteraction,
    #[serde(default = "default_modified_vuln_confidentiality_impact")]
    pub modified_vuln_confidentiality_impact: CvssV4_0ModifiedVulnConfidentialityImpact,
    #[serde(default = "default_modified_vuln_integrity_impact")]
    pub modified_vuln_integrity_impact: CvssV4_0ModifiedVulnConfidentialityImpact,
    #[serde(default = "default_modified_vuln_availability_impact")]
    pub modified_vuln_availability_impact: CvssV4_0ModifiedVulnConfidentialityImpact,
    #[serde(default = "default_modified_sub_confidentiality_impact")]
    pub modified_sub_confidentiality_impact: CvssV4_0ModifiedSubConfidentialityImpact,
    #[serde(default = "default_modified_sub_integrity_impact")]
    pub modified_sub_integrity_impact: CvssV4_0ModifiedSubIntegrityImpact,
    #[serde(default = "default_modified_sub_availability_impact")]
    pub modified_sub_availability_impact: CvssV4_0ModifiedSubIntegrityImpact,
    #[serde(default = "default_safety")]
    pub safety: CvssV4_0Safety,
    #[serde(default = "default_automatable")]
    pub automatable: CvssV4_0Automatable,
    #[serde(default = "default_recovery")]
    pub recovery: CvssV4_0Recovery,
    #[serde(default = "default_value_density")]
    pub value_density: CvssV4_0ValueDensity,
    #[serde(default = "default_vulnerability_response_effort")]
    pub vulnerability_response_effort: CvssV4_0VulnerabilityResponseEffort,
    #[serde(default = "default_provider_urgency")]
    pub provider_urgency: CvssV4_0ProviderUrgency,
}

fn default_exploit_maturity() -> CvssV4_0ExploitMaturity {
    CvssV4_0ExploitMaturity::default()
}

fn default_confidentiality_requirement() -> CvssV4_0ConfidentialityRequirement {
    CvssV4_0ConfidentialityRequirement::default()
}

fn default_availability_requirement() -> CvssV4_0ConfidentialityRequirement {
    CvssV4_0ConfidentialityRequirement::default()
}

fn default_modified_attack_vector() -> CvssV4_0ModifiedAttackVector {
    CvssV4_0ModifiedAttackVector::default()
}

fn default_modified_attack_complexity() -> CvssV4_0ModifiedAttackComplexity {
    CvssV4_0ModifiedAttackComplexity::default()
}

fn default_modified_privileges_required() -> CvssV4_0ModifiedPrivilegesRequired {
    CvssV4_0ModifiedPrivilegesRequired::default()
}

fn default_modified_user_interaction() -> CvssV4_0ModifiedUserInteraction {
    CvssV4_0ModifiedUserInteraction::default()
}

fn default_modified_vuln_confidentiality_impact() -> CvssV4_0ModifiedVulnConfidentialityImpact {
    CvssV4_0ModifiedVulnConfidentialityImpact::default()
}

fn default_modified_vuln_integrity_impact() -> CvssV4_0ModifiedVulnConfidentialityImpact {
    CvssV4_0ModifiedVulnConfidentialityImpact::default()
}

fn default_modified_vuln_availability_impact() -> CvssV4_0ModifiedVulnConfidentialityImpact {
    CvssV4_0ModifiedVulnConfidentialityImpact::default()
}

fn default_modified_sub_confidentiality_impact() -> CvssV4_0ModifiedSubConfidentialityImpact {
    CvssV4_0ModifiedSubConfidentialityImpact::default()
}

fn default_modified_sub_integrity_impact() -> CvssV4_0ModifiedSubIntegrityImpact {
    CvssV4_0ModifiedSubIntegrityImpact::default()
}

fn default_modified_sub_availability_impact() -> CvssV4_0ModifiedSubIntegrityImpact {
    CvssV4_0ModifiedSubIntegrityImpact::default()
}

fn default_safety() -> CvssV4_0Safety {
    CvssV4_0Safety::default()
}

fn default_automatable() -> CvssV4_0Automatable {
    CvssV4_0Automatable::default()
}

fn default_recovery() -> CvssV4_0Recovery {
    CvssV4_0Recovery::default()
}

fn default_value_density() -> CvssV4_0ValueDensity {
    CvssV4_0ValueDensity::default()
}

fn default_vulnerability_response_effort() -> CvssV4_0VulnerabilityResponseEffort {
    CvssV4_0VulnerabilityResponseEffort::default()
}

fn default_provider_urgency() -> CvssV4_0ProviderUrgency {
    CvssV4_0ProviderUrgency::default()
}
