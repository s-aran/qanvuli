use serde::{Deserialize, Deserializer};

use crate::cwe::enumeration::{
    ArchitectureClass, ArchitectureName, DetectionEffectiveness, DetectionMethod, Effectiveness,
    FunctionalArea, Importance, LanguageClass, LanguageName, Likelihood, MitigationStrategy,
    NoteType, OperatingSystemClass, OperatingSystemName, Ordinal, Ordinality, Phase, Prevalence,
    Reason, RelatedNature, Resource, Scope, Stakeholder, TaxonomyMappingFit, TaxonomyName,
    TechnicalImpact, TechnologyClass, TechnologyName, Usage,
};
use crate::cwe::structured_text::{StructuredCode, StructuredText, XhtmlNode};

#[derive(Debug, Deserialize)]
pub(crate) struct TextValue<T> {
    #[serde(rename = "$text")]
    pub value: T,
}

pub(crate) fn deserialize_text<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    TextValue::<T>::deserialize(deserializer).map(|v| v.value)
}

pub(crate) fn deserialize_option_text<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<TextValue<T>>::deserialize(deserializer).map(|v| v.map(|v| v.value))
}

pub(crate) fn deserialize_vec_text<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Vec::<TextValue<T>>::deserialize(deserializer).map(|values| {
        values
            .into_iter()
            .map(|value| value.value)
            .collect::<Vec<_>>()
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AffectedResources {
    #[serde(
        rename = "Affected_Resource",
        default,
        deserialize_with = "deserialize_vec_text"
    )]
    pub affected_resource: Vec<Resource>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlternateTerms {
    #[serde(rename = "Alternate_Term")]
    pub alternate_term: Vec<AlternateTerm>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlternateTerm {
    #[serde(rename = "Term")]
    pub term: String,
    #[serde(rename = "Description")]
    pub description: Option<StructuredText>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicablePlatforms {
    #[serde(rename = "Language", default)]
    pub language: Vec<Language>,
    #[serde(rename = "Operating_System", default)]
    pub operating_system: Vec<OperatingSystem>,
    #[serde(rename = "Architecture", default)]
    pub architecture: Vec<Architecture>,
    #[serde(rename = "Technology", default)]
    pub technology: Vec<Technology>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Language {
    #[serde(rename = "@Name")]
    pub name: Option<LanguageName>,
    #[serde(rename = "@Class")]
    pub class: Option<LanguageClass>,
    #[serde(rename = "@Prevalence")]
    pub prevalence: Prevalence,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatingSystem {
    #[serde(rename = "@Name")]
    pub name: Option<OperatingSystemName>,
    #[serde(rename = "@Version")]
    pub version: Option<String>,
    #[serde(rename = "@CPE_ID")]
    pub cpe_id: Option<String>,
    #[serde(rename = "@Class")]
    pub class: Option<OperatingSystemClass>,
    #[serde(rename = "@Prevalence")]
    pub prevalence: Prevalence,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Architecture {
    #[serde(rename = "@Name")]
    pub name: Option<ArchitectureName>,
    #[serde(rename = "@Class")]
    pub class: Option<ArchitectureClass>,
    #[serde(rename = "@Prevalence")]
    pub prevalence: Prevalence,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Technology {
    #[serde(rename = "@Name")]
    pub name: Option<TechnologyName>,
    #[serde(rename = "@Class")]
    pub class: Option<TechnologyClass>,
    #[serde(rename = "@Prevalence")]
    pub prevalence: Prevalence,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Audience {
    #[serde(rename = "Stakeholder")]
    pub stakeholder: Vec<AudienceStakeholder>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AudienceStakeholder {
    #[serde(rename = "Type", deserialize_with = "deserialize_text")]
    pub stakeholder_type: Stakeholder,
    #[serde(rename = "Description")]
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackgroundDetails {
    #[serde(rename = "Background_Detail")]
    pub background_detail: Vec<StructuredText>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommonConsequences {
    #[serde(rename = "Consequence")]
    pub consequence: Vec<Consequence>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Consequence {
    #[serde(rename = "Scope", default, deserialize_with = "deserialize_vec_text")]
    pub scope: Vec<Scope>,
    #[serde(rename = "Impact", default, deserialize_with = "deserialize_vec_text")]
    pub impact: Vec<TechnicalImpact>,
    #[serde(
        rename = "Likelihood",
        default,
        deserialize_with = "deserialize_option_text"
    )]
    pub likelihood: Option<Likelihood>,
    #[serde(rename = "Note")]
    pub note: Option<StructuredText>,
    #[serde(rename = "@Consequence_ID")]
    pub consequence_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentHistory {
    #[serde(rename = "Submission")]
    pub submission: Submission,
    #[serde(rename = "Modification", default)]
    pub modification: Vec<Modification>,
    #[serde(rename = "Contribution", default)]
    pub contribution: Vec<Contribution>,
    #[serde(rename = "Previous_Entry_Name", default)]
    pub previous_entry_name: Vec<PreviousEntryName>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Submission {
    #[serde(rename = "Submission_Name")]
    pub submission_name: Option<String>,
    #[serde(rename = "Submission_Organization")]
    pub submission_organization: Option<String>,
    #[serde(rename = "Submission_Date")]
    pub submission_date: String,
    #[serde(rename = "Submission_Version")]
    pub submission_version: String,
    #[serde(rename = "Submission_ReleaseDate")]
    pub submission_release_date: String,
    #[serde(rename = "Submission_Comment")]
    pub submission_comment: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Modification {
    #[serde(rename = "Modification_Name")]
    pub modification_name: Option<String>,
    #[serde(rename = "Modification_Organization")]
    pub modification_organization: Option<String>,
    #[serde(rename = "Modification_Date")]
    pub modification_date: String,
    #[serde(rename = "Modification_Version")]
    pub modification_version: Option<String>,
    #[serde(rename = "Modification_ReleaseDate")]
    pub modification_release_date: Option<String>,
    #[serde(rename = "Modification_Importance")]
    pub modification_importance: Option<Importance>,
    #[serde(rename = "Modification_Comment")]
    pub modification_comment: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Contribution {
    #[serde(rename = "Contribution_Name")]
    pub contribution_name: Option<String>,
    #[serde(rename = "Contribution_Organization")]
    pub contribution_organization: Option<String>,
    #[serde(rename = "Contribution_Date")]
    pub contribution_date: String,
    #[serde(rename = "Contribution_Version")]
    pub contribution_version: Option<String>,
    #[serde(rename = "Contribution_ReleaseDate")]
    pub contribution_release_date: Option<String>,
    #[serde(rename = "Contribution_Comment")]
    pub contribution_comment: Option<String>,
    #[serde(rename = "@Type")]
    pub contribution_type: ContributionType,
}

#[derive(Debug, Deserialize)]
pub enum ContributionType {
    Content,
    Feedback,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreviousEntryName {
    #[serde(rename = "$text")]
    pub name: String,
    #[serde(rename = "@Date")]
    pub date: String,
    #[serde(rename = "@Version")]
    pub version: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DemonstrativeExamples {
    #[serde(rename = "Demonstrative_Example")]
    pub demonstrative_example: Vec<DemonstrativeExample>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DemonstrativeExample {
    #[serde(rename = "Title_Text")]
    pub title_text: Option<String>,
    #[serde(rename = "Intro_Text")]
    pub intro_text: StructuredText,
    #[serde(rename = "$value", default)]
    pub content: Vec<DemonstrativeExampleContent>,
    #[serde(rename = "References")]
    pub references: Option<References>,
    #[serde(rename = "@Demonstrative_Example_ID")]
    pub demonstrative_example_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub enum DemonstrativeExampleContent {
    #[serde(rename = "Body_Text")]
    BodyText(StructuredText),
    #[serde(rename = "Example_Code")]
    ExampleCode(StructuredCode),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetectionMethods {
    #[serde(rename = "Detection_Method")]
    pub detection_method: Vec<DetectionMethodEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetectionMethodEntry {
    #[serde(rename = "Method", deserialize_with = "deserialize_text")]
    pub method: DetectionMethod,
    #[serde(rename = "Description")]
    pub description: StructuredText,
    #[serde(
        rename = "Effectiveness",
        default,
        deserialize_with = "deserialize_option_text"
    )]
    pub effectiveness: Option<DetectionEffectiveness>,
    #[serde(rename = "Effectiveness_Notes")]
    pub effectiveness_notes: Option<StructuredText>,
    #[serde(rename = "@Detection_Method_ID")]
    pub detection_method_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExploitationFactors {
    #[serde(rename = "Exploitation_Factor")]
    pub exploitation_factor: Vec<StructuredText>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FunctionalAreas {
    #[serde(
        rename = "Functional_Area",
        default,
        deserialize_with = "deserialize_vec_text"
    )]
    pub functional_area: Vec<FunctionalArea>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MappingNotes {
    #[serde(rename = "Usage", deserialize_with = "deserialize_text")]
    pub usage: Usage,
    #[serde(rename = "Rationale")]
    pub rationale: StructuredText,
    #[serde(rename = "Comments")]
    pub comments: StructuredText,
    #[serde(rename = "Reasons")]
    pub reasons: Reasons,
    #[serde(rename = "Suggestions")]
    pub suggestions: Option<Suggestions>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Member {
    #[serde(rename = "@CWE_ID")]
    pub cwe_id: i64,
    #[serde(rename = "@View_ID")]
    pub view_id: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModesOfIntroduction {
    #[serde(rename = "Introduction")]
    pub introduction: Vec<Introduction>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Introduction {
    #[serde(rename = "Phase", deserialize_with = "deserialize_text")]
    pub phase: Phase,
    #[serde(rename = "Note")]
    pub note: Option<StructuredText>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Notes {
    #[serde(rename = "Note")]
    pub note: Vec<Note>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Note {
    #[serde(rename = "$value", default)]
    pub content: Vec<XhtmlNode>,
    #[serde(rename = "@Type")]
    pub note_type: NoteType,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedExamples {
    #[serde(rename = "Observed_Example")]
    pub observed_example: Vec<ObservedExample>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedExample {
    #[serde(rename = "Reference")]
    pub reference: String,
    #[serde(rename = "Description")]
    pub description: StructuredText,
    #[serde(rename = "Link")]
    pub link: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PotentialMitigations {
    #[serde(rename = "Mitigation")]
    pub mitigation: Vec<Mitigation>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mitigation {
    #[serde(rename = "Phase", default, deserialize_with = "deserialize_vec_text")]
    pub phase: Vec<Phase>,
    #[serde(
        rename = "Strategy",
        default,
        deserialize_with = "deserialize_option_text"
    )]
    pub strategy: Option<MitigationStrategy>,
    #[serde(rename = "Description")]
    pub description: StructuredText,
    #[serde(
        rename = "Effectiveness",
        default,
        deserialize_with = "deserialize_option_text"
    )]
    pub effectiveness: Option<Effectiveness>,
    #[serde(rename = "Effectiveness_Notes")]
    pub effectiveness_notes: Option<StructuredText>,
    #[serde(rename = "@Mitigation_ID")]
    pub mitigation_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reasons {
    #[serde(rename = "Reason")]
    pub reason: Vec<ReasonEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReasonEntry {
    #[serde(rename = "@Type")]
    pub reason_type: Reason,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct References {
    #[serde(rename = "Reference")]
    pub reference: Vec<Reference>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reference {
    #[serde(rename = "@External_Reference_ID")]
    pub external_reference_id: String,
    #[serde(rename = "@Section")]
    pub section: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelatedAttackPatterns {
    #[serde(rename = "Related_Attack_Pattern")]
    pub related_attack_pattern: Vec<RelatedAttackPattern>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelatedAttackPattern {
    #[serde(rename = "@CAPEC_ID")]
    pub capec_id: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelatedWeaknesses {
    #[serde(rename = "Related_Weakness")]
    pub related_weakness: Vec<RelatedWeakness>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelatedWeakness {
    #[serde(rename = "@Nature")]
    pub nature: RelatedNature,
    #[serde(rename = "@CWE_ID")]
    pub cwe_id: i64,
    #[serde(rename = "@View_ID")]
    pub view_id: i64,
    #[serde(rename = "@Chain_ID")]
    pub chain_id: Option<i64>,
    #[serde(rename = "@Ordinal")]
    pub ordinal: Option<Ordinal>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Relationships {
    #[serde(rename = "Member_Of", default)]
    pub member_of: Vec<Member>,
    #[serde(rename = "Has_Member", default)]
    pub has_member: Vec<Member>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Suggestions {
    #[serde(rename = "Suggestion")]
    pub suggestion: Vec<Suggestion>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Suggestion {
    #[serde(rename = "@CWE_ID")]
    pub cwe_id: i64,
    #[serde(rename = "@Comment")]
    pub comment: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaxonomyMappings {
    #[serde(rename = "Taxonomy_Mapping")]
    pub taxonomy_mapping: Vec<TaxonomyMapping>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaxonomyMapping {
    #[serde(rename = "Entry_ID")]
    pub entry_id: Option<String>,
    #[serde(rename = "Entry_Name")]
    pub entry_name: Option<String>,
    #[serde(
        rename = "Mapping_Fit",
        default,
        deserialize_with = "deserialize_option_text"
    )]
    pub mapping_fit: Option<TaxonomyMappingFit>,
    #[serde(rename = "@Taxonomy_Name")]
    pub taxonomy_name: TaxonomyName,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WeaknessOrdinalities {
    #[serde(rename = "Weakness_Ordinality")]
    pub weakness_ordinality: Vec<WeaknessOrdinality>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WeaknessOrdinality {
    #[serde(rename = "Ordinality", deserialize_with = "deserialize_text")]
    pub ordinality: Ordinality,
    #[serde(rename = "Description")]
    pub description: Option<String>,
}
