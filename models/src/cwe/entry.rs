use serde::Deserialize;

use crate::cwe::common::{
    AffectedResources, AlternateTerms, ApplicablePlatforms, Audience, BackgroundDetails,
    CommonConsequences, ContentHistory, DemonstrativeExamples, DetectionMethods,
    ExploitationFactors, FunctionalAreas, MappingNotes, ModesOfIntroduction, Notes,
    ObservedExamples, PotentialMitigations, References, RelatedAttackPatterns, RelatedWeaknesses,
    Relationships, TaxonomyMappings, WeaknessOrdinalities, deserialize_option_text,
};
use crate::cwe::enumeration::{Abstraction, Likelihood, Status, Structure, ViewType};
use crate::cwe::structured_text::StructuredText;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Weakness {
    #[serde(rename = "Description")]
    pub description: String,
    #[serde(rename = "Extended_Description")]
    pub extended_description: Option<StructuredText>,
    #[serde(rename = "Related_Weaknesses")]
    pub related_weaknesses: Option<RelatedWeaknesses>,
    #[serde(rename = "Weakness_Ordinalities")]
    pub weakness_ordinalities: Option<WeaknessOrdinalities>,
    #[serde(rename = "Applicable_Platforms")]
    pub applicable_platforms: Option<ApplicablePlatforms>,
    #[serde(rename = "Background_Details")]
    pub background_details: Option<BackgroundDetails>,
    #[serde(rename = "Alternate_Terms")]
    pub alternate_terms: Option<AlternateTerms>,
    #[serde(rename = "Modes_Of_Introduction")]
    pub modes_of_introduction: Option<ModesOfIntroduction>,
    #[serde(rename = "Exploitation_Factors")]
    pub exploitation_factors: Option<ExploitationFactors>,
    #[serde(
        rename = "Likelihood_Of_Exploit",
        default,
        deserialize_with = "deserialize_option_text"
    )]
    pub likelihood_of_exploit: Option<Likelihood>,
    #[serde(rename = "Common_Consequences")]
    pub common_consequences: Option<CommonConsequences>,
    #[serde(rename = "Detection_Methods")]
    pub detection_methods: Option<DetectionMethods>,
    #[serde(rename = "Potential_Mitigations")]
    pub potential_mitigations: Option<PotentialMitigations>,
    #[serde(rename = "Demonstrative_Examples")]
    pub demonstrative_examples: Option<DemonstrativeExamples>,
    #[serde(rename = "Observed_Examples")]
    pub observed_examples: Option<ObservedExamples>,
    #[serde(rename = "Functional_Areas")]
    pub functional_areas: Option<FunctionalAreas>,
    #[serde(rename = "Affected_Resources")]
    pub affected_resources: Option<AffectedResources>,
    #[serde(rename = "Taxonomy_Mappings")]
    pub taxonomy_mappings: Option<TaxonomyMappings>,
    #[serde(rename = "Related_Attack_Patterns")]
    pub related_attack_patterns: Option<RelatedAttackPatterns>,
    #[serde(rename = "References")]
    pub references: Option<References>,
    #[serde(rename = "Mapping_Notes")]
    pub mapping_notes: MappingNotes,
    #[serde(rename = "Notes")]
    pub notes: Option<Notes>,
    #[serde(rename = "Content_History")]
    pub content_history: ContentHistory,
    #[serde(rename = "@ID")]
    pub id: i64,
    #[serde(rename = "@Name")]
    pub name: String,
    #[serde(rename = "@Abstraction")]
    pub abstraction: Abstraction,
    #[serde(rename = "@Structure")]
    pub structure: Structure,
    #[serde(rename = "@Status")]
    pub status: Status,
    #[serde(rename = "@Diagram")]
    pub diagram: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Category {
    #[serde(rename = "Summary")]
    pub summary: StructuredText,
    #[serde(rename = "Relationships")]
    pub relationships: Option<Relationships>,
    #[serde(rename = "Taxonomy_Mappings")]
    pub taxonomy_mappings: Option<TaxonomyMappings>,
    #[serde(rename = "References")]
    pub references: Option<References>,
    #[serde(rename = "Mapping_Notes")]
    pub mapping_notes: MappingNotes,
    #[serde(rename = "Notes")]
    pub notes: Option<Notes>,
    #[serde(rename = "Content_History")]
    pub content_history: ContentHistory,
    #[serde(rename = "@ID")]
    pub id: i64,
    #[serde(rename = "@Name")]
    pub name: String,
    #[serde(rename = "@Status")]
    pub status: Status,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct View {
    #[serde(rename = "Objective")]
    pub objective: StructuredText,
    #[serde(rename = "Audience")]
    pub audience: Option<Audience>,
    #[serde(rename = "Members")]
    pub members: Option<Relationships>,
    #[serde(rename = "Filter")]
    pub filter: Option<String>,
    #[serde(rename = "References")]
    pub references: Option<References>,
    #[serde(rename = "Mapping_Notes")]
    pub mapping_notes: MappingNotes,
    #[serde(rename = "Notes")]
    pub notes: Option<Notes>,
    #[serde(rename = "Content_History")]
    pub content_history: ContentHistory,
    #[serde(rename = "@ID")]
    pub id: i64,
    #[serde(rename = "@Name")]
    pub name: String,
    #[serde(rename = "@Type")]
    pub view_type: ViewType,
    #[serde(rename = "@Status")]
    pub status: Status,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalReference {
    #[serde(rename = "Author", default)]
    pub author: Vec<String>,
    #[serde(rename = "Title")]
    pub title: String,
    #[serde(rename = "Edition")]
    pub edition: Option<String>,
    #[serde(rename = "Publication")]
    pub publication: Option<String>,
    #[serde(rename = "Publication_Year")]
    pub publication_year: Option<String>,
    #[serde(rename = "Publication_Month")]
    pub publication_month: Option<String>,
    #[serde(rename = "Publication_Day")]
    pub publication_day: Option<String>,
    #[serde(rename = "Publisher")]
    pub publisher: Option<String>,
    #[serde(rename = "URL")]
    pub url: Option<String>,
    #[serde(rename = "URL_Date")]
    pub url_date: Option<String>,
    #[serde(rename = "@Reference_ID")]
    pub reference_id: String,
}
