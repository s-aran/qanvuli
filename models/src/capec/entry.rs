use serde::Deserialize;

use super::{
    common::{
        ContentHistory, Members, Notes, References, RelatedAttackPatterns, RelatedWeaknesses,
        TaxonomyMappings,
    },
    enumeration::{Abstraction, Status, ViewType},
    structured_text::StructuredText,
};

#[derive(Clone, Debug, Deserialize)]
pub struct AttackPattern {
    #[serde(rename = "Description")]
    pub description: StructuredText,
    #[serde(rename = "Extended_Description")]
    pub extended_description: Option<StructuredText>,
    #[serde(rename = "Related_Attack_Patterns")]
    pub related_attack_patterns: Option<RelatedAttackPatterns>,
    #[serde(rename = "Related_Weaknesses")]
    pub related_weaknesses: Option<RelatedWeaknesses>,
    #[serde(rename = "References")]
    pub references: Option<References>,
    #[serde(rename = "@ID")]
    pub id: i64,
    #[serde(rename = "@Name")]
    pub name: String,
    #[serde(rename = "@Abstraction")]
    pub abstraction: Abstraction,
    #[serde(rename = "@Status")]
    pub status: Status,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Category {
    #[serde(rename = "Summary")]
    pub summary: StructuredText,
    #[serde(rename = "Relationships")]
    pub relationships: Option<Members>,
    #[serde(rename = "Taxonomy_Mappings")]
    pub taxonomy_mappings: Option<TaxonomyMappings>,
    #[serde(rename = "References")]
    pub references: Option<References>,
    #[serde(rename = "Notes")]
    pub notes: Option<Notes>,
    #[serde(rename = "Content_History")]
    pub content_history: Option<ContentHistory>,
    #[serde(rename = "@ID")]
    pub id: i64,
    #[serde(rename = "@Name")]
    pub name: String,
    #[serde(rename = "@Status")]
    pub status: Status,
}

#[derive(Clone, Debug, Deserialize)]
pub struct View {
    #[serde(rename = "Objective")]
    pub objective: StructuredText,
    #[serde(rename = "Members")]
    pub members: Option<Members>,
    #[serde(rename = "Filter")]
    pub filter: Option<String>,
    #[serde(rename = "References")]
    pub references: Option<References>,
    #[serde(rename = "Notes")]
    pub notes: Option<Notes>,
    #[serde(rename = "Content_History")]
    pub content_history: Option<ContentHistory>,
    #[serde(rename = "@ID")]
    pub id: i64,
    #[serde(rename = "@Name")]
    pub name: String,
    #[serde(rename = "@Type")]
    pub view_type: ViewType,
    #[serde(rename = "@Status")]
    pub status: Status,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ExternalReference {
    #[serde(rename = "Author", default)]
    pub authors: Vec<String>,
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
