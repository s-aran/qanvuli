use serde::Deserialize;

use super::{
    enumeration::RelationNature,
    structured_text::{StructuredText, XhtmlNode},
};

#[derive(Clone, Debug, Default, Deserialize)]
pub struct RelatedAttackPatterns {
    #[serde(rename = "Related_Attack_Pattern", default)]
    pub items: Vec<RelatedAttackPattern>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct RelatedAttackPattern {
    #[serde(rename = "@Nature")]
    pub nature: RelationNature,
    #[serde(rename = "@CAPEC_ID")]
    pub capec_id: i64,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct RelatedWeaknesses {
    #[serde(rename = "Related_Weakness", default)]
    pub items: Vec<RelatedWeakness>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct RelatedWeakness {
    #[serde(rename = "@CWE_ID")]
    pub cwe_id: i64,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Members {
    #[serde(rename = "Has_Member", default)]
    pub items: Vec<Member>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Member {
    #[serde(rename = "@CAPEC_ID")]
    pub capec_id: i64,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct References {
    #[serde(rename = "Reference", default)]
    pub items: Vec<Reference>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Reference {
    #[serde(rename = "@External_Reference_ID")]
    pub reference_id: String,
    #[serde(rename = "@Section")]
    pub section: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Notes {
    #[serde(rename = "Note", default)]
    pub items: Vec<Note>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Note {
    #[serde(rename = "$value", default)]
    pub content: Vec<XhtmlNode>,
    #[serde(rename = "@Type")]
    pub note_type: String,
}

impl Note {
    pub fn plain_text(&self) -> String {
        StructuredText {
            content: self.content.clone(),
        }
        .plain_text()
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct TaxonomyMappings {
    #[serde(rename = "Taxonomy_Mapping", default)]
    pub items: Vec<TaxonomyMapping>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct TaxonomyMapping {
    #[serde(rename = "@Taxonomy_Name")]
    pub taxonomy: String,
    #[serde(rename = "Entry_ID")]
    pub entry_id: Option<String>,
    #[serde(rename = "Entry_Name")]
    pub entry_name: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ContentHistory {
    #[serde(rename = "Submission")]
    pub submission: Option<Submission>,
    #[serde(rename = "Modification", default)]
    pub modifications: Vec<Modification>,
    #[serde(rename = "Previous_Entry_Name", default)]
    pub previous_names: Vec<PreviousName>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Submission {
    #[serde(rename = "Submission_Name")]
    pub name: String,
    #[serde(rename = "Submission_Organization")]
    pub organization: Option<String>,
    #[serde(rename = "Submission_Date")]
    pub date: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Modification {
    #[serde(rename = "Modification_Name")]
    pub name: String,
    #[serde(rename = "Modification_Organization")]
    pub organization: Option<String>,
    #[serde(rename = "Modification_Date")]
    pub date: String,
    #[serde(rename = "Modification_Comment")]
    pub comment: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PreviousName {
    #[serde(rename = "$text")]
    pub name: String,
    #[serde(rename = "@Date")]
    pub date: String,
}
