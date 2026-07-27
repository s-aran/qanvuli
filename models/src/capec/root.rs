use serde::Deserialize;

use super::entry::{AttackPattern, Category, ExternalReference, View};

#[derive(Clone, Debug, Deserialize)]
#[serde(rename = "Attack_Pattern_Catalog")]
pub struct AttackPatternCatalog {
    #[serde(rename = "Attack_Patterns")]
    pub attack_patterns: Option<AttackPatterns>,
    #[serde(rename = "Categories")]
    pub categories: Option<Categories>,
    #[serde(rename = "Views")]
    pub views: Option<Views>,
    #[serde(rename = "External_References")]
    pub external_references: Option<ExternalReferences>,
    #[serde(rename = "@Name")]
    pub name: String,
    #[serde(rename = "@Version")]
    pub version: String,
    #[serde(rename = "@Date")]
    pub date: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct AttackPatterns {
    #[serde(rename = "Attack_Pattern", default)]
    pub items: Vec<AttackPattern>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Categories {
    #[serde(rename = "Category", default)]
    pub items: Vec<Category>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct Views {
    #[serde(rename = "View", default)]
    pub items: Vec<View>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct ExternalReferences {
    #[serde(rename = "External_Reference", default)]
    pub items: Vec<ExternalReference>,
}
