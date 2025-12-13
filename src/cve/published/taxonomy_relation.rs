use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaxonomyRelation {
    pub taxonomy_id: String,
    pub relationship_name: String,
    pub relationship_value: String,
}
