use serde::Deserialize;

use crate::cve::published::taxonomy_relation::TaxonomyRelation;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TaxonomyMapping {
    pub taxonomy_name: String,
    pub taxonomy_version: Option<String>,
    pub taxonomy_relations: Vec<TaxonomyRelation>,
}
