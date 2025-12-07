use serde::Deserialize;

use crate::cve::taxonomy_relation::TaxonomyRelation;

#[derive(Debug, Deserialize)]
pub struct TaxonomyMapping {
    pub taxonomy_name: String,
    pub taxonomy_version: Option<String>,
    pub taxonomy_relations: Vec<TaxonomyRelation>,
}
