use std::collections::BTreeMap;

use chrono::{DateTime, FixedOffset};
use octocrab::models::repos::Tag;
use serde::Deserialize;
use simd_json::OwnedValue;

use crate::cve::{
    affected::Affected, cna_description::CnaDescription, credit::Credit, impact::Impact,
    metric::Metric, problem_type_description::ProblemTypeDescription,
    provider_metadata::ProviderMetadata, reference::Reference, taxonomy_mapping::TaxonomyMapping,
    timeline::Timeline,
};

#[derive(Debug, Deserialize)]
pub struct Atp {
    pub provider_metadata: ProviderMetadata,
    pub date_public: Option<DateTime<FixedOffset>>,
    pub title: Option<String>,
    pub descriptions: Vec<CnaDescription>,
    pub affected: Vec<Affected>,
    pub problem_types: Vec<ProblemTypeDescription>,
    pub references: Vec<Reference>,
    pub impacts: Vec<Impact>,
    pub metrics: Vec<Metric>,
    pub configurations: Vec<CnaDescription>,
    pub workarounds: Vec<CnaDescription>,
    pub solutions: Vec<CnaDescription>,
    pub exploits: Vec<CnaDescription>,
    pub timeline: Vec<Timeline>,
    pub credits: Vec<Credit>,
    pub source: Option<BTreeMap<String, OwnedValue>>,
    pub tags: Vec<Tag>,
    pub taxonomy_mappings: Vec<TaxonomyMapping>,
}
