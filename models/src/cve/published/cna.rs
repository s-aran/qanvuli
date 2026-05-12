use std::collections::BTreeMap;

use chrono::{DateTime, FixedOffset};
use serde::Deserialize;
use simd_json::OwnedValue;

use crate::cve::published::{
    affected::Affected, cna_description::CnaDescription, credit::Credit, impact::Impact,
    metric::Metric, problem_type_description::ProblemTypeDescription,
    provider_metadata::ProviderMetadata, reference::Reference, tag::Tag,
    taxonomy_mapping::TaxonomyMapping, timeline::Timeline,
};
use qanvuli_utils::datetime_deserialize::deserialize_cve_timestamp;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Cna {
    pub provider_metadata: ProviderMetadata,
    pub date_assigned: Option<String>,
    pub date_updated: Option<DateTime<FixedOffset>>,
    #[serde(default, deserialize_with = "deserialize_cve_timestamp")]
    pub date_public: Option<DateTime<FixedOffset>>,
    pub title: Option<String>,
    pub descriptions: Vec<CnaDescription>,
    pub affected: Vec<Affected>,
    pub problem_type: Option<Vec<ProblemTypeDescription>>,
    pub references: Vec<Reference>,
    pub impacts: Option<Vec<Impact>>,
    pub metrics: Option<Vec<Metric>>,
    pub configurations: Option<Vec<CnaDescription>>,
    pub workarounds: Option<Vec<CnaDescription>>,
    pub solutions: Option<Vec<CnaDescription>>,
    pub exploits: Option<Vec<CnaDescription>>,
    pub timeline: Option<Vec<Timeline>>,
    pub credits: Option<Vec<Credit>>,
    #[serde(flatten)]
    pub source: Option<BTreeMap<String, OwnedValue>>,
    pub tags: Option<Vec<Tag>>,
    pub taxonomy_mappings: Option<Vec<TaxonomyMapping>>,
}
