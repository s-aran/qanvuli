use std::collections::BTreeMap;

use chrono::{DateTime, FixedOffset};
use serde::Deserialize;
use simd_json::OwnedValue;

use crate::cve::{
    cna_description::CnaDescription, credit::Credit, impact::Impact, metric::Metric,
    provider_metadata::ProviderMetadata, reference::Reference, tag::Tag,
    taxonomy_mapping::TaxonomyMapping, timeline::Timeline,
};

#[derive(Debug, Deserialize)]
pub struct Cna {
    pub provider_metadata: ProviderMetadata,
    pub date_assigned: Option<String>,
    pub date_public: Option<DateTime<FixedOffset>>,
    pub title: Option<String>,
    pub descriptions: Vec<CnaDescription>,
    pub references: Vec<Reference>,
    pub impacts: Vec<Impact>,
    pub metrics: Vec<Metric>,
    pub configurations: Vec<CnaDescription>,
    pub workarounds: Vec<CnaDescription>,
    pub solutions: Vec<CnaDescription>,
    pub exploits: Vec<CnaDescription>,
    pub timeline: Option<Timeline>,
    pub credits: Vec<Credit>,
    #[serde(flatten)]
    pub source: Option<BTreeMap<String, OwnedValue>>,
    pub tags: Vec<Tag>,
    pub taxonomy_mappings: Vec<TaxonomyMapping>,
}
