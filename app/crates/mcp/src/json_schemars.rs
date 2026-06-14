use rmcp::schemars;
use serde::Deserialize;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub(crate) struct CweArgs {
    #[serde(default)]
    pub(crate) cwe_ids: Vec<CweArgValue>,
    pub(crate) cwe_id: Option<CweArgValue>,
    pub(crate) limit: Option<u64>,
    pub(crate) offset: Option<u64>,
    pub(crate) include_rejected: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub(crate) enum CweArgValue {
    Number(i32),
    String(String),
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub(crate) struct ProductArgs {
    pub(crate) vendor: Option<String>,
    pub(crate) product: Option<String>,
    pub(crate) limit: Option<u64>,
    pub(crate) offset: Option<u64>,
    pub(crate) include_rejected: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub(crate) struct TextArgs {
    pub(crate) query: String,
    pub(crate) limit: Option<u64>,
    pub(crate) offset: Option<u64>,
    pub(crate) include_rejected: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub(crate) struct GetCveArgs {
    pub(crate) cve_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub(crate) struct CvssArgs {
    pub(crate) min_score: Option<f64>,
    pub(crate) max_score: Option<f64>,
    pub(crate) severity: Option<String>,
    pub(crate) version: Option<String>,
    pub(crate) limit: Option<u64>,
    pub(crate) offset: Option<u64>,
    pub(crate) include_rejected: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub(crate) struct ProductCvssArgs {
    pub(crate) vendor: Option<String>,
    pub(crate) product: Option<String>,
    pub(crate) min_score: Option<f64>,
    pub(crate) severity: Option<String>,
    pub(crate) limit: Option<u64>,
    pub(crate) offset: Option<u64>,
    pub(crate) include_rejected: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub(crate) struct DateArgs {
    pub(crate) published_since: Option<String>,
    pub(crate) updated_since: Option<String>,
    pub(crate) limit: Option<u64>,
    pub(crate) offset: Option<u64>,
    pub(crate) include_rejected: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub(crate) struct UpdateDbArgs {
    pub(crate) zip: Option<String>,
    pub(crate) max_chunks: Option<usize>,
}

impl CweArgs {
    pub(crate) fn search_values(self) -> Vec<String> {
        let mut values = self
            .cwe_ids
            .into_iter()
            .map(CweArgValue::into_search_value)
            .collect::<Vec<_>>();
        if let Some(cwe_id) = self.cwe_id {
            values.push(cwe_id.into_search_value());
        }
        values
    }
}

impl CweArgValue {
    fn into_search_value(self) -> String {
        match self {
            Self::Number(value) => value.to_string(),
            Self::String(value) => value,
        }
    }
}
