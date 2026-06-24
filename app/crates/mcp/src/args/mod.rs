use rmcp::schemars;
use serde::Deserialize;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub(crate) struct CweArgs {
    /// CWE IDs to search for. Accepts numbers or strings such as 79, "CWE-79", or "CWE79".
    #[serde(default)]
    pub(crate) cwe_ids: Vec<CweArgValue>,
    /// Single CWE ID to search for. Kept for clients that do not send arrays.
    pub(crate) cwe_id: Option<CweArgValue>,
    /// Maximum number of results to return. Clamped to 1..=30; default is 10.
    pub(crate) limit: Option<u64>,
    /// Number of matching results to skip for pagination. Default is 0.
    pub(crate) offset: Option<u64>,
    /// Include rejected CVE records when true. Default returns only published CVEs.
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
    /// Affected vendor substring to search for. Can be combined with product.
    pub(crate) vendor: Option<String>,
    /// Affected vendor exact value to match. Can be combined with vendor/product filters.
    pub(crate) vendor_exact: Option<String>,
    /// Affected product substring to search for. Can be combined with vendor.
    pub(crate) product: Option<String>,
    /// Affected product exact value to match. Can be combined with vendor/product filters.
    pub(crate) product_exact: Option<String>,
    /// Maximum number of results to return. Clamped to 1..=30; default is 10.
    pub(crate) limit: Option<u64>,
    /// Number of matching results to skip for pagination. Default is 0.
    pub(crate) offset: Option<u64>,
    /// Include rejected CVE records when true. Default returns only published CVEs.
    pub(crate) include_rejected: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub(crate) struct TextArgs {
    /// Free text query. CVE prefixes, CWE IDs, dates, titles, descriptions, and affected text are supported.
    pub(crate) query: String,
    /// Maximum number of results to return. Clamped to 1..=30; default is 10.
    pub(crate) limit: Option<u64>,
    /// Number of matching results to skip for pagination. Default is 0.
    pub(crate) offset: Option<u64>,
    /// Include rejected CVE records when true. Default returns only published CVEs.
    pub(crate) include_rejected: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub(crate) struct GetCveArgs {
    /// Exact CVE ID, such as CVE-2026-12345.
    pub(crate) cve_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub(crate) struct CvssArgs {
    /// Minimum CVSS base score, inclusive.
    pub(crate) min_score: Option<f64>,
    /// Maximum CVSS base score, inclusive.
    pub(crate) max_score: Option<f64>,
    /// CVSS base severity string, such as LOW, MEDIUM, HIGH, or CRITICAL.
    pub(crate) severity: Option<String>,
    /// CVSS version string, such as 3.1 or 4.0.
    pub(crate) version: Option<String>,
    /// Maximum number of results to return. Clamped to 1..=30; default is 10.
    pub(crate) limit: Option<u64>,
    /// Number of matching results to skip for pagination. Default is 0.
    pub(crate) offset: Option<u64>,
    /// Include rejected CVE records when true. Default returns only published CVEs.
    pub(crate) include_rejected: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub(crate) struct ProductCvssArgs {
    /// Affected vendor substring to search for. Can be combined with product.
    pub(crate) vendor: Option<String>,
    /// Affected vendor exact value to match. Can be combined with vendor/product filters.
    pub(crate) vendor_exact: Option<String>,
    /// Affected product substring to search for. Can be combined with vendor.
    pub(crate) product: Option<String>,
    /// Affected product exact value to match. Can be combined with vendor/product filters.
    pub(crate) product_exact: Option<String>,
    /// Minimum CVSS base score, inclusive.
    pub(crate) min_score: Option<f64>,
    /// CVSS base severity string, such as LOW, MEDIUM, HIGH, or CRITICAL.
    pub(crate) severity: Option<String>,
    /// Maximum number of results to return. Clamped to 1..=30; default is 10.
    pub(crate) limit: Option<u64>,
    /// Number of matching results to skip for pagination. Default is 0.
    pub(crate) offset: Option<u64>,
    /// Include rejected CVE records when true. Default returns only published CVEs.
    pub(crate) include_rejected: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub(crate) struct DateArgs {
    /// Return CVEs whose CVE datePublished is greater than or equal to this ISO-8601 timestamp.
    pub(crate) published_since: Option<String>,
    /// Return CVEs whose CVE dateUpdated is greater than or equal to this ISO-8601 timestamp.
    pub(crate) updated_since: Option<String>,
    /// Maximum number of results to return. Clamped to 1..=30; default is 10.
    pub(crate) limit: Option<u64>,
    /// Number of matching results to skip for pagination. Default is 0.
    pub(crate) offset: Option<u64>,
    /// Include rejected CVE records when true. Default returns only published CVEs.
    pub(crate) include_rejected: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub(crate) struct UpdateDbArgs {
    /// Optional local CVE delta zip path to apply. When omitted, the updater downloads applicable CVE delta archives.
    pub(crate) zip: Option<String>,
    /// Optional cap on downloaded update chunks. Intended for testing or bounded maintenance runs.
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
