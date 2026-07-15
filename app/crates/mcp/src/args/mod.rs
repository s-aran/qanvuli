use rmcp::schemars;
use serde::{Deserialize, Serialize};

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
    /// Affected vendor substring to search for.
    pub(crate) vendor: Option<String>,
    /// Affected vendor exact value to match. Use this instead of vendor when exact matching is required.
    pub(crate) vendor_exact: Option<String>,
    /// Affected product substring to search for.
    pub(crate) product: Option<String>,
    /// Affected product exact value to match. Use this instead of product when exact matching is required.
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
pub(crate) struct ReferenceSearchArgs {
    /// Text to match against CVE reference URLs, names, and tags.
    pub(crate) query: String,
    /// Maximum number of results to return. Clamped to 1..=30; default is 10.
    pub(crate) limit: Option<u64>,
    /// Number of matching results to skip for pagination. Default is 0.
    pub(crate) offset: Option<u64>,
    /// Include rejected CVE records when true. Default returns only published CVEs.
    pub(crate) include_rejected: Option<bool>,
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
    /// Affected vendor substring to search for.
    pub(crate) vendor: Option<String>,
    /// Affected vendor exact value to match. Use this instead of vendor when exact matching is required.
    pub(crate) vendor_exact: Option<String>,
    /// Affected product substring to search for.
    pub(crate) product: Option<String>,
    /// Affected product exact value to match. Use this instead of product when exact matching is required.
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
pub(crate) struct DateRangeArgs {
    /// Return CVEs whose CVE datePublished is greater than or equal to this ISO-8601 timestamp.
    pub(crate) published_from: Option<String>,
    /// Return CVEs whose CVE datePublished is less than or equal to this ISO-8601 timestamp.
    pub(crate) published_to: Option<String>,
    /// Return CVEs whose CVE dateUpdated is greater than or equal to this ISO-8601 timestamp.
    pub(crate) updated_from: Option<String>,
    /// Return CVEs whose CVE dateUpdated is less than or equal to this ISO-8601 timestamp.
    pub(crate) updated_to: Option<String>,
    /// Maximum number of results to return. Clamped to 1..=30; default is 10.
    pub(crate) limit: Option<u64>,
    /// Number of matching results to skip for pagination. Default is 0.
    pub(crate) offset: Option<u64>,
    /// Include rejected CVE records when true. Default returns only published CVEs.
    pub(crate) include_rejected: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub(crate) struct IdPrefixArgs {
    /// CVE ID prefix such as CVE-2026- or CVE-2026-12.
    pub(crate) prefix: String,
    /// Maximum number of results to return. Clamped to 1..=30; default is 10.
    pub(crate) limit: Option<u64>,
    /// Number of matching results to skip for pagination. Default is 0.
    pub(crate) offset: Option<u64>,
    /// Include rejected CVE records when true. Default returns only published CVEs.
    pub(crate) include_rejected: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub(crate) struct ProductVersionArgs {
    /// Affected vendor substring to search for. Can be combined with product.
    pub(crate) vendor: Option<String>,
    /// Affected product substring to search for. Can be combined with vendor.
    pub(crate) product: Option<String>,
    /// Version string to look for in affected version entries. This returns candidate CVEs, not a definitive vulnerable/not-vulnerable verdict.
    pub(crate) version: Option<String>,
    /// Maximum number of results to return. Clamped to 1..=30; default is 10.
    pub(crate) limit: Option<u64>,
    /// Number of matching results to skip for pagination. Default is 0.
    pub(crate) offset: Option<u64>,
    /// Include rejected CVE records when true. Default returns only published CVEs.
    pub(crate) include_rejected: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub(crate) struct CweCatalogArgs {
    /// CWE ID or text query. Empty query returns the first entries in tree order.
    pub(crate) query: Option<String>,
    /// Optional CWE statuses to include, such as Draft, Stable, Deprecated, or Obsolete.
    #[serde(default)]
    pub(crate) statuses: Vec<String>,
    /// Maximum number of CWE entries to return. Clamped to 1..=30; default is 10.
    pub(crate) limit: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub(crate) struct GetCweArgs {
    /// CWE ID. Accepts a number or a string such as CWE-79.
    pub(crate) cwe_id: CweArgValue,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub(crate) struct ExplainMatchArgs {
    /// Exact CVE ID to explain.
    pub(crate) cve_id: String,
    /// Optional query that led to this match.
    pub(crate) query: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub(crate) struct RecentUpdatesArgs {
    /// Return CVEs updated on or after this ISO-8601 timestamp.
    pub(crate) since: Option<String>,
    /// Maximum number of results to return. Clamped to 1..=30; default is 10.
    pub(crate) limit: Option<u64>,
    /// Number of matching results to skip for pagination. Default is 0.
    pub(crate) offset: Option<u64>,
    /// Include rejected CVE records when true. Default returns only published CVEs.
    pub(crate) include_rejected: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub(crate) struct KnownExploitedArgs {
    /// Optional CVE ID. When omitted, returns locally synced KEV entries with pagination.
    pub(crate) cve_id: Option<String>,
    /// Maximum number of KEV entries to return when cve_id is omitted. Clamped to 1..=30; default is 10.
    pub(crate) limit: Option<u64>,
    /// Number of KEV entries to skip when cve_id is omitted. Default is 0.
    pub(crate) offset: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub(crate) struct CveRiskLookupArgs {
    /// CVE IDs to check for KEV, EPSS, and max CVSS. Intended for batch triage.
    pub(crate) cve_ids: Vec<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub(crate) struct EpssArgs {
    /// Minimum EPSS score, inclusive. Omit to return top EPSS records.
    pub(crate) min_score: Option<f64>,
    /// Minimum EPSS percentile, inclusive.
    pub(crate) min_percentile: Option<f64>,
    /// Maximum number of results to return. Clamped to 1..=30; default is 10.
    pub(crate) limit: Option<u64>,
    /// Number of matching results to skip for pagination. Default is 0.
    pub(crate) offset: Option<u64>,
    /// Include rejected CVE records when true. Default returns only published CVEs.
    pub(crate) include_rejected: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub(crate) struct ResolveIdentifierArgs {
    /// CVE, OSV, GHSA, RUSTSEC, PYSEC, GO, or other vulnerability identifier.
    pub(crate) id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub(crate) struct GetEnrichedCveArgs {
    /// Exact CVE ID, such as CVE-2026-12345.
    pub(crate) cve_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub(crate) struct GetEnrichedOsvArgs {
    /// Exact OSV advisory ID, such as GHSA-abcd-efgh-ijkl or RUSTSEC-2026-0001.
    pub(crate) osv_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub(crate) struct QueryPackageEnrichedArgs {
    /// OSV ecosystem name, such as crates.io.
    pub(crate) ecosystem: String,
    /// Package name in the ecosystem.
    pub(crate) package: String,
    /// Installed package version.
    pub(crate) version: String,
    /// Optional package URL to disambiguate package identity.
    pub(crate) purl: Option<String>,
    /// Return only confirmed affected findings (default), or all evaluated findings.
    pub(crate) status: Option<String>,
    /// Maximum findings to return. Clamped to 1..=30; default is 10.
    pub(crate) limit: Option<u64>,
    /// Number of matching findings to skip. Default is 0.
    pub(crate) offset: Option<u64>,
    /// Include verbose OSV/alias/KEV/EPSS match evidence. Defaults to false.
    pub(crate) include_evidence: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub(crate) struct PackageQueryArgs {
    pub(crate) ecosystem: String,
    pub(crate) package: String,
    pub(crate) version: String,
    pub(crate) purl: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub(crate) struct QueryPackagesEnrichedArgs {
    /// Up to 200 package/version tuples.
    pub(crate) packages: Vec<PackageQueryArgs>,
    /// Return only confirmed affected findings (default), or all evaluated findings.
    pub(crate) status: Option<String>,
    /// Include verbose OSV/alias/KEV/EPSS match evidence. Defaults to false.
    pub(crate) include_evidence: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub(crate) struct UpdateDbArgs {
    /// Optional local CVE delta zip path to apply. When omitted, the updater downloads applicable CVE delta archives.
    pub(crate) zip: Option<String>,
    /// Optional cap on downloaded update chunks. Intended for testing or bounded maintenance runs.
    pub(crate) max_chunks: Option<usize>,
    /// Expand local OSV sync coverage to all OSV records.
    pub(crate) osv_all: Option<bool>,
    /// Additional OSV JSON filename/advisory prefixes from all.zip, case-insensitive.
    /// Examples: GHSA, PYSEC, RUSTSEC, GO, UBUNTU.
    pub(crate) osv_prefixes: Option<Vec<String>>,
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
    pub(crate) fn into_search_value(self) -> String {
        match self {
            Self::Number(value) => value.to_string(),
            Self::String(value) => value,
        }
    }
}
