use rmcp::schemars;
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};

// Claude may send numeric MCP arguments as strings, so accept both forms.
fn deserialize_optional_u64<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum U64OrString {
        Number(u64),
        String(String),
    }

    Option::<U64OrString>::deserialize(deserializer)?
        .map(|value| match value {
            U64OrString::Number(value) => Ok(value),
            U64OrString::String(value) => value.trim().parse::<u64>().map_err(|_| {
                D::Error::custom(format!("expected a non-negative integer, got `{value}`"))
            }),
        })
        .transpose()
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub(crate) struct CweArgs {
    /// CWE IDs to search for. Accepts numbers or strings such as 79, "CWE-79", or "CWE79".
    #[serde(default)]
    pub(crate) cwe_ids: Vec<CweArgValue>,
    /// Maximum number of results to return. Clamped to 1..=30; default is 10.
    pub(crate) limit: Option<u64>,
    /// Number of matching results to skip for pagination. Default is 0.
    pub(crate) offset: Option<u64>,
    /// Include rejected CVE records when true. Default returns only published CVEs.
    pub(crate) include_rejected: Option<bool>,
    /// Return complete English descriptions instead of 280-character previews. Defaults to false.
    pub(crate) full_description: Option<bool>,
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
    /// Return complete English descriptions instead of 280-character previews. Defaults to false.
    pub(crate) full_description: Option<bool>,
    /// Exclude WordPress.org collection records, which often match generic library names. Defaults to false.
    pub(crate) exclude_collection: Option<bool>,
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
    /// Return complete English descriptions instead of 280-character previews. Defaults to false.
    pub(crate) full_description: Option<bool>,
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
    /// Return complete English descriptions instead of 280-character previews. Defaults to false.
    pub(crate) full_description: Option<bool>,
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
    /// Return complete English descriptions instead of 280-character previews. Defaults to false.
    pub(crate) full_description: Option<bool>,
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
    /// Return complete English descriptions instead of 280-character previews. Defaults to false.
    pub(crate) full_description: Option<bool>,
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
    /// Return complete English descriptions instead of 280-character previews. Defaults to false.
    pub(crate) full_description: Option<bool>,
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
    /// Return complete English descriptions instead of 280-character previews. Defaults to false.
    pub(crate) full_description: Option<bool>,
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
    /// Return complete English descriptions instead of 280-character previews. Defaults to false.
    pub(crate) full_description: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub(crate) struct CweCatalogArgs {
    /// CWE ID or text query. Empty query returns the first entries in tree order.
    pub(crate) query: Option<String>,
    /// Optional CWE statuses to include, such as Draft, Stable, Deprecated, or Obsolete.
    #[serde(default)]
    pub(crate) statuses: Vec<String>,
    /// Restrict CWE entries to those related to this CAPEC ID.
    pub(crate) capec_id: Option<CweArgValue>,
    /// Maximum number of CWE entries to return. Clamped to 1..=30; default is 10.
    pub(crate) limit: Option<u64>,
    /// Number of matching entries to skip.
    pub(crate) offset: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub(crate) struct GetCweArgs {
    /// CWE ID. Accepts a number or a string such as CWE-79.
    pub(crate) cwe_id: CweArgValue,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub(crate) struct CapecCatalogArgs {
    /// CAPEC ID, name, or description query.
    pub(crate) query: Option<String>,
    /// Optional CAPEC statuses such as Stable, Draft, or Deprecated.
    #[serde(default)]
    pub(crate) statuses: Vec<String>,
    /// Optional CAPEC abstraction types: Meta, Standard, or Detailed.
    #[serde(default)]
    pub(crate) types: Vec<String>,
    /// Restrict entries to those related to this CWE ID.
    pub(crate) cwe_id: Option<CweArgValue>,
    /// Maximum number of entries to return. Clamped to 1..=30; default is 10.
    pub(crate) limit: Option<u64>,
    /// Number of matching entries to skip.
    pub(crate) offset: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub(crate) struct GetCapecArgs {
    /// CAPEC ID. Accepts a number or a string such as CAPEC-1.
    pub(crate) capec_id: CweArgValue,
    /// Include external references. Defaults to false.
    pub(crate) include_references: Option<bool>,
    /// Include category and view details. Defaults to false.
    pub(crate) include_taxonomy: Option<bool>,
    /// Include category and view history. Defaults to false.
    pub(crate) include_history: Option<bool>,
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
    /// Return compact triage rows by default, or full CWE/CVSS/affected details with "full".
    pub(crate) verbosity: Option<String>,
    /// Return complete English descriptions in full mode. Also selects full mode when verbosity is omitted.
    pub(crate) full_description: Option<bool>,
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
    /// Include title and enrichment metadata normally omitted from triage rows. Defaults to false.
    pub(crate) verbosity: Option<String>,
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
    #[serde(default, deserialize_with = "deserialize_optional_u64")]
    pub(crate) limit: Option<u64>,
    /// Number of matching findings to skip. Default is 0.
    #[serde(default, deserialize_with = "deserialize_optional_u64")]
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
    /// Return one compact, decision-preserving summary per package by default, or full findings with "full".
    pub(crate) verbosity: Option<String>,
    /// Include OSV fixed-version candidates in findings and package summaries. Defaults to false.
    pub(crate) include_fixed: Option<bool>,
    /// Include per-CVE KEV, EPSS, and CVSS risk rows in each package result. Defaults to false.
    pub(crate) include_enrichment: Option<bool>,
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
        self.cwe_ids
            .into_iter()
            .map(CweArgValue::into_search_value)
            .collect()
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

#[cfg(test)]
mod tests {
    use super::QueryPackageEnrichedArgs;

    fn package_args(limit: serde_json::Value, offset: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "ecosystem": "crates.io",
            "package": "example",
            "version": "1.0.0",
            "limit": limit,
            "offset": offset,
        })
    }

    #[test]
    fn query_package_enriched_accepts_numeric_strings_for_pagination() {
        let args: QueryPackageEnrichedArgs =
            serde_json::from_value(package_args("30".into(), "2".into())).unwrap();

        assert_eq!(args.limit, Some(30));
        assert_eq!(args.offset, Some(2));
    }

    #[test]
    fn query_package_enriched_still_accepts_numbers_and_omitted_pagination() {
        let args: QueryPackageEnrichedArgs =
            serde_json::from_value(package_args(30.into(), 2.into())).unwrap();
        assert_eq!(args.limit, Some(30));
        assert_eq!(args.offset, Some(2));

        let args: QueryPackageEnrichedArgs = serde_json::from_value(serde_json::json!({
            "ecosystem": "crates.io",
            "package": "example",
            "version": "1.0.0",
        }))
        .unwrap();
        assert_eq!(args.limit, None);
        assert_eq!(args.offset, None);
    }

    #[test]
    fn query_package_enriched_rejects_invalid_numeric_strings() {
        let error = serde_json::from_value::<QueryPackageEnrichedArgs>(package_args(
            "many".into(),
            0.into(),
        ))
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("expected a non-negative integer")
        );
    }
}
