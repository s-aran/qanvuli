use rmcp::schemars;
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use serde_json::Value;

/// MCP clients do not all preserve JSON primitive types when constructing tool
/// arguments. Accept the schema-native primitive and its string representation.
fn deserialize_optional_primitive<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: FlexiblePrimitive,
{
    Option::<Value>::deserialize(deserializer)?
        .map(T::from_value)
        .transpose()
        .map_err(D::Error::custom)
}

trait FlexiblePrimitive: Sized {
    fn from_value(value: Value) -> Result<Self, String>;
}

macro_rules! impl_flexible_primitive {
    ($type:ty, $expected:literal, $native:expr) => {
        impl FlexiblePrimitive for $type {
            fn from_value(value: Value) -> Result<Self, String> {
                if let Some(value) = ($native)(&value) {
                    return Ok(value);
                }
                if let Value::String(text) = &value {
                    return text
                        .trim()
                        .parse::<Self>()
                        .map_err(|_| format!("expected {}, got `{text}`", $expected));
                }
                Err(format!("expected {}, got {value}", $expected))
            }
        }
    };
}

impl_flexible_primitive!(u64, "a non-negative integer", Value::as_u64);
impl_flexible_primitive!(bool, "a boolean", Value::as_bool);

impl FlexiblePrimitive for usize {
    fn from_value(value: Value) -> Result<Self, String> {
        if let Some(value) = value.as_u64().and_then(|value| value.try_into().ok()) {
            return Ok(value);
        }
        if let Value::String(text) = &value {
            return text
                .trim()
                .parse::<Self>()
                .map_err(|_| format!("expected a non-negative integer, got `{text}`"));
        }
        Err(format!("expected a non-negative integer, got {value}"))
    }
}

impl FlexiblePrimitive for f64 {
    fn from_value(value: Value) -> Result<Self, String> {
        let parsed = if let Some(value) = value.as_f64() {
            value
        } else if let Value::String(text) = &value {
            text.trim()
                .parse::<Self>()
                .map_err(|_| format!("expected a finite number, got `{text}`"))?
        } else {
            return Err(format!("expected a finite number, got {value}"));
        };
        parsed
            .is_finite()
            .then_some(parsed)
            .ok_or_else(|| format!("expected a finite number, got `{parsed}`"))
    }
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub(crate) struct CweArgs {
    /// CWE IDs to search for. Accepts numbers or strings such as 79, "CWE-79", or "CWE79".
    #[serde(default)]
    pub(crate) cwe_ids: Vec<CweArgValue>,
    /// Maximum number of results to return. Clamped to 1..=30; default is 10.
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
    pub(crate) limit: Option<u64>,
    /// Number of matching results to skip for pagination. Default is 0.
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
    pub(crate) offset: Option<u64>,
    /// Include rejected CVE records when true. Default returns only published CVEs.
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
    pub(crate) include_rejected: Option<bool>,
    /// Return complete English descriptions instead of 280-character previews. Defaults to false.
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
    pub(crate) full_description: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
#[schemars(inline)]
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
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
    pub(crate) limit: Option<u64>,
    /// Number of matching results to skip for pagination. Default is 0.
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
    pub(crate) offset: Option<u64>,
    /// Include rejected CVE records when true. Default returns only published CVEs.
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
    pub(crate) include_rejected: Option<bool>,
    /// Return complete English descriptions instead of 280-character previews. Defaults to false.
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
    pub(crate) full_description: Option<bool>,
    /// Exclude WordPress.org collection records, which often match generic library names. Defaults to false.
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
    pub(crate) exclude_collection: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub(crate) struct TextArgs {
    /// Free text query. CVE prefixes, CWE IDs, dates, titles, descriptions, and affected text are supported.
    pub(crate) query: String,
    /// Maximum number of results to return. Clamped to 1..=30; default is 10.
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
    pub(crate) limit: Option<u64>,
    /// Number of matching results to skip for pagination. Default is 0.
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
    pub(crate) offset: Option<u64>,
    /// Include rejected CVE records when true. Default returns only published CVEs.
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
    pub(crate) include_rejected: Option<bool>,
    /// Return complete English descriptions instead of 280-character previews. Defaults to false.
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
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
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
    pub(crate) limit: Option<u64>,
    /// Number of matching results to skip for pagination. Default is 0.
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
    pub(crate) offset: Option<u64>,
    /// Include rejected CVE records when true. Default returns only published CVEs.
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
    pub(crate) include_rejected: Option<bool>,
    /// Return complete English descriptions instead of 280-character previews. Defaults to false.
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
    pub(crate) full_description: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub(crate) struct CvssArgs {
    /// Minimum CVSS base score, inclusive.
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
    pub(crate) min_score: Option<f64>,
    /// Maximum CVSS base score, inclusive.
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
    pub(crate) max_score: Option<f64>,
    /// CVSS base severity string, such as LOW, MEDIUM, HIGH, or CRITICAL.
    pub(crate) severity: Option<String>,
    /// CVSS version string, such as 3.1 or 4.0.
    pub(crate) version: Option<String>,
    /// Maximum number of results to return. Clamped to 1..=30; default is 10.
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
    pub(crate) limit: Option<u64>,
    /// Number of matching results to skip for pagination. Default is 0.
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
    pub(crate) offset: Option<u64>,
    /// Include rejected CVE records when true. Default returns only published CVEs.
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
    pub(crate) include_rejected: Option<bool>,
    /// Return complete English descriptions instead of 280-character previews. Defaults to false.
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
    pub(crate) full_description: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub(crate) struct AnalyzeCvssVectorArgs {
    /// Complete CVSS v2.0, v3.0, v3.1, or v4.0 vector, including its CVSS version prefix.
    pub(crate) vector: String,
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
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
    pub(crate) min_score: Option<f64>,
    /// CVSS base severity string, such as LOW, MEDIUM, HIGH, or CRITICAL.
    pub(crate) severity: Option<String>,
    /// Maximum number of results to return. Clamped to 1..=30; default is 10.
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
    pub(crate) limit: Option<u64>,
    /// Number of matching results to skip for pagination. Default is 0.
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
    pub(crate) offset: Option<u64>,
    /// Include rejected CVE records when true. Default returns only published CVEs.
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
    pub(crate) include_rejected: Option<bool>,
    /// Return complete English descriptions instead of 280-character previews. Defaults to false.
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
    pub(crate) full_description: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub(crate) struct DateArgs {
    /// Return CVEs whose CVE datePublished is greater than or equal to this ISO-8601 timestamp.
    pub(crate) published_since: Option<String>,
    /// Return CVEs whose CVE dateUpdated is greater than or equal to this ISO-8601 timestamp.
    pub(crate) updated_since: Option<String>,
    /// Maximum number of results to return. Clamped to 1..=30; default is 10.
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
    pub(crate) limit: Option<u64>,
    /// Number of matching results to skip for pagination. Default is 0.
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
    pub(crate) offset: Option<u64>,
    /// Include rejected CVE records when true. Default returns only published CVEs.
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
    pub(crate) include_rejected: Option<bool>,
    /// Return complete English descriptions instead of 280-character previews. Defaults to false.
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
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
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
    pub(crate) limit: Option<u64>,
    /// Number of matching results to skip for pagination. Default is 0.
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
    pub(crate) offset: Option<u64>,
    /// Include rejected CVE records when true. Default returns only published CVEs.
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
    pub(crate) include_rejected: Option<bool>,
    /// Return complete English descriptions instead of 280-character previews. Defaults to false.
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
    pub(crate) full_description: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub(crate) struct IdPrefixArgs {
    /// CVE ID prefix such as CVE-2026- or CVE-2026-12.
    pub(crate) prefix: String,
    /// Maximum number of results to return. Clamped to 1..=30; default is 10.
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
    pub(crate) limit: Option<u64>,
    /// Number of matching results to skip for pagination. Default is 0.
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
    pub(crate) offset: Option<u64>,
    /// Include rejected CVE records when true. Default returns only published CVEs.
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
    pub(crate) include_rejected: Option<bool>,
    /// Return complete English descriptions instead of 280-character previews. Defaults to false.
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
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
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
    pub(crate) limit: Option<u64>,
    /// Number of matching entries to skip.
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
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
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
    pub(crate) limit: Option<u64>,
    /// Number of matching entries to skip.
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
    pub(crate) offset: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub(crate) struct GetCapecArgs {
    /// CAPEC ID. Accepts a number or a string such as CAPEC-1.
    pub(crate) capec_id: CweArgValue,
    /// Include external references. Defaults to false.
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
    pub(crate) include_references: Option<bool>,
    /// Include category and view details. Defaults to false.
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
    pub(crate) include_taxonomy: Option<bool>,
    /// Include category and view history. Defaults to false.
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
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
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
    pub(crate) limit: Option<u64>,
    /// Number of matching results to skip for pagination. Default is 0.
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
    pub(crate) offset: Option<u64>,
    /// Include rejected CVE records when true. Default returns only published CVEs.
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
    pub(crate) include_rejected: Option<bool>,
    /// Return compact triage rows by default, or full CWE/CVSS/affected details with "full".
    pub(crate) verbosity: Option<String>,
    /// Return complete English descriptions in full mode. Also selects full mode when verbosity is omitted.
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
    pub(crate) full_description: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub(crate) struct KnownExploitedArgs {
    /// Optional CVE ID. When omitted, returns locally synced KEV entries with pagination.
    pub(crate) cve_id: Option<String>,
    /// Maximum number of KEV entries to return when cve_id is omitted. Clamped to 1..=30; default is 10.
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
    pub(crate) limit: Option<u64>,
    /// Number of KEV entries to skip when cve_id is omitted. Default is 0.
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
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
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
    pub(crate) min_score: Option<f64>,
    /// Minimum EPSS percentile, inclusive.
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
    pub(crate) min_percentile: Option<f64>,
    /// Maximum number of results to return. Clamped to 1..=30; default is 10.
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
    pub(crate) limit: Option<u64>,
    /// Number of matching results to skip for pagination. Default is 0.
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
    pub(crate) offset: Option<u64>,
    /// Include rejected CVE records when true. Default returns only published CVEs.
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
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
pub(crate) struct GetCwesArgs {
    /// Up to 200 CWE IDs, as numbers or strings such as CWE-79.
    pub(crate) cwe_ids: Vec<CweArgValue>,
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
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
    pub(crate) limit: Option<u64>,
    /// Number of matching findings to skip. Default is 0.
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
    pub(crate) offset: Option<u64>,
    /// Include verbose OSV/alias/KEV/EPSS match evidence. Defaults to false.
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
    pub(crate) include_evidence: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub(crate) struct EvaluateAffectedArgs {
    /// CVE, OSV, GHSA, RUSTSEC, PYSEC, or GO advisory ID to evaluate.
    pub(crate) cve_id: String,
    /// Package ecosystem used for version comparison, such as npm or PyPI.
    pub(crate) ecosystem: String,
    /// Product or package name. Common separators are ignored for the CVE List join.
    #[serde(alias = "package")]
    pub(crate) name: String,
    /// Installed package version.
    pub(crate) version: String,
}

#[derive(Debug, Deserialize, Serialize, schemars::JsonSchema)]
#[schemars(inline)]
pub(crate) struct PackageQueryArgs {
    pub(crate) ecosystem: String,
    #[serde(alias = "name")]
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
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
    pub(crate) include_evidence: Option<bool>,
    /// Return one compact, decision-preserving summary per package by default, or full findings with "full".
    pub(crate) verbosity: Option<String>,
    /// Include OSV fixed-version candidates in findings and package summaries. Defaults to false.
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
    pub(crate) include_fixed: Option<bool>,
    /// Include per-CVE KEV, EPSS, and CVSS risk rows in each package result. Defaults to false.
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
    pub(crate) include_enrichment: Option<bool>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub(crate) struct UpdateDbArgs {
    /// Optional local CVE delta zip path to apply. When omitted, the updater downloads applicable CVE delta archives.
    pub(crate) zip: Option<String>,
    /// Optional cap on downloaded update chunks. Intended for testing or bounded maintenance runs.
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
    pub(crate) max_chunks: Option<usize>,
    /// Expand local OSV sync coverage to all OSV records.
    #[serde(default, deserialize_with = "deserialize_optional_primitive")]
    pub(crate) osv_all: Option<bool>,
    /// Additional OSV JSON filename/advisory prefixes from all.zip, case-insensitive.
    /// Examples: GHSA, PYSEC, RUSTSEC, GO, UBUNTU.
    pub(crate) osv_prefixes: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub(crate) struct GetUpdateStatusArgs {
    /// Job ID returned by update_db.
    pub(crate) job_id: String,
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
    use super::{CvssArgs, CweArgs, GetCapecArgs, QueryPackageEnrichedArgs, UpdateDbArgs};
    use rmcp::handler::server::wrapper::Parameters;

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
    fn search_arguments_accept_string_encoded_primitives() {
        let Parameters(args): Parameters<CweArgs> = serde_json::from_value(serde_json::json!({
            "cwe_ids": [79],
            "limit": "50",
            "offset": "2",
            "include_rejected": "true",
            "full_description": "false",
        }))
        .unwrap();

        assert_eq!(args.limit, Some(50));
        assert_eq!(args.offset, Some(2));
        assert_eq!(args.include_rejected, Some(true));
        assert_eq!(args.full_description, Some(false));
    }

    #[test]
    fn floating_point_boolean_and_usize_arguments_accept_strings() {
        let cvss: CvssArgs = serde_json::from_value(serde_json::json!({
            "min_score": "7.5",
            "max_score": "9",
        }))
        .unwrap();
        assert_eq!(cvss.min_score, Some(7.5));
        assert_eq!(cvss.max_score, Some(9.0));

        let capec: GetCapecArgs = serde_json::from_value(serde_json::json!({
            "capec_id": "CAPEC-1",
            "include_references": "true",
            "include_taxonomy": "false",
            "include_history": true,
        }))
        .unwrap();
        assert_eq!(capec.include_references, Some(true));
        assert_eq!(capec.include_taxonomy, Some(false));
        assert_eq!(capec.include_history, Some(true));

        let update: UpdateDbArgs = serde_json::from_value(serde_json::json!({
            "max_chunks": "12",
            "osv_all": "true",
        }))
        .unwrap();
        assert_eq!(update.max_chunks, Some(12));
        assert_eq!(update.osv_all, Some(true));
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

    #[test]
    fn primitive_compatibility_rejects_wrong_string_types() {
        let boolean_error = serde_json::from_value::<CweArgs>(serde_json::json!({
            "include_rejected": "yes",
        }))
        .unwrap_err();
        assert!(boolean_error.to_string().contains("expected a boolean"));

        let score_error = serde_json::from_value::<CvssArgs>(serde_json::json!({
            "min_score": "NaN",
        }))
        .unwrap_err();
        assert!(score_error.to_string().contains("expected a finite number"));
    }
}
