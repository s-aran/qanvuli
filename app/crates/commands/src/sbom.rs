use super::common::{DEFAULT_LIMIT, DateFilter, close_database, connect_database, print_json};
use qanvuli_core::database::{
    CveStateScope, CveSummary, CveSummaryWithDetail, EnrichedFinding, PackageQuery,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// CLI arguments for `qanvuli sbom`.
#[derive(Debug, clap::Args)]
pub struct Args {
    /// SBOM file path.
    #[arg(long = "file", value_name = "PATH")]
    file: Option<PathBuf>,
    /// SBOM file path.
    #[arg(value_name = "PATH")]
    path: Option<PathBuf>,
    /// Include findings published on or after this date.
    #[arg(long)]
    published_since: Option<String>,
    /// Include findings updated on or after this date.
    #[arg(long)]
    updated_since: Option<String>,
    /// Maximum findings per package and source.
    #[arg(long)]
    per_package_limit: Option<u64>,
    /// Include rejected CVEs.
    #[arg(long)]
    include_rejected: bool,
    /// Include unverified name matches outside vulnerability counts.
    #[arg(long)]
    include_name_matches: bool,
}

impl Args {
    fn path(&self) -> Result<&Path, String> {
        self.file
            .as_deref()
            .or(self.path.as_deref())
            .ok_or_else(|| "sbom mode requires --file <path> or a positional path".to_owned())
    }

    fn date_filter(&self) -> Result<DateFilter, String> {
        DateFilter::new(
            self.published_since.as_deref(),
            self.updated_since.as_deref(),
        )
    }
}

/// Reads an SBOM JSON file and prints local vulnerability findings as JSON.
pub async fn run(db_url: &str, args: Args) -> Result<(), String> {
    let db = connect_database(db_url).await?;
    db.check_required_schema()
        .await
        .map_err(|err| format!("database rebuild required before SBOM search: {err}"))?;
    let date_filter = args.date_filter()?;
    let packages = load_sbom_packages(args.path()?)?;
    let component_count = packages.len();
    let packages = deduplicate_sbom_packages(packages);
    let unique_component_count = packages.len();
    let mut cve_findings = BTreeMap::<(String, String, String), SbomCveFinding>::new();
    let mut osv_findings = BTreeMap::<(String, String, String, String), SbomOsvFinding>::new();
    let mut unverified_name_matches = BTreeMap::<(String, String, String), SbomCveFinding>::new();
    let mut unresolved_versions = BTreeSet::new();
    let per_package_limit = args.per_package_limit.unwrap_or(DEFAULT_LIMIT);
    let state_scope = CveStateScope::from_include_rejected(args.include_rejected);

    let mut package_query_owners = Vec::new();
    let mut package_queries = Vec::new();
    for (package_index, package) in packages.iter().enumerate() {
        for package_ref in package.package_refs() {
            let Some(version) = package_ref
                .version
                .as_deref()
                .filter(|value| is_concrete_version(value))
            else {
                continue;
            };
            package_query_owners.push((package_index, package_ref.purl.clone()));
            package_queries.push(PackageQuery {
                ecosystem: package_ref.ecosystem,
                package: package_ref.name,
                version: version.to_owned(),
                purl: Some(package_ref.purl),
            });
        }
    }
    let package_query_count = package_queries.len();
    let package_match_batches = db
        .query_package_matches_batch(&package_queries)
        .await
        .map_err(|err| format!("failed to batch package matching: {err}"))?;
    let global_osv_ids = package_match_batches
        .iter()
        .flatten()
        .map(|finding| finding.primary_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let global_osv_dates = db
        .osv_advisory_dates_batch(&global_osv_ids)
        .await
        .map_err(|err| format!("failed to load OSV advisory dates: {err}"))?;
    let global_osv_dates = global_osv_ids
        .into_iter()
        .zip(global_osv_dates)
        .collect::<BTreeMap<_, _>>();
    let global_cve_ids = package_match_batches
        .iter()
        .flatten()
        .flat_map(|finding| finding.cve_ids.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let global_cves = db
        .cve_summaries_with_details_batch(&global_cve_ids, state_scope)
        .await
        .map_err(|err| format!("failed to load linked CVEs: {err}"))?;
    let global_cves = global_cve_ids
        .into_iter()
        .zip(global_cves)
        .collect::<BTreeMap<_, _>>();
    let mut prefetched_matches =
        vec![BTreeMap::<String, Vec<EnrichedFinding>>::new(); unique_component_count];
    for ((package_index, purl), findings) in
        package_query_owners.into_iter().zip(package_match_batches)
    {
        prefetched_matches[package_index].insert(purl, findings);
    }

    eprintln!(
        "sbom: searching {component_count} components as {unique_component_count} unique components with {package_query_count} package queries"
    );
    for (index, package) in packages.into_iter().enumerate() {
        eprintln!(
            "sbom: {} searching {}",
            sbom_progress(index + 1, unique_component_count),
            package.name
        );
        let result = search_package(
            db.clone(),
            package,
            date_filter.clone(),
            state_scope,
            per_package_limit,
            args.include_name_matches,
            Some(PackagePrefetch {
                findings: &prefetched_matches[index],
                osv_dates: &global_osv_dates,
                cves: &global_cves,
            }),
        )
        .await?;
        eprintln!(
            "sbom: {} completed {} (CVE={}, OSV={})",
            sbom_progress(index + 1, unique_component_count),
            result.package_name,
            result.cve_findings.len(),
            result.osv_findings.len()
        );
        for finding in result.cve_findings {
            let key = cve_finding_key_from_finding(&finding);
            merge_cve_finding(&mut cve_findings, key, finding);
        }
        for finding in result.osv_findings {
            let key = osv_finding_key_from_finding(&finding);
            osv_findings.entry(key).or_insert(finding);
        }
        for finding in result.unverified_name_matches {
            let key = cve_finding_key_from_finding(&finding);
            merge_cve_finding(&mut unverified_name_matches, key, finding);
        }
        unresolved_versions.extend(result.unresolved_versions);
    }

    let cve_findings = cve_findings.into_values().collect::<Vec<_>>();
    let osv_findings = osv_findings.into_values().collect::<Vec<_>>();
    let unverified_name_matches = unverified_name_matches.into_values().collect::<Vec<_>>();
    eprintln!(
        "sbom: completed {unique_component_count}/{unique_component_count} unique components from {component_count} components; package_queries={package_query_count}; findings={}",
        cve_findings.len() + osv_findings.len()
    );
    let report = SbomReport {
        vulnerable: !cve_findings.is_empty() || !osv_findings.is_empty(),
        component_count,
        unique_component_count,
        package_query_count,
        count: cve_findings.len() + osv_findings.len(),
        cve_count: cve_findings.len(),
        osv_count: osv_findings.len(),
        findings: cve_findings,
        osv_findings,
        unverified_name_matches: args.include_name_matches.then_some(unverified_name_matches),
        unresolved_versions,
    };
    print_json(&report)?;

    close_database(db).await?;
    Ok(())
}

fn sbom_progress(position: usize, total: usize) -> String {
    format!("[{position}/{total}]")
}

struct PackageSearchResult {
    package_name: String,
    cve_findings: Vec<SbomCveFinding>,
    osv_findings: Vec<SbomOsvFinding>,
    unverified_name_matches: Vec<SbomCveFinding>,
    unresolved_versions: Vec<UnresolvedVersion>,
}

type OsvDateMap = BTreeMap<String, Option<(Option<String>, Option<String>)>>;
type CveDetailMap = BTreeMap<String, Option<CveSummaryWithDetail>>;

#[derive(Clone, Copy)]
struct PackagePrefetch<'a> {
    findings: &'a BTreeMap<String, Vec<EnrichedFinding>>,
    osv_dates: &'a OsvDateMap,
    cves: &'a CveDetailMap,
}

async fn search_package(
    db: qanvuli_core::database::CveDatabase,
    package: SbomPackage,
    date_filter: DateFilter,
    state_scope: CveStateScope,
    per_package_limit: u64,
    include_name_matches: bool,
    prefetch: Option<PackagePrefetch<'_>>,
) -> Result<PackageSearchResult, String> {
    let mut cve_findings = Vec::new();
    let mut osv_findings = Vec::new();
    let mut unverified_name_matches = Vec::new();
    let mut unresolved_versions = Vec::new();
    if include_name_matches && package.purls().is_empty() {
        for component in package.search_names().into_iter().take(8) {
            let cves = db
                .search_cve_summaries_by_affected_component_with_state_scope(
                    None,
                    &component,
                    date_filter.published_since.as_deref(),
                    date_filter.updated_since.as_deref(),
                    state_scope,
                    per_package_limit,
                    0,
                )
                .await
                .map_err(|err| format!("failed to search `{component}`: {err}"))?;

            for cve in cves {
                unverified_name_matches.push(SbomCveFinding {
                    package: package.name.clone(),
                    version: package.version.clone(),
                    matched_component: component.clone(),
                    matched_purl: None,
                    version_match: CveVersionMatch::NotChecked,
                    cve,
                });
            }
        }
    }

    for package_ref in package.package_refs() {
        let Some(version) = package_ref.version.as_deref() else {
            continue;
        };
        if !is_concrete_version(version) {
            unresolved_versions.push(UnresolvedVersion {
                package: package.name.clone(),
                version: version.to_owned(),
                matched_purl: package_ref.purl.clone(),
                reason: "version constraint is not a concrete version".to_owned(),
            });
            continue;
        }
        let findings = if let Some(prefetched) = prefetch {
            prefetched
                .findings
                .get(&package_ref.purl)
                .cloned()
                .unwrap_or_default()
        } else {
            db.query_package_matches(
                &package_ref.ecosystem,
                &package_ref.name,
                version,
                Some(&package_ref.purl),
            )
            .await
            .map_err(|err| format!("failed to query package `{}`: {err}", package.name))?
        };
        let owned_osv_dates;
        let osv_dates = if let Some(prefetched) = prefetch {
            prefetched.osv_dates
        } else {
            let osv_ids = findings
                .iter()
                .map(|finding| finding.primary_id.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            let dates = db
                .osv_advisory_dates_batch(&osv_ids)
                .await
                .map_err(|err| format!("failed to load OSV advisory dates: {err}"))?;
            owned_osv_dates = osv_ids.into_iter().zip(dates).collect();
            &owned_osv_dates
        };
        let owned_cves;
        let cves = if let Some(prefetched) = prefetch {
            prefetched.cves
        } else {
            let cve_ids = findings
                .iter()
                .flat_map(|finding| finding.cve_ids.iter().cloned())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            let summaries = db
                .cve_summaries_with_details_batch(&cve_ids, state_scope)
                .await
                .map_err(|err| format!("failed to load linked CVEs: {err}"))?;
            owned_cves = cve_ids.into_iter().zip(summaries).collect();
            &owned_cves
        };
        for finding in findings {
            let osv_matches_dates = osv_dates
                .get(&finding.primary_id)
                .and_then(Option::as_ref)
                .is_some_and(|(published, modified)| {
                    matches_since(published.as_deref(), date_filter.published_since.as_deref())
                        && matches_since(modified.as_deref(), date_filter.updated_since.as_deref())
                });
            if finding.affected.status != "affected" {
                if osv_matches_dates {
                    unresolved_versions.push(UnresolvedVersion {
                        package: package.name.clone(),
                        version: version.to_owned(),
                        matched_purl: package_ref.purl.clone(),
                        reason: format!(
                            "advisory {} found but version evaluation returned {}",
                            finding.primary_id, finding.affected.status
                        ),
                    });
                }
                continue;
            }
            for cve_id in &finding.cve_ids {
                let Some(cve) = cves.get(cve_id).and_then(Option::as_ref) else {
                    continue;
                };
                if !matches_since(
                    Some(&cve.summary.published_at),
                    date_filter.published_since.as_deref(),
                ) || !matches_since(
                    Some(&cve.summary.updated_at),
                    date_filter.updated_since.as_deref(),
                ) {
                    continue;
                }
                cve_findings.push(SbomCveFinding {
                    package: package.name.clone(),
                    version: package_ref.version.clone(),
                    matched_component: package_ref.name.clone(),
                    matched_purl: Some(package_ref.purl.clone()),
                    version_match: CveVersionMatch::OsvRangeMatched,
                    cve: cve.summary.clone(),
                });
            }
            if osv_matches_dates {
                osv_findings.push(SbomOsvFinding {
                    package: package.name.clone(),
                    version: package_ref.version.clone(),
                    matched_purl: package_ref.purl.clone(),
                    finding,
                });
            }
        }
    }

    let limit = usize::try_from(per_package_limit).unwrap_or(usize::MAX);
    cve_findings.truncate(limit);
    osv_findings.truncate(limit);
    unverified_name_matches.truncate(limit);

    Ok(PackageSearchResult {
        package_name: package.name.clone(),
        cve_findings,
        osv_findings,
        unverified_name_matches,
        unresolved_versions,
    })
}

fn matches_since(value: Option<&str>, since: Option<&str>) -> bool {
    since.is_none_or(|since| value.is_some_and(|value| value >= since))
}

/// Builds an unambiguous key that keeps findings for distinct package versions separate.
#[cfg(test)]
fn cve_finding_key(package: &SbomPackage, cve_id: &str) -> (String, String, String) {
    (
        package.name.clone(),
        package.version.clone().unwrap_or_default(),
        cve_id.to_owned(),
    )
}

/// Builds an unambiguous key for OSV findings, including the PURL that was matched.
#[cfg(test)]
fn osv_finding_key(
    package: &SbomPackage,
    purl: &str,
    finding_id: &str,
) -> (String, String, String, String) {
    (
        package.name.clone(),
        package.version.clone().unwrap_or_default(),
        purl.to_owned(),
        finding_id.to_owned(),
    )
}

fn cve_finding_key_from_finding(finding: &SbomCveFinding) -> (String, String, String) {
    (
        finding.package.clone(),
        finding.version.clone().unwrap_or_default(),
        finding.cve.cve_id.clone(),
    )
}

fn merge_cve_finding(
    findings: &mut BTreeMap<(String, String, String), SbomCveFinding>,
    key: (String, String, String),
    finding: SbomCveFinding,
) {
    match findings.entry(key) {
        std::collections::btree_map::Entry::Vacant(entry) => {
            entry.insert(finding);
        }
        std::collections::btree_map::Entry::Occupied(mut entry)
            if finding.version_match.is_verified() && !entry.get().version_match.is_verified() =>
        {
            entry.insert(finding);
        }
        std::collections::btree_map::Entry::Occupied(_) => {}
    }
}

fn osv_finding_key_from_finding(finding: &SbomOsvFinding) -> (String, String, String, String) {
    (
        finding.package.clone(),
        finding.version.clone().unwrap_or_default(),
        finding.matched_purl.clone(),
        finding.finding.primary_id.clone(),
    )
}

fn load_sbom_packages(path: &Path) -> Result<Vec<SbomPackage>, String> {
    let mut json = std::fs::read(path)
        .map_err(|err| format!("failed to read SBOM {}: {err}", path.display()))?;
    load_sbom_packages_from_slice(&mut json)
}

fn load_sbom_packages_from_slice(json: &mut [u8]) -> Result<Vec<SbomPackage>, String> {
    let sbom: GitHubSbom =
        simd_json::from_slice(json).map_err(|err| format!("failed to parse SBOM JSON: {err}"))?;
    let mut packages = Vec::new();
    if let Some(document) = sbom.sbom {
        packages.extend(document.packages);
        packages.extend(document.components);
    }
    packages.extend(sbom.packages);
    packages.extend(sbom.components);

    Ok(packages
        .into_iter()
        .filter(|package| !package.name.is_empty())
        .collect())
}

fn deduplicate_sbom_packages(packages: Vec<SbomPackage>) -> Vec<SbomPackage> {
    let mut unique = BTreeMap::new();
    for package in packages {
        let normalized_purls = package
            .purls()
            .into_iter()
            .filter_map(|purl| package_ref_from_purl(purl, package.version.as_deref()))
            .map(|package_ref| {
                format!(
                    "{}\u{1f}{}\u{1f}{}",
                    package_ref.ecosystem.to_ascii_lowercase(),
                    package_ref.name.to_ascii_lowercase(),
                    package_ref.version.unwrap_or_default()
                )
            })
            .collect::<BTreeSet<_>>();
        let key = (
            package.name.to_ascii_lowercase(),
            package.version.clone().unwrap_or_default(),
            normalized_purls,
        );
        unique.entry(key).or_insert(package);
    }
    unique.into_values().collect()
}

#[derive(Debug, Deserialize)]
struct GitHubSbom {
    sbom: Option<SbomDocument>,
    #[serde(default)]
    packages: Vec<SbomPackage>,
    #[serde(default)]
    components: Vec<SbomPackage>,
}

#[derive(Debug, Deserialize)]
struct SbomDocument {
    #[serde(default)]
    packages: Vec<SbomPackage>,
    #[serde(default)]
    components: Vec<SbomPackage>,
}

#[derive(Clone, Debug, Deserialize)]
struct SbomPackage {
    name: String,
    #[serde(rename = "versionInfo", alias = "version")]
    version: Option<String>,
    #[serde(default, rename = "externalRefs")]
    external_refs: Vec<SbomExternalRef>,
    #[serde(rename = "purl", alias = "packageUrl")]
    package_url: Option<String>,
}

impl SbomPackage {
    fn search_names(&self) -> Vec<String> {
        let mut names = BTreeSet::from([self.name.clone()]);

        for purl in self.purls() {
            if let Some(package_ref) = package_ref_from_purl(purl, self.version.as_deref()) {
                names.insert(package_ref.name.clone());
                if let Some(short_name) = package_ref.name.rsplit('/').next() {
                    names.insert(short_name.to_owned());
                }
            }
        }

        names.into_iter().collect()
    }

    fn purls(&self) -> Vec<&str> {
        let mut purls = Vec::new();
        if let Some(package_url) = self.package_url.as_deref() {
            purls.push(package_url);
        }
        purls.extend(self.external_refs.iter().filter_map(SbomExternalRef::purl));
        purls.sort();
        purls.dedup();
        purls
    }

    fn package_refs(&self) -> Vec<PackageRef> {
        let mut normalized = BTreeMap::new();
        for package_ref in self
            .purls()
            .into_iter()
            .filter_map(|purl| package_ref_from_purl(purl, self.version.as_deref()))
        {
            let key = (
                package_ref.ecosystem.to_ascii_lowercase(),
                package_ref.name.to_ascii_lowercase(),
                package_ref.version.clone().unwrap_or_default(),
            );
            normalized.entry(key).or_insert(package_ref);
        }
        normalized.into_values().collect()
    }
}

#[derive(Clone, Debug, Deserialize)]
struct SbomExternalRef {
    #[serde(rename = "referenceType")]
    reference_type: Option<String>,
    #[serde(rename = "referenceLocator")]
    reference_locator: Option<String>,
}

impl SbomExternalRef {
    fn purl(&self) -> Option<&str> {
        self.reference_locator.as_deref().filter(|locator| {
            locator.starts_with("pkg:")
                || self
                    .reference_type
                    .as_deref()
                    .is_some_and(|kind| kind.eq_ignore_ascii_case("purl"))
        })
    }
}

#[derive(Debug, Serialize)]
struct SbomCveFinding {
    package: String,
    version: Option<String>,
    matched_component: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    matched_purl: Option<String>,
    version_match: CveVersionMatch,
    cve: CveSummary,
}

#[derive(Debug, Serialize)]
struct SbomReport {
    vulnerable: bool,
    component_count: usize,
    unique_component_count: usize,
    package_query_count: usize,
    count: usize,
    cve_count: usize,
    osv_count: usize,
    findings: Vec<SbomCveFinding>,
    osv_findings: Vec<SbomOsvFinding>,
    unverified_name_matches: Option<Vec<SbomCveFinding>>,
    unresolved_versions: BTreeSet<UnresolvedVersion>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum CveVersionMatch {
    /// The CVE is a component-name match; its version range was not evaluated.
    NotChecked,
    /// An OSV/GHSA affected-version range matched and aliases this CVE.
    OsvRangeMatched,
}

impl CveVersionMatch {
    const fn is_verified(&self) -> bool {
        matches!(self, Self::OsvRangeMatched)
    }
}

#[derive(Debug, Serialize)]
struct SbomOsvFinding {
    package: String,
    version: Option<String>,
    matched_purl: String,
    finding: EnrichedFinding,
}

#[derive(Debug, Serialize, Ord, PartialOrd, Eq, PartialEq)]
struct UnresolvedVersion {
    package: String,
    version: String,
    matched_purl: String,
    reason: String,
}

/// Constraints such as `>= 2.2.1,< 3` are not installed versions and must not
/// be sent through the exact-version OSV matcher.
fn is_concrete_version(version: &str) -> bool {
    !version.is_empty()
        && !version.chars().any(|character| {
            matches!(
                character,
                '<' | '>' | '=' | '!' | '~' | '^' | '*' | ',' | ' ' | '|'
            )
        })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PackageRef {
    ecosystem: String,
    name: String,
    version: Option<String>,
    purl: String,
}

fn package_ref_from_purl(purl: &str, fallback_version: Option<&str>) -> Option<PackageRef> {
    let body = purl.strip_prefix("pkg:").unwrap_or(purl);
    let without_qualifiers = body.split(['?', '#']).next().unwrap_or(body);
    let (package_path, purl_version) = without_qualifiers.rsplit_once('@').map_or(
        (without_qualifiers, None),
        |(package, version)| {
            if package.is_empty() {
                (without_qualifiers, None)
            } else {
                (package, Some(version))
            }
        },
    );
    let (purl_type, name_path) = package_path.split_once('/')?;
    let ecosystem = osv_ecosystem_from_purl_type(purl_type)?;
    let name = percent_decode(name_path);
    if name.is_empty() {
        return None;
    }

    Some(PackageRef {
        ecosystem: ecosystem.to_owned(),
        name,
        version: purl_version
            .or(fallback_version)
            .map(percent_decode)
            .filter(|version| !version.is_empty()),
        purl: purl.to_owned(),
    })
}

fn osv_ecosystem_from_purl_type(purl_type: &str) -> Option<&'static str> {
    match purl_type.to_ascii_lowercase().as_str() {
        "cargo" => Some("crates.io"),
        "gem" => Some("RubyGems"),
        "github" => Some("GitHub Actions"),
        "golang" => Some("Go"),
        "maven" => Some("Maven"),
        "npm" => Some("npm"),
        "nuget" => Some("NuGet"),
        "pypi" => Some("PyPI"),
        "pub" => Some("Pub"),
        _ => None,
    }
}

/// Decodes percent-encoded UTF-8 while leaving malformed values unchanged.
fn percent_decode(value: &str) -> String {
    let mut decoded = Vec::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && let Ok(hex) = std::str::from_utf8(&bytes[index + 1..index + 3])
            && let Ok(byte) = u8::from_str_radix(hex, 16)
        {
            decoded.push(byte);
            index += 3;
            continue;
        }
        decoded.push(bytes[index]);
        index += 1;
    }
    String::from_utf8(decoded).unwrap_or_else(|_| value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_minimal_spdx_sbom() {
        let mut json = br#"{
            "spdxVersion": "SPDX-2.3",
            "packages": [
                {
                    "name": "mlua",
                    "versionInfo": "0.11.1",
                    "externalRefs": [{
                        "referenceType": "purl",
                        "referenceLocator": "pkg:cargo/mlua@0.11.1"
                    }]
                },
                {"name": "serde_json", "versionInfo": "1.0.0"}
            ]
        }"#
        .to_vec();
        let packages = load_sbom_packages_from_slice(&mut json).unwrap();

        assert_eq!(packages.len(), 2);
        assert!(packages.iter().any(|package| package.name == "mlua"));
        assert!(packages.iter().any(|package| package.name == "serde_json"));
    }

    #[test]
    fn extracts_package_refs_from_purls() {
        assert_eq!(
            package_ref_from_purl("pkg:cargo/mlua@0.11.1", None),
            Some(PackageRef {
                ecosystem: "crates.io".to_owned(),
                name: "mlua".to_owned(),
                version: Some("0.11.1".to_owned()),
                purl: "pkg:cargo/mlua@0.11.1".to_owned(),
            })
        );
        assert_eq!(
            package_ref_from_purl("pkg:npm/%40scope/name@1.2.3", None)
                .unwrap()
                .name,
            "@scope/name"
        );
    }

    #[test]
    fn maps_every_advertised_purl_ecosystem() {
        for (purl_type, ecosystem) in [
            ("cargo", "crates.io"),
            ("gem", "RubyGems"),
            ("github", "GitHub Actions"),
            ("golang", "Go"),
            ("maven", "Maven"),
            ("npm", "npm"),
            ("nuget", "NuGet"),
            ("pypi", "PyPI"),
            ("pub", "Pub"),
        ] {
            assert_eq!(osv_ecosystem_from_purl_type(purl_type), Some(ecosystem));
        }
    }

    #[test]
    fn decodes_percent_encoded_utf8_purl_names() {
        assert_eq!(
            package_ref_from_purl("pkg:npm/%E3%81%82@1.2.3", None)
                .unwrap()
                .name,
            "あ"
        );
        assert_eq!(percent_decode("%FF"), "%FF");
    }

    #[test]
    fn distinguishes_concrete_versions_from_constraints() {
        assert!(is_concrete_version("2.10"));
        assert!(is_concrete_version("7.25.9"));
        assert!(!is_concrete_version(">= 2.2.1,< 3"));
        assert!(!is_concrete_version(">= 0.9.1"));
    }

    #[test]
    fn source_dates_are_filtered_inclusive_of_the_boundary() {
        assert!(matches_since(
            Some("2026-01-02T00:00:00Z"),
            Some("2026-01-02T00:00:00Z")
        ));
        assert!(!matches_since(
            Some("2026-01-01T00:00:00Z"),
            Some("2026-01-02T00:00:00Z")
        ));
        assert!(!matches_since(None, Some("2026-01-02T00:00:00Z")));
    }

    #[tokio::test]
    async fn verified_findings_honor_source_date_filters_and_final_limit() {
        use qanvuli_core::database::{OsvRawRecord, SqlxDatabase};

        let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        database.initialize().await.unwrap();
        database
            .import_cve_raw_jsons_bulk_init(vec![
                r#"{"cveMetadata":{"cveId":"CVE-2099-7001","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-02T00:00:00Z"},"containers":{"cna":{"title":"SBOM filter fixture"}}}"#.to_owned(),
            ])
            .await
            .unwrap();
        database
            .import_osv_record(OsvRawRecord {
                source_path: None,
                raw_json: r#"{"schema_version":"1.8.0","id":"GHSA-2099-filter","published":"2099-01-01T00:00:00Z","modified":"2099-01-02T00:00:00Z","aliases":["CVE-2099-7001"],"affected":[{"package":{"ecosystem":"crates.io","name":"fixture"},"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"2.0.0"}]}]}]}"#.to_owned(),
            })
            .await
            .unwrap();
        let package = SbomPackage {
            name: "fixture".to_owned(),
            version: Some("1.5.0".to_owned()),
            external_refs: Vec::new(),
            package_url: Some("pkg:cargo/fixture@1.5.0".to_owned()),
        };
        let included = search_package(
            database.clone(),
            package.clone(),
            DateFilter::new(Some("2099-01-01T00:00:00Z"), Some("2099-01-02T00:00:00Z")).unwrap(),
            CveStateScope::PublishedOnly,
            1,
            false,
            None,
        )
        .await
        .unwrap();
        assert_eq!(included.cve_findings.len(), 1);
        assert_eq!(included.osv_findings.len(), 1);

        let excluded = search_package(
            database,
            package,
            DateFilter::new(Some("2099-01-03T00:00:00Z"), None).unwrap(),
            CveStateScope::PublishedOnly,
            1,
            false,
            None,
        )
        .await
        .unwrap();
        assert!(excluded.cve_findings.is_empty());
        assert!(excluded.osv_findings.is_empty());
    }

    #[test]
    fn finding_keys_keep_package_versions_separate() {
        let v1 = SbomPackage {
            name: "example".to_owned(),
            version: Some("1.0.0".to_owned()),
            external_refs: Vec::new(),
            package_url: None,
        };
        let v2 = SbomPackage {
            version: Some("2.0.0".to_owned()),
            ..v1.clone()
        };

        assert_ne!(
            cve_finding_key(&v1, "CVE-2024-1"),
            cve_finding_key(&v2, "CVE-2024-1")
        );
        assert_ne!(
            osv_finding_key(&v1, "pkg:cargo/example@1.0.0", "GHSA-test"),
            osv_finding_key(&v1, "pkg:cargo/example@2.0.0", "GHSA-test")
        );
    }

    #[test]
    fn version_matched_cve_replaces_component_only_match() {
        let summary = CveSummary {
            cve_id: "CVE-2026-1".to_owned(),
            state: 1,
            published_at: "2026-01-01T00:00:00Z".to_owned(),
            updated_at: "2026-01-01T00:00:00Z".to_owned(),
            title: "example".to_owned(),
            description_en: None,
        };
        let key = (
            "example".to_owned(),
            "1.0.0".to_owned(),
            summary.cve_id.clone(),
        );
        let mut findings = BTreeMap::new();
        merge_cve_finding(
            &mut findings,
            key.clone(),
            SbomCveFinding {
                package: "example".to_owned(),
                version: Some("1.0.0".to_owned()),
                matched_component: "example".to_owned(),
                matched_purl: None,
                version_match: CveVersionMatch::NotChecked,
                cve: summary.clone(),
            },
        );
        merge_cve_finding(
            &mut findings,
            key.clone(),
            SbomCveFinding {
                package: "example".to_owned(),
                version: Some("1.0.0".to_owned()),
                matched_component: "example".to_owned(),
                matched_purl: Some("pkg:cargo/example@1.0.0".to_owned()),
                version_match: CveVersionMatch::OsvRangeMatched,
                cve: summary,
            },
        );

        assert!(findings[&key].version_match.is_verified());
    }

    #[test]
    fn loads_cyclonedx_components() {
        let mut json = br#"{
            "bomFormat": "CycloneDX",
            "components": [
                {"name": "serde_json", "version": "1.0.0", "purl": "pkg:cargo/serde_json@1.0.0"}
            ]
        }"#
        .to_vec();

        let packages = load_sbom_packages_from_slice(&mut json).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].search_names(), vec!["serde_json".to_owned()]);
    }

    #[test]
    fn deduplicates_equivalent_normalized_package_entries_without_merging_versions() {
        let packages = vec![
            SbomPackage {
                name: "Example".to_owned(),
                version: Some("1.0.0".to_owned()),
                external_refs: Vec::new(),
                package_url: Some("pkg:npm/%65xample@1.0.0".to_owned()),
            },
            SbomPackage {
                name: "example".to_owned(),
                version: Some("1.0.0".to_owned()),
                external_refs: Vec::new(),
                package_url: Some("pkg:npm/example@1.0.0".to_owned()),
            },
            SbomPackage {
                name: "example".to_owned(),
                version: Some("2.0.0".to_owned()),
                external_refs: Vec::new(),
                package_url: Some("pkg:npm/example@2.0.0".to_owned()),
            },
        ];
        let unique = deduplicate_sbom_packages(packages);
        assert_eq!(unique.len(), 2);
        assert_eq!(
            unique
                .iter()
                .map(|package| package.version.as_deref().unwrap())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["1.0.0", "2.0.0"])
        );
    }

    #[test]
    fn one_component_can_generate_multiple_package_queries() {
        let package = SbomPackage {
            name: "example".to_owned(),
            version: Some("1.0.0".to_owned()),
            external_refs: vec![
                SbomExternalRef {
                    reference_type: Some("purl".to_owned()),
                    reference_locator: Some("pkg:npm/example@1.0.0".to_owned()),
                },
                SbomExternalRef {
                    reference_type: Some("purl".to_owned()),
                    reference_locator: Some("pkg:cargo/example@1.0.0".to_owned()),
                },
            ],
            package_url: None,
        };

        assert_eq!(package.package_refs().len(), 2);
    }

    #[test]
    fn progress_reaches_unique_component_denominator() {
        assert_eq!(sbom_progress(2, 2), "[2/2]");
    }

    #[test]
    fn report_json_uses_distinct_component_and_query_counts() {
        let report = SbomReport {
            vulnerable: false,
            component_count: 3,
            unique_component_count: 2,
            package_query_count: 4,
            count: 0,
            cve_count: 0,
            osv_count: 0,
            findings: Vec::new(),
            osv_findings: Vec::new(),
            unverified_name_matches: None,
            unresolved_versions: BTreeSet::new(),
        };
        let value = serde_json::to_value(report).unwrap();

        assert_eq!(value["component_count"], 3);
        assert_eq!(value["unique_component_count"], 2);
        assert_eq!(value["package_query_count"], 4);
        assert!(value.get("package_count").is_none());
        assert!(value.get("unique_package_query_count").is_none());
    }

    #[tokio::test]
    #[ignore = "performance benchmark"]
    async fn benchmark_sbom_document_batch_sizes() {
        use qanvuli_core::database::SqlxDatabase;

        let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        database.initialize().await.unwrap();
        for (label, input_count, distinct_count) in [
            ("100", 100_usize, 100_usize),
            ("1000", 1_000, 1_000),
            ("duplicate-heavy-1000", 1_000, 100),
        ] {
            let packages = (0..input_count)
                .map(|index| {
                    let package_index = index % distinct_count;
                    SbomPackage {
                        name: format!("package-{package_index}"),
                        version: Some(format!("1.{}.0", package_index % 10)),
                        external_refs: Vec::new(),
                        package_url: Some(format!(
                            "pkg:npm/package-{package_index}@1.{}.0",
                            package_index % 10
                        )),
                    }
                })
                .collect();
            let unique = deduplicate_sbom_packages(packages);
            let queries = unique
                .iter()
                .flat_map(|package| package.purls())
                .filter_map(|purl| package_ref_from_purl(purl, None))
                .map(|package| PackageQuery {
                    ecosystem: package.ecosystem,
                    package: package.name,
                    version: package.version.unwrap(),
                    purl: Some(package.purl),
                })
                .collect::<Vec<_>>();
            let baseline_queries = (0..input_count)
                .map(|index| {
                    let package_index = index % distinct_count;
                    PackageQuery {
                        ecosystem: "npm".to_owned(),
                        package: format!("package-{package_index}"),
                        version: format!("1.{}.0", package_index % 10),
                        purl: Some(format!(
                            "pkg:npm/package-{package_index}@1.{}.0",
                            package_index % 10
                        )),
                    }
                })
                .collect::<Vec<_>>();
            let baseline_started = std::time::Instant::now();
            for query in &baseline_queries {
                database
                    .query_package_matches(
                        &query.ecosystem,
                        &query.package,
                        &query.version,
                        query.purl.as_deref(),
                    )
                    .await
                    .unwrap();
            }
            let baseline_elapsed = baseline_started.elapsed();
            let batched_started = std::time::Instant::now();
            let results = database
                .query_package_matches_batch(&queries)
                .await
                .unwrap();
            eprintln!(
                "SBOM batch: fixture={label} input={input_count} unique={} baseline_per_component={baseline_elapsed:?} batched_elapsed={:?} result_groups={}",
                queries.len(),
                batched_started.elapsed(),
                results.len()
            );
        }
        database.close().await.unwrap();
    }
}
