use super::common::{DEFAULT_LIMIT, DateFilter, close_database, connect_database, print_json};
use qanvuli_core::database::{
    CveStateScope, CveSummary, CveSummaryWithDetail, EnrichedFinding, PackageQuery,
    ecosystem_identity_key, is_concrete_package_version, normalize_package_name,
    parse_package_purl,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
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
    /// Also write the report as SARIF 2.1.0 while JSON remains on stdout.
    #[arg(long, value_name = "PATH")]
    sarif_output: Option<PathBuf>,
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
    let input_path = args.path()?.to_path_buf();
    if args.sarif_output.as_deref() == Some(input_path.as_path()) {
        return Err("--sarif-output must not overwrite the input SBOM".to_owned());
    }
    let db = connect_database(db_url).await?;
    db.check_required_schema()
        .await
        .map_err(|err| format!("database rebuild required before SBOM search: {err}"))?;
    let date_filter = args.date_filter()?;
    let packages = load_sbom_packages(&input_path)?;
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
                .filter(|value| is_concrete_package_version(&package_ref.ecosystem, value))
            else {
                continue;
            };
            package_query_owners.push((package_index, package_ref.purl.clone()));
            package_queries.push(PackageQuery {
                ecosystem: package_ref.ecosystem,
                package: package_ref.name,
                version: version.to_owned(),
                purl: Some(package_ref.query_purl),
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
    if let Some(output_path) = args.sarif_output.as_deref() {
        write_sarif(output_path, &SarifLog::from_report(&report, &input_path))?;
        eprintln!("sbom: wrote SARIF report to {}", output_path.display());
    }
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

    for purl in package.purls() {
        if package_ref_from_purl(purl, package.version.as_deref()).is_none() {
            unresolved_versions.push(UnresolvedVersion {
                package: package.name.clone(),
                version: package.version.clone().unwrap_or_default(),
                matched_purl: purl.to_owned(),
                reason: "PURL is malformed or uses an unsupported package type".to_owned(),
            });
        }
    }

    for package_ref in package.package_refs() {
        let Some(version) = package_ref.version.as_deref() else {
            unresolved_versions.push(UnresolvedVersion {
                package: package.name.clone(),
                version: String::new(),
                matched_purl: package_ref.purl.clone(),
                reason: "installed version is missing".to_owned(),
            });
            continue;
        };
        if !is_concrete_package_version(&package_ref.ecosystem, version) {
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
                Some(&package_ref.query_purl),
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
            let cve_matches_dates = cves
                .get(&finding.primary_id)
                .and_then(Option::as_ref)
                .is_some_and(|cve| {
                    matches_since(
                        Some(&cve.summary.published_at),
                        date_filter.published_since.as_deref(),
                    ) && matches_since(
                        Some(&cve.summary.updated_at),
                        date_filter.updated_since.as_deref(),
                    )
                });
            let advisory_matches_dates = match finding.source.as_str() {
                "osv" => osv_matches_dates,
                "cve-list" => cve_matches_dates,
                _ => osv_matches_dates || cve_matches_dates,
            };
            if finding.affected.status != "affected" {
                if version_evaluation_needs_review(&finding.affected.status)
                    && advisory_matches_dates
                {
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
        append_cyclonedx_metadata_component(&mut packages, document.metadata);
        append_cyclonedx_components(&mut packages, document.components);
    }
    packages.extend(sbom.packages);
    append_cyclonedx_metadata_component(&mut packages, sbom.metadata);
    append_cyclonedx_components(&mut packages, sbom.components);

    Ok(packages
        .into_iter()
        .filter(|package| !package.name.is_empty())
        .collect())
}

fn append_cyclonedx_metadata_component(
    packages: &mut Vec<SbomPackage>,
    metadata: Option<CycloneDxMetadata>,
) {
    if let Some(component) = metadata.and_then(|metadata| metadata.component) {
        append_cyclonedx_components(packages, vec![component]);
    }
}

fn append_cyclonedx_components(
    packages: &mut Vec<SbomPackage>,
    components: Vec<CycloneDxComponent>,
) {
    let mut pending = components.into_iter().rev().collect::<Vec<_>>();
    while let Some(CycloneDxComponent {
        package,
        components,
    }) = pending.pop()
    {
        packages.push(package);
        pending.extend(components.into_iter().rev());
    }
}

fn deduplicate_sbom_packages(packages: Vec<SbomPackage>) -> Vec<SbomPackage> {
    let mut unique = BTreeMap::new();
    for package in packages {
        let normalized_purls = package
            .purls()
            .into_iter()
            .filter_map(|purl| package_ref_from_purl(purl, package.version.as_deref()))
            .map(|package_ref| package_ref_identity_key(&package_ref))
            .collect::<BTreeSet<_>>();
        // A PURL is authoritative for package identity. Without one, preserve
        // the component name exactly because its ecosystem (and therefore its
        // case rules) is unknown.
        let component_name = if normalized_purls.is_empty() {
            package.name.clone()
        } else {
            String::new()
        };
        let key = (
            component_name,
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
    components: Vec<CycloneDxComponent>,
    metadata: Option<CycloneDxMetadata>,
}

#[derive(Debug, Deserialize)]
struct SbomDocument {
    #[serde(default)]
    packages: Vec<SbomPackage>,
    #[serde(default)]
    components: Vec<CycloneDxComponent>,
    metadata: Option<CycloneDxMetadata>,
}

#[derive(Debug, Deserialize)]
struct CycloneDxMetadata {
    component: Option<CycloneDxComponent>,
}

#[derive(Debug, Deserialize)]
struct CycloneDxComponent {
    #[serde(flatten)]
    package: SbomPackage,
    #[serde(default)]
    components: Vec<CycloneDxComponent>,
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
            let key = package_ref_identity_key(&package_ref);
            normalized.entry(key).or_insert(package_ref);
        }
        normalized.into_values().collect()
    }
}

fn package_ref_identity_key(package_ref: &PackageRef) -> String {
    let suffix = package_ref
        .query_purl
        .find(['?', '#'])
        .map(|index| &package_ref.query_purl[index..])
        .unwrap_or_default();
    format!(
        "{}\u{1f}{}\u{1f}{}\u{1f}{}",
        ecosystem_identity_key(&package_ref.ecosystem),
        normalize_package_name(&package_ref.ecosystem, &package_ref.name),
        package_ref.version.as_deref().unwrap_or_default(),
        suffix
    )
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
struct SarifLog {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: Vec<SarifRun>,
}

#[derive(Debug, Serialize)]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
}

#[derive(Debug, Serialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Debug, Serialize)]
struct SarifDriver {
    name: &'static str,
    #[serde(rename = "semanticVersion")]
    semantic_version: &'static str,
    #[serde(rename = "informationUri")]
    information_uri: &'static str,
    rules: Vec<SarifRule>,
}

#[derive(Clone, Debug, Serialize)]
struct SarifRule {
    id: String,
    #[serde(rename = "shortDescription")]
    short_description: SarifMessage,
    #[serde(rename = "helpUri", skip_serializing_if = "Option::is_none")]
    help_uri: Option<String>,
    properties: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize)]
struct SarifMessage {
    text: String,
}

#[derive(Debug, Serialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: String,
    level: &'static str,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
    #[serde(rename = "partialFingerprints")]
    partial_fingerprints: BTreeMap<String, String>,
    properties: BTreeMap<String, Value>,
}

#[derive(Debug, Serialize)]
struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    physical_location: SarifPhysicalLocation,
}

#[derive(Debug, Serialize)]
struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    artifact_location: SarifArtifactLocation,
    region: SarifRegion,
}

#[derive(Debug, Serialize)]
struct SarifArtifactLocation {
    uri: String,
}

#[derive(Debug, Serialize)]
struct SarifRegion {
    #[serde(rename = "startLine")]
    start_line: u64,
}

impl SarifLog {
    fn from_report(report: &SbomReport, input_path: &Path) -> Self {
        let artifact_uri = sarif_artifact_uri(input_path);
        let mut rules = BTreeMap::<String, SarifRule>::new();
        let mut results = Vec::new();

        for finding in &report.findings {
            let rule_id = finding.cve.cve_id.clone();
            rules.entry(rule_id.clone()).or_insert_with(|| SarifRule {
                id: rule_id.clone(),
                short_description: SarifMessage {
                    text: nonempty_or(&finding.cve.title, "CVE vulnerability").to_owned(),
                },
                help_uri: Some(format!(
                    "https://www.cve.org/CVERecord?id={}",
                    finding.cve.cve_id
                )),
                properties: sarif_rule_properties("cve"),
            });
            let version = finding.version.as_deref().unwrap_or("unknown version");
            let identity = format!(
                "cve\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}",
                finding.package,
                version,
                finding.matched_purl.as_deref().unwrap_or_default(),
                finding.cve.cve_id
            );
            results.push(sarif_result(
                rule_id,
                "warning",
                format!(
                    "{} affects {} {}.",
                    finding.cve.cve_id, finding.package, version
                ),
                &artifact_uri,
                &identity,
                BTreeMap::from([
                    ("package".to_owned(), json!(finding.package)),
                    ("version".to_owned(), json!(finding.version)),
                    (
                        "matchedComponent".to_owned(),
                        json!(finding.matched_component),
                    ),
                    ("matchedPurl".to_owned(), json!(finding.matched_purl)),
                    ("versionMatch".to_owned(), json!(finding.version_match)),
                    ("publishedAt".to_owned(), json!(finding.cve.published_at)),
                    ("updatedAt".to_owned(), json!(finding.cve.updated_at)),
                ]),
            ));
        }

        for finding in &report.osv_findings {
            let rule_id = finding.finding.primary_id.clone();
            rules.entry(rule_id.clone()).or_insert_with(|| SarifRule {
                id: rule_id.clone(),
                short_description: SarifMessage {
                    text: "OSV vulnerability advisory".to_owned(),
                },
                help_uri: Some(format!(
                    "https://osv.dev/vulnerability/{}",
                    finding.finding.primary_id
                )),
                properties: sarif_rule_properties("osv"),
            });
            let version = finding.version.as_deref().unwrap_or("unknown version");
            let identity = format!(
                "osv\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}",
                finding.package, version, finding.matched_purl, finding.finding.primary_id
            );
            let fixed_suffix = if finding.finding.fixed_versions.is_empty() {
                String::new()
            } else {
                format!(
                    " Fixed versions: {}.",
                    finding.finding.fixed_versions.join(", ")
                )
            };
            results.push(sarif_result(
                rule_id,
                if finding.finding.priority_signals.known_exploited {
                    "error"
                } else {
                    "warning"
                },
                format!(
                    "{} affects {} {}.{}",
                    finding.finding.primary_id, finding.package, version, fixed_suffix
                ),
                &artifact_uri,
                &identity,
                BTreeMap::from([
                    ("package".to_owned(), json!(finding.package)),
                    ("version".to_owned(), json!(finding.version)),
                    ("matchedPurl".to_owned(), json!(finding.matched_purl)),
                    ("source".to_owned(), json!(finding.finding.source)),
                    ("cveIds".to_owned(), json!(finding.finding.cve_ids)),
                    ("aliases".to_owned(), json!(finding.finding.aliases)),
                    (
                        "fixedVersions".to_owned(),
                        json!(finding.finding.fixed_versions),
                    ),
                    (
                        "knownExploited".to_owned(),
                        json!(finding.finding.priority_signals.known_exploited),
                    ),
                    (
                        "epssPercentile".to_owned(),
                        json!(finding.finding.priority_signals.epss_percentile),
                    ),
                    (
                        "suggestedPriority".to_owned(),
                        json!(finding.finding.priority_signals.suggested_priority),
                    ),
                ]),
            ));
        }

        if let Some(findings) = &report.unverified_name_matches {
            for finding in findings {
                let rule_id = finding.cve.cve_id.clone();
                rules.entry(rule_id.clone()).or_insert_with(|| SarifRule {
                    id: rule_id.clone(),
                    short_description: SarifMessage {
                        text: nonempty_or(&finding.cve.title, "Unverified CVE match").to_owned(),
                    },
                    help_uri: Some(format!(
                        "https://www.cve.org/CVERecord?id={}",
                        finding.cve.cve_id
                    )),
                    properties: sarif_rule_properties("cve"),
                });
                let version = finding.version.as_deref().unwrap_or("unknown version");
                let identity = format!(
                    "unverified\u{1f}{}\u{1f}{}\u{1f}{}",
                    finding.package, version, finding.cve.cve_id
                );
                results.push(sarif_result(
                    rule_id,
                    "note",
                    format!(
                        "{} may match {} {}; the package version was not verified.",
                        finding.cve.cve_id, finding.package, version
                    ),
                    &artifact_uri,
                    &identity,
                    BTreeMap::from([
                        ("package".to_owned(), json!(finding.package)),
                        ("version".to_owned(), json!(finding.version)),
                        (
                            "matchedComponent".to_owned(),
                            json!(finding.matched_component),
                        ),
                        ("versionMatch".to_owned(), json!(finding.version_match)),
                    ]),
                ));
            }
        }

        if !report.unresolved_versions.is_empty() {
            let rule_id = "QANVULI-UNRESOLVED-VERSION".to_owned();
            rules.insert(
                rule_id.clone(),
                SarifRule {
                    id: rule_id.clone(),
                    short_description: SarifMessage {
                        text: "Package version could not be evaluated".to_owned(),
                    },
                    help_uri: None,
                    properties: sarif_rule_properties("review"),
                },
            );
            for unresolved in &report.unresolved_versions {
                let identity = format!(
                    "unresolved\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}",
                    unresolved.package,
                    unresolved.version,
                    unresolved.matched_purl,
                    unresolved.reason
                );
                results.push(sarif_result(
                    rule_id.clone(),
                    "note",
                    format!(
                        "Could not evaluate {} {}: {}.",
                        unresolved.package, unresolved.version, unresolved.reason
                    ),
                    &artifact_uri,
                    &identity,
                    BTreeMap::from([
                        ("package".to_owned(), json!(unresolved.package)),
                        ("version".to_owned(), json!(unresolved.version)),
                        ("matchedPurl".to_owned(), json!(unresolved.matched_purl)),
                        ("reason".to_owned(), json!(unresolved.reason)),
                    ]),
                ));
            }
        }

        Self {
            schema: "https://json.schemastore.org/sarif-2.1.0.json",
            version: "2.1.0",
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: "qanvuli",
                        semantic_version: env!("CARGO_PKG_VERSION"),
                        information_uri: "https://github.com/s-aran/qanvuli",
                        rules: rules.into_values().collect(),
                    },
                },
                results,
            }],
        }
    }
}

fn sarif_rule_properties(kind: &str) -> BTreeMap<String, Value> {
    BTreeMap::from([
        ("kind".to_owned(), json!(kind)),
        (
            "tags".to_owned(),
            json!(["security", "vulnerability", "dependency"]),
        ),
    ])
}

fn sarif_result(
    rule_id: String,
    level: &'static str,
    message: String,
    artifact_uri: &str,
    identity: &str,
    properties: BTreeMap<String, Value>,
) -> SarifResult {
    SarifResult {
        rule_id,
        level,
        message: SarifMessage { text: message },
        locations: vec![SarifLocation {
            physical_location: SarifPhysicalLocation {
                artifact_location: SarifArtifactLocation {
                    uri: artifact_uri.to_owned(),
                },
                region: SarifRegion { start_line: 1 },
            },
        }],
        partial_fingerprints: BTreeMap::from([(
            "primaryLocationLineHash".to_owned(),
            sarif_fingerprint(identity),
        )]),
        properties,
    }
}

fn sarif_fingerprint(identity: &str) -> String {
    let mut output = String::with_capacity(64);
    for byte in Sha256::digest(identity.as_bytes()) {
        write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

fn sarif_artifact_uri(input_path: &Path) -> String {
    let path = if input_path.is_absolute() {
        std::env::current_dir()
            .ok()
            .and_then(|directory| input_path.strip_prefix(directory).ok())
            .unwrap_or_else(|| input_path.file_name().map(Path::new).unwrap_or(input_path))
    } else {
        input_path
    };
    path.to_string_lossy().replace('\\', "/")
}

fn nonempty_or<'a>(value: &'a str, fallback: &'a str) -> &'a str {
    if value.trim().is_empty() {
        fallback
    } else {
        value
    }
}

fn write_sarif(path: &Path, report: &SarifLog) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(report)
        .map_err(|error| format!("failed to encode SARIF: {error}"))?;
    std::fs::write(path, bytes)
        .map_err(|error| format!("failed to write SARIF {}: {error}", path.display()))
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

fn version_evaluation_needs_review(status: &str) -> bool {
    !matches!(status, "affected" | "not_affected")
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PackageRef {
    ecosystem: String,
    name: String,
    version: Option<String>,
    purl: String,
    query_purl: String,
}

fn package_ref_from_purl(purl: &str, fallback_version: Option<&str>) -> Option<PackageRef> {
    let parsed = parse_package_purl(purl)?;
    Some(PackageRef {
        ecosystem: parsed.ecosystem,
        name: parsed.name,
        version: parsed.version.or_else(|| {
            fallback_version
                .filter(|version| !version.is_empty())
                .map(str::to_owned)
        }),
        purl: purl.to_owned(),
        query_purl: parsed.identity_purl,
    })
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
                query_purl: "pkg:cargo/mlua".to_owned(),
            })
        );
        assert_eq!(
            package_ref_from_purl("pkg:npm/%40scope/name@1.2.3", None)
                .unwrap()
                .name,
            "@scope/name"
        );
        let maven =
            package_ref_from_purl("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", None)
                .unwrap();
        assert_eq!(maven.name, "org.apache.logging.log4j:log4j-core");
        assert_eq!(
            maven.query_purl,
            "pkg:maven/org.apache.logging.log4j/log4j-core"
        );

        let scoped = package_ref_from_purl(
            "pkg://npm/%40scope/name@1.2.3%2Bbuild?download_url=https%3A%2F%2Fexample.invalid#lib",
            None,
        )
        .unwrap();
        assert_eq!(scoped.ecosystem, "npm");
        assert_eq!(scoped.name, "@scope/name");
        assert_eq!(scoped.version.as_deref(), Some("1.2.3+build"));
        assert_eq!(
            scoped.query_purl,
            "pkg:npm/%40scope/name?download_url=https:%2F%2Fexample.invalid#lib"
        );

        let remote_maven = package_ref_from_purl(
            "pkg:maven/org.example/core@1.0.0?repository_url=https%3A%2F%2Frepo.example%2Fmaven",
            None,
        )
        .unwrap();
        assert_eq!(remote_maven.ecosystem, "Maven:https://repo.example/maven");

        assert_eq!(
            package_ref_from_purl("pkg:npm/example?arch=x64", Some("2.0.0"))
                .unwrap()
                .version
                .as_deref(),
            Some("2.0.0")
        );
        assert!(package_ref_from_purl("pkg:npm/example@?arch=x64", Some("2.0.0")).is_none());
        assert!(package_ref_from_purl("npm/example@1.0.0", None).is_none());
        assert!(package_ref_from_purl("pkg:maven/org.example%2Fcore@1.0.0", None).is_none());
    }

    #[tokio::test]
    async fn missing_versions_and_invalid_purls_are_reported_for_review() {
        use qanvuli_core::database::SqlxDatabase;

        let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        database.initialize().await.unwrap();
        let missing = search_package(
            database.clone(),
            SbomPackage {
                name: "example".to_owned(),
                version: None,
                external_refs: Vec::new(),
                package_url: Some("pkg:npm/example".to_owned()),
            },
            DateFilter::new(None, None).unwrap(),
            CveStateScope::PublishedOnly,
            10,
            false,
            None,
        )
        .await
        .unwrap();
        assert_eq!(missing.unresolved_versions.len(), 1);
        assert_eq!(
            missing.unresolved_versions[0].reason,
            "installed version is missing"
        );

        let invalid = search_package(
            database.clone(),
            SbomPackage {
                name: "example".to_owned(),
                version: Some("1.0.0".to_owned()),
                external_refs: Vec::new(),
                package_url: Some("pkg:unknown/example@1.0.0".to_owned()),
            },
            DateFilter::new(None, None).unwrap(),
            CveStateScope::PublishedOnly,
            10,
            false,
            None,
        )
        .await
        .unwrap();
        assert_eq!(invalid.unresolved_versions.len(), 1);
        assert!(invalid.unresolved_versions[0].reason.contains("PURL"));

        let malformed = search_package(
            database,
            SbomPackage {
                name: "example".to_owned(),
                version: Some("1.0.0".to_owned()),
                external_refs: Vec::new(),
                package_url: Some("pkg:npm/ex%ZZample@1.0.0".to_owned()),
            },
            DateFilter::new(None, None).unwrap(),
            CveStateScope::PublishedOnly,
            10,
            false,
            None,
        )
        .await
        .unwrap();
        assert_eq!(malformed.unresolved_versions.len(), 1);
    }

    #[tokio::test]
    async fn maven_sbom_purl_matches_osv_coordinate_and_version_range() {
        use qanvuli_core::database::{OsvRawRecord, SqlxDatabase};

        let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        database.initialize().await.unwrap();
        database
            .import_osv_record(OsvRawRecord {
                source_path: None,
                raw_json: r#"{"schema_version":"1.8.0","id":"GHSA-2099-maven","modified":"2099-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"Maven","name":"org.example:core","purl":"pkg:maven/org.example/core"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]}]}"#.to_owned(),
            })
            .await
            .unwrap();
        let package = package_ref_from_purl("pkg:maven/org.example/core@1.5.0", None).unwrap();

        let findings = database
            .query_package_matches(
                &package.ecosystem,
                &package.name,
                package.version.as_deref().unwrap(),
                Some(&package.query_purl),
            )
            .await
            .unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].affected.status, "affected");
    }

    #[tokio::test]
    async fn cve_list_unsupported_version_is_reported_for_review() {
        use qanvuli_core::database::SqlxDatabase;

        let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
        database.initialize().await.unwrap();
        database
            .import_cve_raw_json(
                r#"{"cveMetadata":{"cveId":"CVE-2099-sbom-review","state":"PUBLISHED","datePublished":"2099-01-01T00:00:00Z","dateUpdated":"2099-01-02T00:00:00Z"},"containers":{"cna":{"title":"review","affected":[{"vendor":"example","product":"example","packageName":"example","collectionURL":"https://pypi.org/project/example","versions":[{"version":"0","status":"affected","lessThan":"2.0.0"}]}]}}}"#
                    .to_owned(),
            )
            .await
            .unwrap();

        let result = search_package(
            database,
            SbomPackage {
                name: "example".to_owned(),
                version: Some("1.0.0".to_owned()),
                external_refs: Vec::new(),
                package_url: Some("pkg:pypi/example@1.0.0".to_owned()),
            },
            DateFilter::new(None, None).unwrap(),
            CveStateScope::PublishedOnly,
            10,
            false,
            None,
        )
        .await
        .unwrap();

        assert!(result.cve_findings.is_empty());
        assert!(result.osv_findings.is_empty());
        assert_eq!(result.unresolved_versions.len(), 1);
        assert!(
            result.unresolved_versions[0]
                .reason
                .contains("CVE-2099-sbom-review")
        );
        assert!(
            result.unresolved_versions[0]
                .reason
                .contains("unsupported_version_scheme")
        );
    }

    #[test]
    fn maps_every_advertised_purl_ecosystem() {
        for (purl, ecosystem) in [
            ("pkg:cargo/example", "crates.io"),
            ("pkg:gem/example", "RubyGems"),
            ("pkg:github/owner/repository", "GitHub Actions"),
            ("pkg:golang/example.com/module", "Go"),
            ("pkg:maven/org.example/artifact", "Maven"),
            ("pkg:npm/example", "npm"),
            ("pkg:nuget/example", "NuGet"),
            ("pkg:pypi/example", "PyPI"),
            ("pkg:pub/example", "Pub"),
        ] {
            assert_eq!(
                package_ref_from_purl(purl, None).map(|package| package.ecosystem),
                Some(ecosystem.to_owned())
            );
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
        assert!(package_ref_from_purl("pkg:npm/%FF@1.2.3", None).is_none());
    }

    #[test]
    fn distinguishes_concrete_versions_from_constraints() {
        assert!(is_concrete_package_version("PyPI", "1!2.0"));
        assert!(is_concrete_package_version("npm", "7.25.9"));
        assert!(!is_concrete_package_version("PyPI", "!=2.0"));
        assert!(!is_concrete_package_version("npm", ">=2.2.1,<3"));
    }

    #[test]
    fn fixed_versions_are_not_reported_as_unresolved() {
        assert!(!version_evaluation_needs_review("affected"));
        assert!(!version_evaluation_needs_review("not_affected"));
        assert!(version_evaluation_needs_review("unknown"));
        assert!(version_evaluation_needs_review(
            "unsupported_version_scheme"
        ));
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
    fn loads_nested_cyclonedx_components_recursively() {
        let mut json = br#"{
            "bomFormat": "CycloneDX",
            "components": [{
                "name": "application",
                "version": "1.0.0",
                "purl": "pkg:npm/application@1.0.0",
                "components": [{
                    "name": "dependency",
                    "version": "2.0.0",
                    "purl": "pkg:npm/dependency@2.0.0",
                    "components": [{
                        "name": "transitive",
                        "version": "3.0.0",
                        "purl": "pkg:npm/transitive@3.0.0"
                    }]
                }]
            }]
        }"#
        .to_vec();

        let packages = load_sbom_packages_from_slice(&mut json).unwrap();
        assert_eq!(
            packages
                .iter()
                .map(|package| package.name.as_str())
                .collect::<Vec<_>>(),
            vec!["application", "dependency", "transitive"]
        );
    }

    #[test]
    fn loads_cyclonedx_metadata_root_and_unknown_fields() {
        let mut json = br#"{
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "unknownRootField": {"harmless": true},
            "metadata": {
                "unknownMetadataField": [1, 2, 3],
                "component": {
                    "name": "application",
                    "version": "1.0.0",
                    "purl": "pkg:npm/application@1.0.0",
                    "unknownComponentField": "ignored"
                }
            }
        }"#
        .to_vec();

        let packages = load_sbom_packages_from_slice(&mut json).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "application");
    }

    #[test]
    fn loads_nested_components_below_cyclonedx_metadata_root() {
        let mut json = br#"{
            "bomFormat": "CycloneDX",
            "metadata": {
                "component": {
                    "name": "application",
                    "version": "1.0.0",
                    "purl": "pkg:npm/application@1.0.0",
                    "components": [{
                        "name": "dependency",
                        "version": "2.0.0",
                        "purl": "pkg:npm/dependency@2.0.0"
                    }]
                }
            }
        }"#
        .to_vec();

        let packages = load_sbom_packages_from_slice(&mut json).unwrap();
        assert_eq!(
            packages
                .iter()
                .map(|package| package.name.as_str())
                .collect::<Vec<_>>(),
            vec!["application", "dependency"]
        );
    }

    #[test]
    fn cyclonedx_metadata_and_top_level_duplicates_share_one_query() {
        let mut json = br#"{
            "bomFormat": "CycloneDX",
            "metadata": {
                "component": {
                    "name": "application",
                    "version": "1.0.0",
                    "purl": "pkg:npm/application@1.0.0"
                }
            },
            "components": [{
                "name": "application duplicate",
                "version": "1.0.0",
                "purl": "pkg:npm/application@1.0.0"
            }]
        }"#
        .to_vec();

        let packages = load_sbom_packages_from_slice(&mut json).unwrap();
        assert_eq!(packages.len(), 2, "component_count");
        let packages = deduplicate_sbom_packages(packages);
        assert_eq!(packages.len(), 1, "unique_component_count");
        assert_eq!(
            packages
                .iter()
                .flat_map(SbomPackage::package_refs)
                .filter(|package_ref| {
                    package_ref.version.as_deref().is_some_and(|version| {
                        is_concrete_package_version(&package_ref.ecosystem, version)
                    })
                })
                .count(),
            1,
            "package_query_count"
        );
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
    fn deduplication_respects_each_ecosystems_name_and_variant_rules() {
        let packages = vec![
            SbomPackage {
                name: "Friendly_Bard".to_owned(),
                version: Some("1.0".to_owned()),
                external_refs: Vec::new(),
                package_url: Some("pkg:pypi/Friendly_Bard@1.0".to_owned()),
            },
            SbomPackage {
                name: "friendly-bard".to_owned(),
                version: Some("1.0".to_owned()),
                external_refs: Vec::new(),
                package_url: Some("pkg:pypi/friendly-bard@1.0".to_owned()),
            },
            SbomPackage {
                name: "org.example:Core".to_owned(),
                version: Some("1.0.0".to_owned()),
                external_refs: Vec::new(),
                package_url: Some("pkg:maven/org.example/Core@1.0.0".to_owned()),
            },
            SbomPackage {
                name: "org.example:core".to_owned(),
                version: Some("1.0.0".to_owned()),
                external_refs: Vec::new(),
                package_url: Some("pkg:maven/org.example/core@1.0.0".to_owned()),
            },
        ];

        let unique = deduplicate_sbom_packages(packages);
        assert_eq!(
            unique.len(),
            3,
            "PyPI aliases merge; Maven case variants do not"
        );

        let variants = SbomPackage {
            name: "example".to_owned(),
            version: Some("1.0.0".to_owned()),
            external_refs: vec![
                SbomExternalRef {
                    reference_type: Some("purl".to_owned()),
                    reference_locator: Some("pkg:gem/example@1.0.0?platform=ruby".to_owned()),
                },
                SbomExternalRef {
                    reference_type: Some("purl".to_owned()),
                    reference_locator: Some("pkg:gem/example@1.0.0?platform=java".to_owned()),
                },
            ],
            package_url: None,
        };
        assert_eq!(variants.package_refs().len(), 2);

        let equivalent_spellings = SbomPackage {
            name: "example".to_owned(),
            version: Some("1.0.0".to_owned()),
            external_refs: vec![
                SbomExternalRef {
                    reference_type: Some("purl".to_owned()),
                    reference_locator: Some(
                        "pkg://NPM/example@1.0.0?OS=linux&arch=x64#/lib/".to_owned(),
                    ),
                },
                SbomExternalRef {
                    reference_type: Some("purl".to_owned()),
                    reference_locator: Some(
                        "pkg:npm/example@1.0.0?arch=x64&os=linux#lib".to_owned(),
                    ),
                },
            ],
            package_url: None,
        };
        assert_eq!(equivalent_spellings.package_refs().len(), 1);
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
                    purl: Some(package.query_purl),
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
