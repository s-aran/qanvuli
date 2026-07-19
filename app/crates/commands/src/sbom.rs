use super::common::{DEFAULT_LIMIT, DateFilter, close_db, connect_db, print_json};
use qanvuli_core::database::{CveStateScope, CveSummary, EnrichedFinding};
use serde::{Deserialize, Serialize};
use simd_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use tokio::task::JoinSet;

const MAX_DEFAULT_SBOM_SEARCH_CONCURRENCY: usize = 16;

/// CLI arguments for `qanvuli sbom`.
#[derive(Debug, clap::Args)]
pub struct Args {
    #[arg(long = "file", value_name = "PATH")]
    file: Option<PathBuf>,
    #[arg(value_name = "PATH")]
    path: Option<PathBuf>,
    #[arg(long)]
    published_since: Option<String>,
    #[arg(long, alias = "since")]
    updated_since: Option<String>,
    #[arg(long)]
    per_package_limit: Option<u64>,
    /// Maximum number of packages searched concurrently.
    #[arg(short = 'j', long, value_name = "N")]
    jobs: Option<usize>,
    #[arg(long)]
    include_rejected: bool,
    /// Include unverified text-name matches. These never affect vulnerability counts.
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
    let jobs = args.jobs.unwrap_or_else(default_search_concurrency);
    if jobs == 0 {
        return Err("--jobs must be at least 1".to_owned());
    }
    let db = connect_db(db_url).await?;
    db.initialize_schema()
        .await
        .map_err(|err| format!("failed to initialize schema: {err}"))?;
    let date_filter = args.date_filter()?;
    let packages = load_sbom_packages(args.path()?)?;
    let package_count = packages.len();
    let mut cve_findings = BTreeMap::<(String, String, String), SbomCveFinding>::new();
    let mut osv_findings = BTreeMap::<(String, String, String, String), SbomOsvFinding>::new();
    let mut unverified_name_matches = BTreeMap::<(String, String, String), SbomCveFinding>::new();
    let mut unresolved_versions = BTreeSet::new();
    let per_package_limit = args.per_package_limit.unwrap_or(DEFAULT_LIMIT);
    let state_scope = CveStateScope::from_include_rejected(args.include_rejected);

    eprintln!("sbom: searching {package_count} packages with up to {jobs} concurrent searches");
    let mut pending = JoinSet::new();
    let mut packages = packages.into_iter().enumerate();
    let mut completed = 0usize;
    while pending.len() < jobs {
        let Some((index, package)) = packages.next() else {
            break;
        };
        start_package_search(
            &mut pending,
            db.clone(),
            package,
            index + 1,
            package_count,
            date_filter.clone(),
            state_scope,
            per_package_limit,
            args.include_name_matches,
        );
    }
    while let Some(result) = pending.join_next().await {
        let result = result.map_err(|err| format!("SBOM search task failed: {err}"))??;
        completed += 1;
        eprintln!(
            "sbom: [{completed}/{package_count}] completed {} (CVE={}, OSV={})",
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
        if let Some((index, package)) = packages.next() {
            start_package_search(
                &mut pending,
                db.clone(),
                package,
                index + 1,
                package_count,
                date_filter.clone(),
                state_scope,
                per_package_limit,
                args.include_name_matches,
            );
        }
    }

    let cve_findings = cve_findings.into_values().collect::<Vec<_>>();
    let osv_findings = osv_findings.into_values().collect::<Vec<_>>();
    let unverified_name_matches = unverified_name_matches.into_values().collect::<Vec<_>>();
    eprintln!(
        "sbom: completed {package_count} packages; findings={}",
        cve_findings.len() + osv_findings.len()
    );
    print_json(&json!({
        "vulnerable": !cve_findings.is_empty() || !osv_findings.is_empty(),
        "package_count": package_count,
        "count": cve_findings.len() + osv_findings.len(),
        "cve_count": cve_findings.len(),
        "osv_count": osv_findings.len(),
        "findings": cve_findings,
        "osv_findings": osv_findings,
        "unverified_name_matches": if args.include_name_matches { Some(unverified_name_matches) } else { None },
        "unresolved_versions": unresolved_versions,
    }))?;

    close_db(db).await?;
    Ok(())
}

fn default_search_concurrency() -> usize {
    std::thread::available_parallelism()
        .map(|parallelism| parallelism.get().saturating_mul(2))
        .unwrap_or(1)
        .clamp(1, MAX_DEFAULT_SBOM_SEARCH_CONCURRENCY)
}

#[allow(clippy::too_many_arguments)]
fn start_package_search(
    pending: &mut JoinSet<Result<PackageSearchResult, String>>,
    db: qanvuli_core::database::CveDatabase,
    package: SbomPackage,
    index: usize,
    total: usize,
    date_filter: DateFilter,
    state_scope: CveStateScope,
    per_package_limit: u64,
    include_name_matches: bool,
) {
    eprintln!("sbom: [{index}/{total}] searching {}", package.name);
    pending.spawn(search_package(
        db,
        package,
        date_filter,
        state_scope,
        per_package_limit,
        include_name_matches,
    ));
}

struct PackageSearchResult {
    package_name: String,
    cve_findings: Vec<SbomCveFinding>,
    osv_findings: Vec<SbomOsvFinding>,
    unverified_name_matches: Vec<SbomCveFinding>,
    unresolved_versions: Vec<UnresolvedVersion>,
}

async fn search_package(
    db: qanvuli_core::database::CveDatabase,
    package: SbomPackage,
    date_filter: DateFilter,
    state_scope: CveStateScope,
    per_package_limit: u64,
    include_name_matches: bool,
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
        let Some(package_ref) = package_ref_from_purl(purl, package.version.as_deref()) else {
            continue;
        };
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
        let findings = db
            .query_package_enriched(
                &package_ref.ecosystem,
                &package_ref.name,
                version,
                Some(&package_ref.purl),
            )
            .await
            .map_err(|err| format!("failed to query package `{}`: {err}", package.name))?;
        for finding in findings {
            if finding.affected.status == "affected" {
                for cve_id in &finding.cve_ids {
                    let Some(cve) = db
                        .find_cve_summary_with_detail_with_state_scope(cve_id, state_scope)
                        .await
                        .map_err(|err| format!("failed to load {cve_id}: {err}"))?
                    else {
                        continue;
                    };
                    cve_findings.push(SbomCveFinding {
                        package: package.name.clone(),
                        version: package_ref.version.clone(),
                        matched_component: package_ref.name.clone(),
                        matched_purl: Some(package_ref.purl.clone()),
                        version_match: CveVersionMatch::OsvRangeMatched,
                        cve: cve.summary,
                    });
                }
            }
            if finding.affected.status == "affected" {
                osv_findings.push(SbomOsvFinding {
                    package: package.name.clone(),
                    version: package_ref.version.clone(),
                    matched_purl: package_ref.purl.clone(),
                    finding,
                });
            }
        }
    }

    Ok(PackageSearchResult {
        package_name: package.name.clone(),
        cve_findings,
        osv_findings,
        unverified_name_matches,
        unresolved_versions,
    })
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
    fn default_search_concurrency_is_nonzero_and_bounded() {
        assert!((1..=MAX_DEFAULT_SBOM_SEARCH_CONCURRENCY).contains(&default_search_concurrency()));
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
}
