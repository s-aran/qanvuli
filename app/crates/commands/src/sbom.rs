use super::common::{DEFAULT_LIMIT, DateFilter, connect_db, print_json};
use qanvuli_db::{CveStateScope, CveSummary, EnrichedFinding};
use serde::{Deserialize, Serialize};
use simd_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

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
    #[arg(long)]
    include_rejected: bool,
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

pub async fn run(db_url: &str, args: Args) -> Result<(), String> {
    let db = connect_db(db_url).await?;
    db.initialize_schema()
        .await
        .map_err(|err| format!("failed to initialize schema: {err}"))?;
    let date_filter = args.date_filter()?;
    let packages = load_sbom_packages(args.path()?)?;
    let package_count = packages.len();
    let mut cve_findings = BTreeMap::<String, SbomCveFinding>::new();
    let mut osv_findings = BTreeMap::<String, SbomOsvFinding>::new();
    let per_package_limit = args.per_package_limit.unwrap_or(DEFAULT_LIMIT);
    let state_scope = if args.include_rejected {
        CveStateScope::IncludeRejected
    } else {
        CveStateScope::PublishedOnly
    };

    for package in packages {
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
                let key = format!("{}:{}", package.name, cve.cve_id);
                cve_findings.entry(key).or_insert_with(|| SbomCveFinding {
                    package: package.name.clone(),
                    version: package.version.clone(),
                    matched_component: component.clone(),
                    cve,
                });
            }
        }

        for purl in package.purls() {
            let Some(package_ref) = package_ref_from_purl(purl, package.version.as_deref()) else {
                continue;
            };
            let Some(version) = package_ref.version.as_deref() else {
                continue;
            };
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
                let key = format!("{}:{}", package.name, finding.primary_id);
                osv_findings.entry(key).or_insert_with(|| SbomOsvFinding {
                    package: package.name.clone(),
                    version: package.version.clone(),
                    matched_purl: package_ref.purl.clone(),
                    finding,
                });
            }
        }
    }

    let cve_findings = cve_findings.into_values().collect::<Vec<_>>();
    let osv_findings = osv_findings.into_values().collect::<Vec<_>>();
    print_json(&json!({
        "vulnerable": !cve_findings.is_empty() || !osv_findings.is_empty(),
        "package_count": package_count,
        "count": cve_findings.len() + osv_findings.len(),
        "cve_count": cve_findings.len(),
        "osv_count": osv_findings.len(),
        "findings": cve_findings,
        "osv_findings": osv_findings,
    }))?;

    db.close()
        .await
        .map_err(|err| format!("failed to close database: {err}"))?;
    Ok(())
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
    cve: CveSummary,
}

#[derive(Debug, Serialize)]
struct SbomOsvFinding {
    package: String,
    version: Option<String>,
    matched_purl: String,
    finding: EnrichedFinding,
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
    let name = percent_decode_minimal(name_path);
    if name.is_empty() {
        return None;
    }

    Some(PackageRef {
        ecosystem: ecosystem.to_owned(),
        name,
        version: purl_version
            .or(fallback_version)
            .map(percent_decode_minimal)
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

fn percent_decode_minimal(value: &str) -> String {
    let mut decoded = String::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && let Ok(hex) = std::str::from_utf8(&bytes[index + 1..index + 3])
            && let Ok(byte) = u8::from_str_radix(hex, 16)
        {
            decoded.push(byte as char);
            index += 3;
            continue;
        }
        decoded.push(bytes[index] as char);
        index += 1;
    }
    decoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_github_spdx_sbom_sample() {
        let mut json = include_bytes!("../../../../sbom_sample.json").to_vec();
        let packages = load_sbom_packages_from_slice(&mut json).unwrap();

        assert_eq!(packages.len(), 8);
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
