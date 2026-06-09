use super::common::{DEFAULT_LIMIT, DateFilter, connect_db, print_json};
use qanvuli_db::CveSummary;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
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
    let date_filter = args.date_filter()?;
    let packages = load_sbom_packages(args.path()?)?;
    let mut findings = BTreeMap::<String, SbomFinding>::new();
    let per_package_limit = args.per_package_limit.unwrap_or(DEFAULT_LIMIT);

    for package in packages {
        for component in package.search_names() {
            let cves = db
                .search_cve_summaries_by_affected_component(
                    None,
                    &component,
                    date_filter.published_since.as_deref(),
                    date_filter.updated_since.as_deref(),
                    per_package_limit,
                    0,
                )
                .await
                .map_err(|err| format!("failed to search `{component}`: {err}"))?;

            for cve in cves {
                let key = format!("{}:{}", package.name, cve.cve_id);
                findings.entry(key).or_insert_with(|| SbomFinding {
                    package: package.name.clone(),
                    version: package.version.clone(),
                    matched_component: component.clone(),
                    cve,
                });
            }
        }
    }

    let findings = findings.into_values().collect::<Vec<_>>();
    print_json(&json!({
        "vulnerable": !findings.is_empty(),
        "count": findings.len(),
        "findings": findings,
    }))?;

    db.close()
        .await
        .map_err(|err| format!("failed to close database: {err}"))?;
    Ok(())
}

fn load_sbom_packages(path: &Path) -> Result<Vec<SbomPackage>, String> {
    let json = std::fs::read_to_string(path)
        .map_err(|err| format!("failed to read SBOM {}: {err}", path.display()))?;
    let sbom: GitHubSbom =
        serde_json::from_str(&json).map_err(|err| format!("failed to parse SBOM JSON: {err}"))?;
    let packages = sbom
        .sbom
        .map(|sbom| sbom.packages)
        .filter(|packages| !packages.is_empty())
        .unwrap_or(sbom.packages);

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
}

#[derive(Debug, Deserialize)]
struct SbomDocument {
    #[serde(default)]
    packages: Vec<SbomPackage>,
}

#[derive(Clone, Debug, Deserialize)]
struct SbomPackage {
    name: String,
    #[serde(rename = "versionInfo", alias = "version")]
    version: Option<String>,
    #[serde(default, rename = "externalRefs")]
    external_refs: Vec<SbomExternalRef>,
}

impl SbomPackage {
    fn search_names(&self) -> Vec<String> {
        let mut names = vec![self.name.clone()];

        for purl in self.external_refs.iter().filter_map(SbomExternalRef::purl) {
            if let Some(name) = package_name_from_purl(purl) {
                names.push(name);
            }
        }

        names.sort();
        names.dedup();
        names
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
struct SbomFinding {
    package: String,
    version: Option<String>,
    matched_component: String,
    cve: CveSummary,
}

fn package_name_from_purl(purl: &str) -> Option<String> {
    let body = purl.strip_prefix("pkg:").unwrap_or(purl);
    let without_qualifiers = body.split(['?', '#']).next().unwrap_or(body);
    let without_version =
        without_qualifiers
            .rsplit_once('@')
            .map_or(without_qualifiers, |(package, _version)| {
                if package.is_empty() {
                    without_qualifiers
                } else {
                    package
                }
            });
    let name = without_version
        .split('/')
        .next_back()
        .map(percent_decode_minimal)?;

    if name.is_empty() { None } else { Some(name) }
}

fn percent_decode_minimal(value: &str) -> String {
    let mut decoded = String::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let Ok(hex) = std::str::from_utf8(&bytes[index + 1..index + 3]) {
                if let Ok(byte) = u8::from_str_radix(hex, 16) {
                    decoded.push(byte as char);
                    index += 3;
                    continue;
                }
            }
        }
        decoded.push(bytes[index] as char);
        index += 1;
    }
    decoded
}
