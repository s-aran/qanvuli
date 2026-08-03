use serde_json::{Value, json};
use std::{
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

struct TemporarySbomFixture {
    database_path: PathBuf,
    database_url: String,
    sbom_path: PathBuf,
    sarif_path: PathBuf,
}

impl Drop for TemporarySbomFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.sbom_path);
        let _ = std::fs::remove_file(&self.sarif_path);
        let _ = std::fs::remove_file(&self.database_path);
        let _ = std::fs::remove_file(self.database_path.with_extension("sqlite-shm"));
        let _ = std::fs::remove_file(self.database_path.with_extension("sqlite-wal"));
    }
}

async fn vulnerable_npm_sbom_fixture() -> TemporarySbomFixture {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after the Unix epoch")
        .as_nanos();
    let stem = format!("qanvuli-sbom-cli-{}-{nonce}", std::process::id());
    let database_path = std::env::temp_dir().join(format!("{stem}.sqlite"));
    let database_url = format!("sqlite://{}?mode=rwc", database_path.display());
    let sbom_path = std::env::temp_dir().join(format!("{stem}.spdx.json"));
    let sarif_path = std::env::temp_dir().join(format!("{stem}.sarif"));

    let database = qanvuli_core::database::SqlxDatabase::connect(&database_url)
        .await
        .expect("temporary SBOM database should open");
    database
        .initialize()
        .await
        .expect("temporary SBOM database should initialize");
    database
        .import_osv_record(qanvuli_core::database::OsvRawRecord {
            source_path: None,
            raw_json: json!({
                "schema_version": "1.8.0",
                "id": "GHSA-2099-sbom-cli",
                "modified": "2099-01-01T00:00:00Z",
                "summary": "SBOM CLI integration fixture",
                "affected": [{
                    "package": {
                        "ecosystem": "npm",
                        "name": "node-forge",
                        "purl": "pkg:npm/node-forge"
                    },
                    "ranges": [{
                        "type": "SEMVER",
                        "events": [
                            { "introduced": "0" },
                            { "fixed": "2.0.0" }
                        ]
                    }]
                }]
            })
            .to_string(),
        })
        .await
        .expect("OSV fixture should import");
    database
        .close()
        .await
        .expect("temporary SBOM database should close");

    let sbom = json!({
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "qanvuli SBOM CLI integration fixture",
        "dataLicense": "CC0-1.0",
        "documentNamespace": format!("https://example.invalid/qanvuli/{stem}"),
        "packages": [{
            "name": "node-forge",
            "SPDXID": "SPDXRef-Package-node-forge",
            "versionInfo": "1.5.0",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": false,
            "externalRefs": [{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": "pkg:npm/node-forge@1.5.0"
            }]
        }]
    });
    std::fs::write(
        &sbom_path,
        serde_json::to_vec_pretty(&sbom).expect("SBOM fixture should serialize"),
    )
    .expect("SBOM fixture should be written");

    TemporarySbomFixture {
        database_path,
        database_url,
        sbom_path,
        sarif_path,
    }
}

async fn custom_sbom_fixture(label: &str, advisory: Value, sbom: Value) -> TemporarySbomFixture {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after the Unix epoch")
        .as_nanos();
    let stem = format!("qanvuli-sbom-cli-{label}-{}-{nonce}", std::process::id());
    let database_path = std::env::temp_dir().join(format!("{stem}.sqlite"));
    let database_url = format!("sqlite://{}?mode=rwc", database_path.display());
    let sbom_path = std::env::temp_dir().join(format!("{stem}.json"));
    let sarif_path = std::env::temp_dir().join(format!("{stem}.sarif"));

    let database = qanvuli_core::database::SqlxDatabase::connect(&database_url)
        .await
        .expect("temporary SBOM database should open");
    database
        .initialize()
        .await
        .expect("temporary SBOM database should initialize");
    database
        .import_osv_record(qanvuli_core::database::OsvRawRecord {
            source_path: None,
            raw_json: advisory.to_string(),
        })
        .await
        .expect("OSV fixture should import");
    database
        .close()
        .await
        .expect("temporary SBOM database should close");
    std::fs::write(
        &sbom_path,
        serde_json::to_vec_pretty(&sbom).expect("SBOM fixture should serialize"),
    )
    .expect("SBOM fixture should be written");

    TemporarySbomFixture {
        database_path,
        database_url,
        sbom_path,
        sarif_path,
    }
}

fn run_sbom_fixture(fixture: &TemporarySbomFixture) -> (Value, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_qanvuli"))
        .args(["--db-url", &fixture.database_url, "sbom", "--file"])
        .arg(&fixture.sbom_path)
        .output()
        .expect("SBOM CLI process should start");
    let stdout = String::from_utf8(output.stdout).expect("SBOM stdout should be UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("SBOM stderr should be UTF-8");
    assert!(
        output.status.success(),
        "SBOM CLI failed with {}\nstderr:\n{stderr}\nstdout:\n{stdout}",
        output.status
    );
    let report = serde_json::from_str(&stdout)
        .unwrap_or_else(|error| panic!("SBOM CLI returned invalid JSON: {error}\n{stdout}"));
    (report, stderr)
}

#[tokio::test(flavor = "current_thread")]
async fn sbom_cli_reports_vulnerability_from_spdx_purl_and_osv_semver_range() {
    let fixture = vulnerable_npm_sbom_fixture().await;
    let output = Command::new(env!("CARGO_BIN_EXE_qanvuli"))
        .args(["--db-url", &fixture.database_url, "sbom", "--file"])
        .arg(&fixture.sbom_path)
        .output()
        .expect("SBOM CLI process should start");

    let stdout = String::from_utf8(output.stdout).expect("SBOM stdout should be UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("SBOM stderr should be UTF-8");
    assert!(
        output.status.success(),
        "SBOM CLI failed with {}\nstderr:\n{stderr}\nstdout:\n{stdout}",
        output.status
    );

    let report: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|error| panic!("SBOM CLI returned invalid JSON: {error}\n{stdout}"));
    assert_eq!(report.get("vulnerable"), Some(&Value::Bool(true)));
    assert_eq!(report.get("component_count"), Some(&Value::from(1)));
    assert_eq!(report.get("unique_component_count"), Some(&Value::from(1)));
    assert_eq!(report.get("package_query_count"), Some(&Value::from(1)));
    assert_eq!(report.get("count"), Some(&Value::from(1)));
    assert_eq!(report.get("cve_count"), Some(&Value::from(0)));
    assert_eq!(report.get("osv_count"), Some(&Value::from(1)));
    assert_eq!(
        report
            .pointer("/osv_findings/0/finding/primary_id")
            .and_then(Value::as_str),
        Some("GHSA-2099-sbom-cli")
    );
    assert_eq!(
        report
            .pointer("/osv_findings/0/finding/affected/status")
            .and_then(Value::as_str),
        Some("affected")
    );
    assert_eq!(
        report
            .pointer("/osv_findings/0/matched_purl")
            .and_then(Value::as_str),
        Some("pkg:npm/node-forge@1.5.0")
    );
    assert_eq!(
        report
            .get("unresolved_versions")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(0)
    );
    assert!(
        stderr.contains("sbom: completed 1/1 unique components"),
        "SBOM progress did not reach completion: {stderr}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn sbom_cli_writes_sarif_and_keeps_json_on_stdout() {
    let fixture = vulnerable_npm_sbom_fixture().await;
    let output = Command::new(env!("CARGO_BIN_EXE_qanvuli"))
        .args(["--db-url", &fixture.database_url, "sbom", "--file"])
        .arg(&fixture.sbom_path)
        .arg("--sarif-output")
        .arg(&fixture.sarif_path)
        .output()
        .expect("SBOM CLI process should start");

    let stdout = String::from_utf8(output.stdout).expect("SBOM stdout should be UTF-8");
    let stderr = String::from_utf8(output.stderr).expect("SBOM stderr should be UTF-8");
    assert!(
        output.status.success(),
        "SBOM CLI failed with {}\nstderr:\n{stderr}\nstdout:\n{stdout}",
        output.status
    );

    let json_report: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|error| panic!("SBOM CLI returned invalid JSON: {error}\n{stdout}"));
    assert_eq!(json_report["osv_count"], 1);

    let sarif: Value = serde_json::from_slice(
        &std::fs::read(&fixture.sarif_path).expect("SARIF output should be written"),
    )
    .expect("SARIF output should be JSON");
    assert_eq!(sarif["version"], "2.1.0");
    assert_eq!(sarif["runs"][0]["tool"]["driver"]["name"], "qanvuli");
    assert_eq!(
        sarif["runs"][0]["results"][0]["ruleId"],
        "GHSA-2099-sbom-cli"
    );
    assert_eq!(sarif["runs"][0]["results"][0]["level"], "warning");
    assert_eq!(
        sarif["runs"][0]["results"][0]["properties"]["matchedPurl"],
        "pkg:npm/node-forge@1.5.0"
    );
    assert!(
        sarif["runs"][0]["results"][0]["partialFingerprints"]["primaryLocationLineHash"]
            .as_str()
            .is_some_and(|value| value.len() == 64)
    );
    assert_eq!(
        sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"],
        1
    );
    assert!(stderr.contains("sbom: wrote SARIF report to"));
}

#[tokio::test(flavor = "current_thread")]
async fn sbom_cli_accepts_pypi_epoch_and_detects_osv_advisory() {
    let fixture = custom_sbom_fixture(
        "pypi-epoch",
        json!({
            "schema_version": "1.8.0",
            "id": "PYSEC-2099-EPOCH",
            "modified": "2099-01-01T00:00:00Z",
            "affected": [{
                "package": {"ecosystem": "PyPI", "name": "example"},
                "ranges": [{
                    "type": "ECOSYSTEM",
                    "events": [
                        {"introduced": "1!1.0"},
                        {"fixed": "1!3.0"}
                    ]
                }]
            }]
        }),
        json!({
            "spdxVersion": "SPDX-2.3",
            "packages": [{
                "name": "example",
                "versionInfo": "1!2.0",
                "externalRefs": [{
                    "referenceType": "purl",
                    "referenceLocator": "pkg:pypi/example@1!2.0"
                }]
            }]
        }),
    )
    .await;

    let (report, _) = run_sbom_fixture(&fixture);
    assert_eq!(report["package_query_count"], 1);
    assert_eq!(report["osv_count"], 1);
    assert_eq!(
        report["osv_findings"][0]["finding"]["primary_id"],
        "PYSEC-2099-EPOCH"
    );
    assert_eq!(report["unresolved_versions"], json!([]));
}

#[tokio::test(flavor = "current_thread")]
async fn sbom_cli_keeps_pypi_not_equal_constraint_unresolved() {
    let fixture = custom_sbom_fixture(
        "pypi-constraint",
        json!({
            "schema_version": "1.8.0",
            "id": "PYSEC-2099-CONSTRAINT",
            "modified": "2099-01-01T00:00:00Z",
            "affected": [{
                "package": {"ecosystem": "PyPI", "name": "example"},
                "ranges": [{
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}]
                }]
            }]
        }),
        json!({
            "spdxVersion": "SPDX-2.3",
            "packages": [{
                "name": "example",
                "versionInfo": "!=2.0",
                "externalRefs": [{
                    "referenceType": "purl",
                    "referenceLocator": "pkg:pypi/example@!=2.0"
                }]
            }]
        }),
    )
    .await;

    let (report, _) = run_sbom_fixture(&fixture);
    assert_eq!(report["package_query_count"], 0);
    assert_eq!(report["count"], 0);
    assert_eq!(
        report["unresolved_versions"].as_array().map(Vec::len),
        Some(1)
    );
    assert_eq!(report["unresolved_versions"][0]["version"], "!=2.0");
}

#[tokio::test(flavor = "current_thread")]
async fn sbom_cli_scans_cyclonedx_metadata_root_and_deduplicates_top_level_component() {
    let fixture = custom_sbom_fixture(
        "cyclonedx-root",
        json!({
            "schema_version": "1.8.0",
            "id": "GHSA-2099-CYCLONEDX",
            "modified": "2099-01-01T00:00:00Z",
            "affected": [{
                "package": {"ecosystem": "npm", "name": "application"},
                "ranges": [{
                    "type": "SEMVER",
                    "events": [
                        {"introduced": "0"},
                        {"fixed": "2.0.0"}
                    ]
                }]
            }]
        }),
        json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "unknownRootField": true,
            "metadata": {
                "component": {
                    "name": "application",
                    "version": "1.0.0",
                    "purl": "pkg:npm/application@1.0.0",
                    "components": [{
                        "name": "dependency",
                        "version": "3.0.0",
                        "purl": "pkg:npm/dependency@3.0.0"
                    }]
                }
            },
            "components": [{
                "name": "application duplicate",
                "version": "1.0.0",
                "purl": "pkg:npm/application@1.0.0"
            }]
        }),
    )
    .await;

    let (report, _) = run_sbom_fixture(&fixture);
    assert_eq!(report["component_count"], 3);
    assert_eq!(report["unique_component_count"], 2);
    assert_eq!(report["package_query_count"], 2);
    assert_eq!(report["osv_count"], 1);
    assert_eq!(
        report["osv_findings"][0]["finding"]["primary_id"],
        "GHSA-2099-CYCLONEDX"
    );
}
