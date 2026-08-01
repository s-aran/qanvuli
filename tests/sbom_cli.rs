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
}

impl Drop for TemporarySbomFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.sbom_path);
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
    }
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
