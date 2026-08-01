use qanvuli_core::database::{OsvRawRecord, SqlxDatabase};
use serde_json::json;

struct EcosystemCase {
    ecosystem: &'static str,
    package: &'static str,
    range_type: &'static str,
    introduced: &'static str,
    fixed: &'static str,
    affected: &'static str,
    not_affected: &'static str,
}

#[tokio::test(flavor = "current_thread")]
async fn osv_import_and_package_query_resolve_every_supported_ecosystem_natively() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();

    let cases = [
        EcosystemCase {
            ecosystem: "crates.io",
            package: "fixture-cargo",
            range_type: "ECOSYSTEM",
            introduced: "1.2.3-alpha.1",
            fixed: "1.2.3",
            affected: "1.2.3-alpha.2",
            not_affected: "1.2.3",
        },
        EcosystemCase {
            ecosystem: "Go",
            package: "example.invalid/fixture/go",
            range_type: "ECOSYSTEM",
            introduced: "1.2.3-alpha.1",
            fixed: "1.2.3",
            affected: "v1.2.3-alpha.2",
            not_affected: "v1.2.3",
        },
        EcosystemCase {
            ecosystem: "GitHub Actions",
            package: "Owner/Fixture-Action",
            range_type: "ECOSYSTEM",
            introduced: "4.0.0",
            fixed: "4.1.3",
            affected: "v4.1.2",
            not_affected: "v4.1.3",
        },
        EcosystemCase {
            ecosystem: "Maven",
            package: "org.example:fixture-maven",
            range_type: "ECOSYSTEM",
            introduced: "1.0-rc1",
            fixed: "1.0",
            affected: "1.0-SNAPSHOT",
            not_affected: "1.0-final",
        },
        EcosystemCase {
            ecosystem: "npm",
            package: "@fixture/native-version",
            range_type: "ECOSYSTEM",
            introduced: "1.0.0",
            fixed: "2.0.0",
            affected: "v1.5.0",
            not_affected: "2.0.0",
        },
        EcosystemCase {
            ecosystem: "NuGet",
            package: "Fixture.Native.Version",
            range_type: "ECOSYSTEM",
            introduced: "1.0.0-alpha.1",
            fixed: "1.0.0",
            affected: "1.0.0-ALPHA.2",
            not_affected: "1.0",
        },
        EcosystemCase {
            ecosystem: "PyPI",
            package: "fixture_native.version",
            range_type: "ECOSYSTEM",
            introduced: "2.0rc1",
            fixed: "2.0.post1",
            affected: "2.0",
            not_affected: "2.0.post1",
        },
        EcosystemCase {
            ecosystem: "Pub",
            package: "fixture_native_version",
            range_type: "ECOSYSTEM",
            introduced: "1.0.0+2",
            fixed: "1.0.0+10",
            affected: "1.0.0+3",
            not_affected: "1.0.0+10",
        },
        EcosystemCase {
            ecosystem: "RubyGems",
            package: "fixture-native-version",
            range_type: "ECOSYSTEM",
            introduced: "1.0.pre.1",
            fixed: "1.0",
            affected: "1.0.pre.2",
            not_affected: "1.0.0",
        },
    ];

    for (index, case) in cases.iter().enumerate() {
        database
            .import_osv_record(OsvRawRecord {
                source_path: None,
                raw_json: json!({
                    "schema_version": "1.8.0",
                    "id": format!("GHSA-2099-native-{index:04}"),
                    "modified": "2099-01-01T00:00:00Z",
                    "affected": [{
                        "package": {
                            "ecosystem": case.ecosystem,
                            "name": case.package
                        },
                        "ranges": [{
                            "type": case.range_type,
                            "events": [
                                { "introduced": case.introduced },
                                { "fixed": case.fixed }
                            ]
                        }]
                    }]
                })
                .to_string(),
            })
            .await
            .unwrap();

        let findings = database
            .query_package_matches(case.ecosystem, case.package, case.affected, None)
            .await
            .unwrap();
        assert_eq!(findings.len(), 1, "{} affected lookup", case.ecosystem);
        assert_eq!(
            findings[0].affected.status, "affected",
            "{} affected status",
            case.ecosystem
        );

        let findings = database
            .query_package_matches(case.ecosystem, case.package, case.not_affected, None)
            .await
            .unwrap();
        assert!(findings.is_empty(), "{} fixed lookup", case.ecosystem);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn package_query_keeps_ecosystem_specific_name_identity() {
    let database = SqlxDatabase::connect("sqlite::memory:").await.unwrap();
    database.initialize().await.unwrap();
    database
        .import_osv_record(OsvRawRecord {
            source_path: None,
            raw_json: json!({
                "schema_version": "1.8.0",
                "id": "GHSA-2099-pypi-name-normalization",
                "modified": "2099-01-01T00:00:00Z",
                "affected": [{
                    "package": { "ecosystem": "PyPI", "name": "Friendly-._-Package" },
                    "ranges": [{
                        "type": "ECOSYSTEM",
                        "events": [{ "introduced": "1.0" }, { "fixed": "2.0" }]
                    }]
                }]
            })
            .to_string(),
        })
        .await
        .unwrap();

    let normalized = database
        .query_package_matches(
            "PyPI",
            "friendly-package",
            "1.5",
            Some("pkg:pypi/friendly_package@1.5"),
        )
        .await
        .unwrap();
    assert_eq!(normalized.len(), 1);
    assert_eq!(normalized[0].affected.status, "affected");

    assert!(
        database
            .query_package_matches("npm", "friendly-package", "1.5.0", None)
            .await
            .unwrap()
            .is_empty(),
        "package names must not match across ecosystems"
    );
}
