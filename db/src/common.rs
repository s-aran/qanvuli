//! Identifier normalization shared by SQLx ingestion and graph queries.

pub fn detect_identifier_type(id: &str) -> &'static str {
    let id = id.trim().to_ascii_uppercase();
    if id.starts_with("CVE-") {
        "cve"
    } else if id.starts_with("GHSA-") {
        "ghsa"
    } else if id.starts_with("RUSTSEC-") {
        "rustsec"
    } else if id.starts_with("PYSEC-") {
        "pysec"
    } else if id.starts_with("GO-") {
        "go"
    } else if id.starts_with("OSV-") {
        "osv"
    } else {
        "other"
    }
}
