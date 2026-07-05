//! Common DB helpers shared by CVE, OSV, KEV, EPSS, and identifier graph code.

use md5::{Digest, Md5};

pub(crate) fn md5_hex(bytes: &[u8]) -> String {
    let mut hasher = Md5::new();
    hasher.update(bytes);
    md5_hasher_hex(hasher)
}

pub(crate) fn md5_hex_concat<'a>(chunks: impl IntoIterator<Item = &'a [u8]>) -> String {
    let mut hasher = Md5::new();
    for chunk in chunks {
        hasher.update(chunk);
    }
    md5_hasher_hex(hasher)
}

fn md5_hasher_hex(hasher: Md5) -> String {
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub(crate) fn normalize_identifier(id: &str) -> String {
    id.trim().to_ascii_uppercase()
}

pub fn detect_identifier_type(id: &str) -> &'static str {
    identifier_type(&normalize_identifier(id))
}

pub(crate) fn identifier_type(id: &str) -> &'static str {
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

pub(crate) fn sql_string_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

pub(crate) fn sql_string_list(values: &[String]) -> String {
    values
        .iter()
        .map(|value| sql_string_literal(value))
        .collect::<Vec<_>>()
        .join(",")
}

pub(crate) fn sql_values_list(values: &[String]) -> String {
    values
        .iter()
        .enumerate()
        .map(|(index, value)| format!("({}, {})", sql_string_literal(value), index))
        .collect::<Vec<_>>()
        .join(",")
}
