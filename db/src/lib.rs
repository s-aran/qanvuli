#![allow(clippy::too_many_arguments)]

pub mod common;
pub mod cve_types;
pub mod entity;
pub mod epss;
pub mod identifiers;
pub mod kev;
pub mod migration;
pub mod osv;

use chrono::Utc;
pub use common::detect_identifier_type;
use common::*;
pub use cve_types::*;
use entity::{
    app_metadata, cve, cve_affected, cve_cvss, cve_cwe, cve_zip_file, cwe, read_json_file,
};
pub use epss::*;
pub use identifiers::*;
pub use kev::*;
use migration::Migrator;
pub use osv::*;
use std::collections::{BTreeSet, HashMap, HashSet};

use qanvuli_models::{
    CveStatusData, RawCveRecord, RawCveStatusRecord, cna_affected_raw_values, cna_cvss_raw_values,
    cna_cwe_raw_values,
    cve::base::cve_metadata::CveState,
    cve::published::cna_description::CnaDescription,
    cwe::{WeaknessCatalog, enumeration::RelatedNature},
    epss::EpssCurrentCsv,
    kev::KevCatalog,
    osv::OSV_SCHEMA_VERSION,
    parse_value_with_raw,
};
use rayon::prelude::*;
use sea_orm::sea_query::{Expr, OnConflict};
use sea_orm::{
    ColumnTrait, Condition, ConnectionTrait, Database, DatabaseConnection, DatabaseTransaction,
    DbBackend, DbErr, EntityTrait, FromQueryResult, PaginatorTrait, QueryFilter, QueryOrder,
    QuerySelect, Set, Statement, TransactionTrait, Value as SeaValue,
};
use sea_orm_migration::prelude::MigratorTrait;
use serde::Deserialize;
use serde_json::Value;
use simd_json::{BorrowedValue, prelude::*};

const CVE_CHUNK_SIZE: usize = 2000;
const CVSS_CHUNK_SIZE: usize = CVE_CHUNK_SIZE * 2;
const AFFECTED_CHUNK_SIZE: usize = CVE_CHUNK_SIZE * 2;
const CWE_CHUNK_SIZE: usize = CVE_CHUNK_SIZE * 6;
const CWE_MASTER_CHUNK_SIZE: usize = CVE_CHUNK_SIZE * 2;
const READ_JSON_FILE_CHUNK_SIZE: usize = 8_000;
const FTS_ORDER_SCAN_THRESHOLD: u64 = 100;
const CVE_ASSET_METADATA_PREFIX: &str = "cve_asset:";
const PUBLISHED_STATE: i32 = 0;
const REJECTED_STATE: i32 = 1;

impl ReadJsonFileRecord {
    /// Creates a file-read marker by hashing the original JSON content.
    pub fn from_content(filename: impl Into<String>, content: &[u8]) -> Self {
        Self {
            filename: filename.into(),
            md5hash: md5_hex(content),
        }
    }
}

impl From<RawCveRecord<CveStatusData>> for CveActiveModels {
    fn from(value: RawCveRecord<CveStatusData>) -> Self {
        let raw_json = value.raw_json().clone();
        let cve_id = cve_id_from_raw_json(&raw_json).to_owned();

        Self {
            cve_id: cve_id.clone(),
            cve: cve::ActiveModel::from(value),
            cvss_rows: cvss_active_models(&cve_id, &raw_json),
            affected_rows: affected_active_models(&cve_id, &raw_json),
            cwe_master_rows: Vec::new(),
            cwe_rows: cwe_active_models(&cve_id, &raw_json),
        }
    }
}

impl CveActiveModels {
    /// Builds database active models from a parsed CVE JSON value.
    pub fn from_raw_json(raw_json: Value) -> Self {
        let cve_id = cve_id_from_raw_json(&raw_json).to_owned();
        let cvss_rows = cvss_active_models(&cve_id, &raw_json);
        let affected_rows = affected_active_models(&cve_id, &raw_json);
        let cwe_rows = cwe_active_models(&cve_id, &raw_json);

        Self {
            cve_id: cve_id.clone(),
            cve: cve_active_model_from_raw_json(raw_json, &cve_id),
            cvss_rows,
            affected_rows,
            cwe_master_rows: Vec::new(),
            cwe_rows,
        }
    }

    /// Builds database active models from a raw CVE JSON string.
    pub fn from_raw_json_string(raw_json: String) -> Result<Self, DbErr> {
        let mut bytes = raw_json.as_bytes().to_vec();
        let value: BorrowedValue<'_> =
            simd_json::to_borrowed_value(&mut bytes).map_err(json_parse_db_err)?;
        let compact_raw_json = compact_json_str(&raw_json)?;
        let cve_id = borrowed_cve_id(&value).unwrap_or_default().to_owned();
        let cvss_rows = borrowed_cvss_active_models(&value)?;
        let affected_rows = borrowed_affected_active_models(&value)?;
        let cwe_rows = borrowed_cwe_active_models(&value);

        Ok(Self {
            cve_id: cve_id.clone(),
            cve: borrowed_cve_active_model(compact_raw_json, &value, &cve_id),
            cvss_rows,
            affected_rows,
            cwe_master_rows: Vec::new(),
            cwe_rows,
        })
    }
}

impl From<RawCveRecord<CveStatusData>> for cve::ActiveModel {
    fn from(value: RawCveRecord<CveStatusData>) -> Self {
        let (content, raw_json) = value.into_parts();
        let raw_json_string = raw_json.to_string();

        match content {
            CveStatusData::Published(cve) => {
                let metadata = cve.cve_metadata;
                let cna = cve.containers.cna;
                let cve_id = metadata.cve_id;
                let title = cna.title.unwrap_or_else(|| cve_id.clone());

                Self {
                    id: Default::default(),
                    cve_id: Set(cve_id),
                    state: Set(cve_state_to_int(&metadata.state)),
                    published_at: Set(metadata
                        .date_published
                        .map_or_else(String::new, |d| d.to_rfc3339())),
                    updated_at: Set(metadata
                        .date_updated
                        .map_or_else(String::new, |d| d.to_rfc3339())),
                    serial: Set(metadata.serial.unwrap_or_default() as i32),
                    title: Set(title),
                    description_en: Set(description_en(&cna.descriptions)),
                    reference_text: Set(reference_text_from_raw_json(&raw_json)),
                    raw_json: Set(raw_json_string),
                }
            }
            CveStatusData::Rejected(cve) => {
                let metadata = cve.cve_metadata;
                let cna = cve.containers.cna;
                let cve_id = metadata.cve_id;

                Self {
                    id: Default::default(),
                    cve_id: Set(cve_id.clone()),
                    state: Set(cve_state_to_int(&metadata.state)),
                    published_at: Set(metadata
                        .date_published
                        .map_or_else(String::new, |d| d.to_rfc3339())),
                    updated_at: Set(metadata
                        .date_updated
                        .map_or_else(String::new, |d| d.to_rfc3339())),
                    serial: Set(metadata.serial.unwrap_or_default() as i32),
                    title: Set(cve_id),
                    description_en: Set(description_en(&cna.rejected_reasons)),
                    reference_text: Set(reference_text_from_raw_json(&raw_json)),
                    raw_json: Set(raw_json_string),
                }
            }
        }
    }
}

fn cve_active_model_from_raw_json(raw_json: Value, cve_id: &str) -> cve::ActiveModel {
    let metadata = raw_json.get("cveMetadata").and_then(Value::as_object);
    let state = metadata
        .and_then(|metadata| metadata.get("state"))
        .and_then(Value::as_str)
        .unwrap_or("PUBLISHED");
    let cna = raw_json
        .get("containers")
        .and_then(Value::as_object)
        .and_then(|containers| containers.get("cna"));
    let title = cna
        .and_then(|cna| cna.get("title"))
        .and_then(Value::as_str)
        .unwrap_or(cve_id)
        .to_owned();
    let description_en = if state == "REJECTED" {
        description_en_from_raw(cna.and_then(|cna| cna.get("rejectedReasons")))
    } else {
        description_en_from_raw(cna.and_then(|cna| cna.get("descriptions")))
    };

    cve::ActiveModel {
        id: Default::default(),
        cve_id: Set(cve_id.to_owned()),
        state: Set(cve_state_str_to_int(state)),
        published_at: Set(metadata
            .and_then(|metadata| metadata.get("datePublished"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()),
        updated_at: Set(metadata
            .and_then(|metadata| metadata.get("dateUpdated"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()),
        serial: Set(metadata
            .and_then(|metadata| metadata.get("serial"))
            .and_then(Value::as_i64)
            .and_then(|serial| i32::try_from(serial).ok())
            .unwrap_or_default()),
        title: Set(title),
        description_en: Set(description_en),
        reference_text: Set(reference_text_from_raw_json(&raw_json)),
        raw_json: Set(raw_json.to_string()),
    }
}

fn cve_id_from_raw_json(raw_json: &Value) -> &str {
    raw_json
        .get("cveMetadata")
        .and_then(Value::as_object)
        .and_then(|metadata| metadata.get("cveId"))
        .and_then(Value::as_str)
        .unwrap_or_default()
}

fn borrowed_cve_active_model(
    raw_json: String,
    value: &BorrowedValue<'_>,
    cve_id: &str,
) -> cve::ActiveModel {
    let metadata = borrowed_metadata(value);
    let state = metadata
        .and_then(|metadata| metadata.get("state"))
        .and_then(BorrowedValue::as_str)
        .unwrap_or("PUBLISHED");
    let cna = borrowed_cna(value);
    let title = cna
        .and_then(|cna| cna.get("title"))
        .and_then(BorrowedValue::as_str)
        .unwrap_or(cve_id)
        .to_owned();
    let description_en = if state == "REJECTED" {
        borrowed_description_en(cna.and_then(|cna| cna.get("rejectedReasons")))
    } else {
        borrowed_description_en(cna.and_then(|cna| cna.get("descriptions")))
    };

    cve::ActiveModel {
        id: Default::default(),
        cve_id: Set(cve_id.to_owned()),
        state: Set(cve_state_str_to_int(state)),
        published_at: Set(metadata
            .and_then(|metadata| metadata.get("datePublished"))
            .and_then(BorrowedValue::as_str)
            .unwrap_or_default()
            .to_owned()),
        updated_at: Set(metadata
            .and_then(|metadata| metadata.get("dateUpdated"))
            .and_then(BorrowedValue::as_str)
            .unwrap_or_default()
            .to_owned()),
        serial: Set(metadata
            .and_then(|metadata| metadata.get("serial"))
            .and_then(BorrowedValue::as_i64)
            .and_then(|serial| i32::try_from(serial).ok())
            .unwrap_or_default()),
        title: Set(title),
        description_en: Set(description_en),
        reference_text: Set(borrowed_reference_text(value)),
        raw_json: Set(raw_json),
    }
}

fn borrowed_cvss_active_models(
    value: &BorrowedValue<'_>,
) -> Result<Vec<cve_cvss::ActiveModel>, DbErr> {
    let Some(metrics) = borrowed_cna(value)
        .and_then(|cna| cna.get("metrics"))
        .and_then(BorrowedValue::as_array)
    else {
        return Ok(Vec::new());
    };

    let mut rows = Vec::new();
    for metric in metrics {
        for cvss_key in ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"] {
            let Some(cvss) = metric.get(cvss_key) else {
                continue;
            };
            rows.push(cve_cvss::ActiveModel {
                cve_db_id: Set(0),
                version: Set(
                    borrowed_string(cvss, "version").unwrap_or_else(|| cvss_key.to_owned())
                ),
                base_score: Set(cvss.get("baseScore").and_then(BorrowedValue::as_f64)),
                base_severity: Set(borrowed_string(cvss, "baseSeverity")),
                vector_string: Set(borrowed_string(cvss, "vectorString")),
                source: Set(Some("cna".to_owned())),
                raw_json: Set(borrowed_json_string(cvss)?),
                ..Default::default()
            });
        }
    }
    Ok(rows)
}

fn borrowed_affected_active_models(
    value: &BorrowedValue<'_>,
) -> Result<Vec<cve_affected::ActiveModel>, DbErr> {
    let Some(affected) = borrowed_cna(value)
        .and_then(|cna| cna.get("affected"))
        .and_then(BorrowedValue::as_array)
    else {
        return Ok(Vec::new());
    };

    affected
        .iter()
        .map(|affected| {
            Ok(cve_affected::ActiveModel {
                cve_db_id: Set(0),
                vendor: Set(borrowed_string(affected, "vendor")),
                product: Set(borrowed_string_or_json(affected, "product")?),
                package_name: Set(borrowed_string(affected, "packageName")),
                collection_url: Set(borrowed_string(affected, "collectionURL")),
                default_status: Set(borrowed_string(affected, "defaultStatus")),
                version_text: Set(borrowed_affected_version_text(affected)),
                raw_json: Set(borrowed_json_string(affected)?),
                ..Default::default()
            })
        })
        .collect()
}

fn borrowed_cwe_active_models(value: &BorrowedValue<'_>) -> Vec<cve_cwe::ActiveModel> {
    let mut seen = HashSet::new();
    let Some(problem_types) = borrowed_cna(value)
        .and_then(|cna| cna.get("problemTypes"))
        .and_then(BorrowedValue::as_array)
    else {
        return Vec::new();
    };

    problem_types
        .iter()
        .flat_map(|problem_type| {
            problem_type
                .get("descriptions")
                .and_then(BorrowedValue::as_array)
                .into_iter()
                .flatten()
        })
        .filter_map(|description| {
            let cwe_id = cwe_number(borrowed_string(description, "cweId")?.as_str())?;
            if !seen.insert(cwe_id) {
                return None;
            }
            Some(cve_cwe::ActiveModel {
                cve_db_id: Set(0),
                cwe_id: Set(cwe_id),
            })
        })
        .collect()
}

fn borrowed_metadata<'a>(value: &'a BorrowedValue<'a>) -> Option<&'a BorrowedValue<'a>> {
    value.get("cveMetadata")
}

fn borrowed_cna<'a>(value: &'a BorrowedValue<'a>) -> Option<&'a BorrowedValue<'a>> {
    value
        .get("containers")
        .and_then(|containers| containers.get("cna"))
}

fn borrowed_cve_id<'a>(value: &'a BorrowedValue<'a>) -> Option<&'a str> {
    borrowed_metadata(value)
        .and_then(|metadata| metadata.get("cveId"))
        .and_then(BorrowedValue::as_str)
}

fn borrowed_description_en(descriptions: Option<&BorrowedValue<'_>>) -> Option<String> {
    descriptions?.as_array()?.iter().find_map(|description| {
        let lang = description
            .get("lang")
            .and_then(BorrowedValue::as_str)
            .unwrap_or_default();
        if lang.eq_ignore_ascii_case("en") {
            description
                .get("value")
                .and_then(BorrowedValue::as_str)
                .map(ToOwned::to_owned)
        } else {
            None
        }
    })
}

fn borrowed_reference_text(value: &BorrowedValue<'_>) -> String {
    let mut parts = Vec::new();
    collect_borrowed_reference_text(
        borrowed_cna(value).and_then(|cna| cna.get("references")),
        &mut parts,
    );
    if let Some(adps) = value
        .get("containers")
        .and_then(|containers| containers.get("adp"))
        .and_then(BorrowedValue::as_array)
    {
        for adp in adps {
            collect_borrowed_reference_text(adp.get("references"), &mut parts);
        }
    }
    parts.join(" ")
}

fn collect_borrowed_reference_text(value: Option<&BorrowedValue<'_>>, parts: &mut Vec<String>) {
    let Some(references) = value.and_then(BorrowedValue::as_array) else {
        return;
    };
    for reference in references {
        push_borrowed_string(reference, "url", parts);
        push_borrowed_string(reference, "name", parts);
        if let Some(tags) = reference.get("tags").and_then(BorrowedValue::as_array) {
            for tag in tags {
                if let Some(tag) = tag.as_str() {
                    parts.push(tag.to_owned());
                }
            }
        }
    }
}

fn borrowed_affected_version_text(affected: &BorrowedValue<'_>) -> String {
    let Some(versions) = affected.get("versions").and_then(BorrowedValue::as_array) else {
        return String::new();
    };
    let mut parts = Vec::new();
    for version in versions {
        push_borrowed_string(version, "version", &mut parts);
        push_borrowed_string(version, "status", &mut parts);
        push_borrowed_string(version, "versionType", &mut parts);
        push_borrowed_string(version, "lessThan", &mut parts);
        push_borrowed_string(version, "lessThanOrEqual", &mut parts);
    }
    parts.join(" ")
}

fn push_borrowed_string(value: &BorrowedValue<'_>, key: &str, parts: &mut Vec<String>) {
    if let Some(text) = value.get(key).and_then(BorrowedValue::as_str)
        && !text.is_empty()
    {
        parts.push(text.to_owned());
    }
}

fn borrowed_string(value: &BorrowedValue<'_>, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(BorrowedValue::as_str)
        .map(ToOwned::to_owned)
}

fn borrowed_string_or_json(value: &BorrowedValue<'_>, key: &str) -> Result<Option<String>, DbErr> {
    let Some(value) = value.get(key) else {
        return Ok(None);
    };
    if let Some(s) = value.as_str() {
        return Ok(Some(s.to_owned()));
    }
    Ok(Some(borrowed_json_string(value)?))
}

fn borrowed_json_string(value: &BorrowedValue<'_>) -> Result<String, DbErr> {
    simd_json::to_string(value).map_err(json_parse_db_err)
}

fn compact_json_str(value: &str) -> Result<String, DbErr> {
    let mut compact = String::with_capacity(value.len());
    let mut in_string = false;
    let mut escaped = false;
    for ch in value.chars() {
        if in_string {
            compact.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
        } else if ch == '"' {
            in_string = true;
            compact.push(ch);
        } else if !ch.is_whitespace() {
            compact.push(ch);
        }
    }
    if escaped || in_string {
        return Err(DbErr::Custom(
            "failed to compact JSON: unterminated string literal".to_owned(),
        ));
    }
    if compact.is_empty() {
        return Err(DbErr::Custom(
            "failed to compact JSON: empty JSON payload".to_owned(),
        ));
    }
    Ok(compact)
}

fn json_parse_db_err(err: simd_json::Error) -> DbErr {
    DbErr::Custom(format!("failed to parse CVE JSON: {err}"))
}

fn raw_json_value(raw_json: &str) -> Result<Value, DbErr> {
    serde_json::from_str(raw_json)
        .map_err(|err| DbErr::Custom(format!("failed to decode raw JSON: {err}")))
}

fn cvss_active_models(_cve_id: &str, raw_json: &Value) -> Vec<cve_cvss::ActiveModel> {
    cna_cvss_raw_values(raw_json)
        .into_iter()
        .map(|cvss| cve_cvss::ActiveModel {
            cve_db_id: Set(0),
            version: Set(json_string(&cvss.raw_json, "version").unwrap_or(cvss.cvss_key)),
            base_score: Set(cvss.raw_json.get("baseScore").and_then(Value::as_f64)),
            base_severity: Set(json_string(&cvss.raw_json, "baseSeverity")),
            vector_string: Set(json_string(&cvss.raw_json, "vectorString")),
            source: Set(Some("cna".to_owned())),
            raw_json: Set(cvss.raw_json.to_string()),
            ..Default::default()
        })
        .collect()
}

fn affected_active_models(_cve_id: &str, raw_json: &Value) -> Vec<cve_affected::ActiveModel> {
    cna_affected_raw_values(raw_json)
        .into_iter()
        .map(|affected| cve_affected::ActiveModel {
            cve_db_id: Set(0),
            vendor: Set(json_string(&affected, "vendor")),
            product: Set(json_string_or_json(&affected, "product")),
            package_name: Set(json_string(&affected, "packageName")),
            collection_url: Set(json_string(&affected, "collectionURL")),
            default_status: Set(json_string(&affected, "defaultStatus")),
            version_text: Set(affected_version_text_from_raw_value(&affected)),
            raw_json: Set(affected.to_string()),
            ..Default::default()
        })
        .collect()
}

fn cwe_active_models(_cve_id: &str, raw_json: &Value) -> Vec<cve_cwe::ActiveModel> {
    let mut seen = HashSet::new();

    cna_cwe_raw_values(raw_json)
        .into_iter()
        .filter_map(|cwe| {
            let cwe_id = cwe_number(json_string(&cwe, "cweId")?.as_str())?;
            if !seen.insert(cwe_id) {
                return None;
            }

            Some(cve_cwe::ActiveModel {
                cve_db_id: Set(0),
                cwe_id: Set(cwe_id),
            })
        })
        .collect()
}

fn json_string(value: &Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn reference_text_from_raw_json(raw_json: &Value) -> String {
    let mut parts = Vec::new();
    collect_reference_text(raw_json.pointer("/containers/cna/references"), &mut parts);
    if let Some(adps) = raw_json
        .pointer("/containers/adp")
        .and_then(Value::as_array)
    {
        for adp in adps {
            collect_reference_text(adp.get("references"), &mut parts);
        }
    }
    parts.join(" ")
}

fn collect_reference_text(value: Option<&Value>, parts: &mut Vec<String>) {
    let Some(references) = value.and_then(Value::as_array) else {
        return;
    };
    for reference in references {
        push_json_string(reference, "url", parts);
        push_json_string(reference, "name", parts);
        if let Some(tags) = reference.get("tags").and_then(Value::as_array) {
            for tag in tags {
                if let Some(tag) = tag.as_str() {
                    parts.push(tag.to_owned());
                }
            }
        }
    }
}

fn affected_version_text_from_raw_value(affected: &Value) -> String {
    let Some(versions) = affected.get("versions").and_then(Value::as_array) else {
        return String::new();
    };
    let mut parts = Vec::new();
    for version in versions {
        push_json_string(version, "version", &mut parts);
        push_json_string(version, "status", &mut parts);
        push_json_string(version, "versionType", &mut parts);
        push_json_string(version, "lessThan", &mut parts);
        push_json_string(version, "lessThanOrEqual", &mut parts);
    }
    parts.join(" ")
}

fn push_json_string(value: &Value, key: &str, parts: &mut Vec<String>) {
    if let Some(text) = value.get(key).and_then(Value::as_str)
        && !text.is_empty()
    {
        parts.push(text.to_owned());
    }
}

fn cve_asset_metadata_key(asset_name: &str) -> String {
    format!("{CVE_ASSET_METADATA_PREFIX}{asset_name}")
}

fn json_string_or_json(value: &Value, key: &str) -> Option<String> {
    value.get(key).map(|value| {
        value
            .as_str()
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| value.to_string())
    })
}

fn cve_affected_detail_from_row(row: CveAffectedDetailRow) -> CveAffectedDetail {
    CveAffectedDetail {
        vendor: row.vendor,
        product: row.product,
        package_name: row.package_name,
        collection_url: row.collection_url,
        default_status: row.default_status,
        versions: affected_versions(&row.raw_json),
    }
}

fn affected_versions(raw_json: &str) -> Vec<CveAffectedVersionDetail> {
    let mut bytes = raw_json.as_bytes().to_vec();
    let Ok(raw_json) = simd_json::to_borrowed_value(&mut bytes) else {
        return Vec::new();
    };
    raw_json
        .get("versions")
        .and_then(BorrowedValue::as_array)
        .map(|versions| {
            versions
                .iter()
                .map(|version| CveAffectedVersionDetail {
                    version: borrowed_string(version, "version"),
                    status: borrowed_string(version, "status"),
                    version_type: borrowed_string(version, "versionType"),
                    less_than: borrowed_string(version, "lessThan"),
                    less_than_or_equal: borrowed_string(version, "lessThanOrEqual"),
                })
                .collect()
        })
        .unwrap_or_default()
}

fn cwe_numbers(cwe_ids: &[String]) -> Vec<i32> {
    let mut seen = HashSet::new();
    cwe_ids
        .iter()
        .filter_map(|cwe_id| cwe_number(cwe_id))
        .filter(|cwe_id| seen.insert(*cwe_id))
        .collect()
}

fn cwe_number(cwe_id: &str) -> Option<i32> {
    let value = cwe_id.trim();
    let value_upper = value.to_ascii_uppercase();
    let number = value
        .strip_prefix("CWE-")
        .or_else(|| value.strip_prefix("CWE"))
        .or_else(|| value_upper.strip_prefix("CWE-"))
        .or_else(|| value_upper.strip_prefix("CWE"))
        .unwrap_or(value);

    number.parse::<i32>().ok().filter(|number| *number > 0)
}

fn cve_state_to_int(state: &CveState) -> i32 {
    match state {
        CveState::Reserved | CveState::Published => PUBLISHED_STATE,
        CveState::Rejected => REJECTED_STATE,
    }
}

fn cve_state_str_to_int(state: &str) -> i32 {
    match state {
        "REJECTED" => REJECTED_STATE,
        _ => PUBLISHED_STATE,
    }
}

fn description_en(descriptions: &[CnaDescription]) -> Option<String> {
    descriptions
        .iter()
        .find(|description| description.lang == "en")
        .or_else(|| descriptions.first())
        .map(|description| description.value.clone())
}

fn description_en_from_raw(descriptions: Option<&Value>) -> Option<String> {
    let descriptions = descriptions.and_then(Value::as_array)?;
    descriptions
        .iter()
        .find(|description| {
            description
                .get("lang")
                .and_then(Value::as_str)
                .unwrap_or("en")
                == "en"
        })
        .or_else(|| descriptions.first())
        .and_then(|description| description.get("value"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

/// Async database handle for CVE, CWE, OSV, KEV, EPSS, and identifier graph data.
#[derive(Clone)]
pub struct CveDatabase {
    db: DatabaseConnection,
}

/// Transaction-backed session for streaming a full CVE replacement import.
pub struct CveBulkReplaceSession {
    txn: DatabaseTransaction,
}

impl CveDatabase {
    /// Connects to the database URL and returns a `CveDatabase` handle.
    pub async fn connect(database_url: &str) -> Result<Self, DbErr> {
        let db = connect_database(database_url).await?;
        Ok(Self { db })
    }

    /// Borrows the underlying SeaORM connection.
    pub fn connection(&self) -> &DatabaseConnection {
        &self.db
    }

    /// Consumes this handle and returns the underlying SeaORM connection.
    pub fn into_connection(self) -> DatabaseConnection {
        self.db
    }

    /// Closes the underlying database connection.
    pub async fn close(self) -> Result<(), DbErr> {
        self.db.close().await
    }

    /// Applies all pending schema migrations.
    pub async fn initialize_schema(&self) -> Result<(), DbErr> {
        Migrator::up(&self.db, None).await
    }

    /// Drops and recreates the schema by running migrations down and up.
    pub async fn rebuild_schema(&self) -> Result<(), DbErr> {
        Migrator::down(&self.db, None).await?;
        self.initialize_schema().await
    }

    /// Inserts or updates one CVE base row.
    pub async fn upsert_cve(&self, model: cve::ActiveModel) -> Result<(), DbErr> {
        upsert_cve_on(&self.db, model).await
    }

    /// Inserts or updates prepared CVE models and their detail rows in batches.
    pub async fn upsert_cve_models(&self, models: Vec<CveActiveModels>) -> Result<usize, DbErr> {
        if models.is_empty() {
            return Ok(0);
        }

        let txn = self.db.begin().await?;
        let mut inserted = 0usize;
        let mut batch = Vec::with_capacity(CVE_CHUNK_SIZE);

        for model in models {
            batch.push(model);
            if batch.len() == CVE_CHUNK_SIZE {
                inserted += upsert_cve_model_batch(&txn, std::mem::take(&mut batch)).await?;
                batch = Vec::with_capacity(CVE_CHUNK_SIZE);
            }
        }

        if !batch.is_empty() {
            inserted += upsert_cve_model_batch(&txn, batch).await?;
        }

        txn.commit().await?;
        Ok(inserted)
    }

    /// Converts parsed CVE records into database models and upserts them.
    pub async fn upsert_cve_records(
        &self,
        records: Vec<RawCveRecord<CveStatusData>>,
    ) -> Result<usize, DbErr> {
        self.upsert_cve_models(records.into_iter().map(CveActiveModels::from).collect())
            .await
    }

    /// Parses raw CVE JSON strings and upserts the resulting records.
    pub async fn upsert_cve_raw_json_strings(&self, values: Vec<String>) -> Result<usize, DbErr> {
        self.upsert_cve_models(
            values
                .into_iter()
                .map(CveActiveModels::from_raw_json_string)
                .collect::<Result<Vec<_>, _>>()?,
        )
        .await
    }

    /// Replaces all CVE data with the provided prepared models.
    pub async fn replace_all_cve_models(
        &self,
        models: Vec<CveActiveModels>,
    ) -> Result<usize, DbErr> {
        let txn = self.db.begin().await?;

        clear_cve_tables_on(&txn).await?;
        let inserted = insert_cve_models_on(&txn, models, true).await?;

        txn.commit().await?;
        Ok(inserted)
    }

    /// Prepares storage and indexes for a full bulk CVE replacement.
    pub async fn prepare_bulk_replace_all(&self) -> Result<(), DbErr> {
        prepare_bulk_replace_all_on(&self.db).await
    }

    /// Starts a transaction-backed full CVE replacement session.
    pub async fn begin_bulk_replace_all(&self) -> Result<CveBulkReplaceSession, DbErr> {
        prepare_bulk_replace_all_on(&self.db).await?;
        let txn = self.db.begin().await?;
        Ok(CveBulkReplaceSession { txn })
    }

    /// Inserts prepared CVE models during a bulk import without clearing existing data.
    pub async fn insert_cve_models_bulk(
        &self,
        models: Vec<CveActiveModels>,
    ) -> Result<usize, DbErr> {
        if models.is_empty() {
            return Ok(0);
        }

        let txn = self.db.begin().await?;
        let inserted = insert_cve_models_on(&txn, models, false).await?;
        txn.commit().await?;
        Ok(inserted)
    }

    /// Finishes a full bulk CVE replacement by restoring indexes and storage settings.
    pub async fn finish_bulk_replace_all(&self) -> Result<(), DbErr> {
        finish_bulk_replace_all_on(&self.db).await
    }

    /// Prepares storage and indexes for a bulk OSV import.
    pub async fn prepare_bulk_osv_import(&self) -> Result<(), DbErr> {
        prepare_bulk_osv_import_on(&self.db).await
    }

    /// Finishes a bulk OSV import and restores query indexes.
    pub async fn finish_bulk_osv_import(&self) -> Result<(), DbErr> {
        finish_bulk_osv_import_on(&self.db).await
    }

    /// Restores storage settings after a partial OSV import without rebuilding indexes.
    pub async fn finish_bulk_osv_import_storage_only(&self) -> Result<(), DbErr> {
        finish_bulk_osv_import_storage_on(&self.db).await
    }

    /// Compacts the underlying SQLite storage where supported.
    pub async fn compact_storage(&self) -> Result<(), DbErr> {
        compact_storage_on(&self.db).await
    }

    /// Deletes CVE core and detail tables inside a transaction.
    pub async fn clear_cve_tables(&self) -> Result<(), DbErr> {
        let txn = self.db.begin().await?;
        clear_cve_tables_on(&txn).await?;
        txn.commit().await
    }

    /// Inserts or updates the CWE catalog tree.
    pub async fn upsert_cwe_catalog(&self, catalog: &WeaknessCatalog) -> Result<usize, DbErr> {
        let txn = self.db.begin().await?;
        let count = upsert_cwe_catalog_on(&txn, catalog).await?;
        txn.commit().await?;
        Ok(count)
    }

    /// Inserts or updates one minimal CWE row.
    pub async fn upsert_cwe(&self, id: i32, description: Option<String>) -> Result<(), DbErr> {
        let txn = self.db.begin().await?;
        upsert_cwe_rows(
            &txn,
            vec![cwe::ActiveModel {
                id: Set(id),
                description: Set(description),
                status: Set(None),
                parent_id: Set(None),
            }],
        )
        .await?;
        txn.commit().await
    }

    /// Inserts prepared CVE models without upsert conflict handling.
    pub async fn insert_cve_models(&self, models: Vec<CveActiveModels>) -> Result<usize, DbErr> {
        if models.is_empty() {
            return Ok(0);
        }

        let txn = self.db.begin().await?;
        let inserted = insert_cve_models_on(&txn, models, true).await?;
        txn.commit().await?;
        Ok(inserted)
    }

    /// Converts parsed CVE records and inserts them during a bulk import.
    pub async fn insert_cve_records_bulk(
        &self,
        records: Vec<RawCveRecord<CveStatusData>>,
    ) -> Result<usize, DbErr> {
        self.insert_cve_models_bulk(records.into_iter().map(CveActiveModels::from).collect())
            .await
    }

    /// Parses raw CVE JSON strings and inserts them during a bulk import.
    pub async fn insert_cve_raw_json_strings_bulk(
        &self,
        values: Vec<String>,
    ) -> Result<usize, DbErr> {
        self.insert_cve_models_bulk(
            values
                .into_iter()
                .map(CveActiveModels::from_raw_json_string)
                .collect::<Result<Vec<_>, _>>()?,
        )
        .await
    }

    /// Replaces CVSS, affected-product, and CWE detail rows for one CVE.
    pub async fn replace_cve_children(
        &self,
        cve_id: &str,
        mut cvss_rows: Vec<cve_cvss::ActiveModel>,
        mut affected_rows: Vec<cve_affected::ActiveModel>,
        mut cwe_rows: Vec<cve_cwe::ActiveModel>,
    ) -> Result<(), DbErr> {
        let txn = self.db.begin().await?;
        let cve_db_id = cve_db_id_by_cve_id(&txn, cve_id).await?;

        cve_cvss::Entity::delete_many()
            .filter(cve_cvss::Column::CveDbId.eq(cve_db_id))
            .exec(&txn)
            .await?;
        cve_affected::Entity::delete_many()
            .filter(cve_affected::Column::CveDbId.eq(cve_db_id))
            .exec(&txn)
            .await?;
        cve_cwe::Entity::delete_many()
            .filter(cve_cwe::Column::CveDbId.eq(cve_db_id))
            .exec(&txn)
            .await?;

        set_cvss_cve_db_id(&mut cvss_rows, cve_db_id);
        set_affected_cve_db_id(&mut affected_rows, cve_db_id);
        set_cwe_cve_db_id(&mut cwe_rows, cve_db_id);

        if !cvss_rows.is_empty() {
            cve_cvss::Entity::insert_many(cvss_rows).exec(&txn).await?;
        }
        if !affected_rows.is_empty() {
            cve_affected::Entity::insert_many(affected_rows)
                .exec(&txn)
                .await?;
        }
        if !cwe_rows.is_empty() {
            cve_cwe::Entity::insert_many(cwe_rows).exec(&txn).await?;
        }
        upsert_cve_summary_index_rows(&txn, &[cve_id.to_owned()]).await?;

        txn.commit().await
    }

    /// Returns all CVE base rows ordered by newest publication date.
    pub async fn get_all(&self) -> Result<Vec<cve::Model>, DbErr> {
        cve::Entity::find()
            .order_by_desc(cve::Column::PublishedAt)
            .order_by_asc(cve::Column::CveId)
            .all(&self.db)
            .await
    }

    /// Finds one stored CVE base row by exact CVE ID.
    pub async fn find_cve_by_id(&self, cve_id: &str) -> Result<Option<cve::Model>, DbErr> {
        cve::Entity::find()
            .filter(cve::Column::CveId.eq(cve_id))
            .one(&self.db)
            .await
    }

    /// Finds one CVE and returns its raw JSON payload.
    pub async fn find_cve_raw_json_by_id(&self, cve_id: &str) -> Result<Option<Value>, DbErr> {
        self.find_cve_by_id(cve_id)
            .await
            .and_then(|row| row.map(|row| raw_json_value(&row.raw_json)).transpose())
    }

    /// Finds one CVE and deserializes the raw JSON into the model crate type.
    pub async fn find_cve_model_by_id(
        &self,
        cve_id: &str,
    ) -> Result<Option<RawCveStatusRecord>, DbErr> {
        self.find_cve_by_id(cve_id)
            .await?
            .map(|cve| {
                parse_value_with_raw(raw_json_value(&cve.raw_json)?)
                    .map_err(|err| DbErr::Custom(format!("failed to deserialize {cve_id}: {err}")))
            })
            .transpose()
    }

    /// Loads normalized CWE, CVSS, and affected-product detail for one CVE.
    pub async fn find_cve_detail(&self, cve_id: &str) -> Result<CveDetail, DbErr> {
        let Some(cve) = self.find_cve_by_id(cve_id).await? else {
            return Ok(CveDetail::default());
        };
        let cve_db_id = cve.id;

        let cwes = cve_cwe::Entity::find()
            .select_only()
            .column_as(cve_cwe::Column::CweId, "id")
            .column_as(cwe::Column::Description, "description")
            .inner_join(cwe::Entity)
            .filter(cve_cwe::Column::CveDbId.eq(cve_db_id))
            .order_by_asc(cve_cwe::Column::CweId)
            .into_model::<CveCweDetail>()
            .all(&self.db)
            .await?;

        let cvss = cve_cvss::Entity::find()
            .select_only()
            .columns([
                cve_cvss::Column::Version,
                cve_cvss::Column::BaseScore,
                cve_cvss::Column::BaseSeverity,
                cve_cvss::Column::VectorString,
                cve_cvss::Column::Source,
            ])
            .filter(cve_cvss::Column::CveDbId.eq(cve_db_id))
            .order_by_desc(cve_cvss::Column::BaseScore)
            .order_by_asc(cve_cvss::Column::Version)
            .into_model::<CveCvssDetail>()
            .all(&self.db)
            .await?;

        let affected_rows = cve_affected::Entity::find()
            .select_only()
            .column(cve_affected::Column::CveDbId)
            .columns([
                cve_affected::Column::Vendor,
                cve_affected::Column::Product,
                cve_affected::Column::PackageName,
                cve_affected::Column::CollectionUrl,
                cve_affected::Column::DefaultStatus,
                cve_affected::Column::RawJson,
            ])
            .filter(cve_affected::Column::CveDbId.eq(cve_db_id))
            .order_by_asc(cve_affected::Column::Vendor)
            .order_by_asc(cve_affected::Column::Product)
            .into_model::<CveAffectedDetailRow>()
            .all(&self.db)
            .await?;
        let affected = affected_rows
            .into_iter()
            .map(cve_affected_detail_from_row)
            .collect();

        Ok(CveDetail {
            cwes,
            cvss,
            affected,
        })
    }

    /// Attaches full normalized detail to each CVE summary row.
    pub async fn attach_cve_details(
        &self,
        rows: Vec<CveSummary>,
    ) -> Result<Vec<CveSummaryWithDetail>, DbErr> {
        if rows.is_empty() {
            return Ok(Vec::new());
        }

        let cve_ids = rows
            .iter()
            .map(|row| row.cve_id.clone())
            .collect::<Vec<_>>();
        let id_rows = cve::Entity::find()
            .select_only()
            .columns([cve::Column::Id, cve::Column::CveId])
            .filter(cve::Column::CveId.is_in(cve_ids))
            .into_model::<CveDbIdByCveId>()
            .all(&self.db)
            .await?;
        let cve_db_ids = id_rows.iter().map(|row| row.id).collect::<Vec<_>>();
        let cve_id_by_db_id = id_rows
            .iter()
            .map(|row| (row.id, row.cve_id.clone()))
            .collect::<HashMap<_, _>>();

        let mut detail_by_cve_id = id_rows
            .into_iter()
            .map(|row| (row.cve_id, CveDetail::default()))
            .collect::<HashMap<_, _>>();

        let cwes = cve_cwe::Entity::find()
            .select_only()
            .column(cve_cwe::Column::CveDbId)
            .column_as(cve_cwe::Column::CweId, "id")
            .column_as(cwe::Column::Description, "description")
            .inner_join(cwe::Entity)
            .filter(cve_cwe::Column::CveDbId.is_in(cve_db_ids.clone()))
            .order_by_asc(cve_cwe::Column::CveDbId)
            .order_by_asc(cve_cwe::Column::CweId)
            .into_model::<CveCweDetailRow>()
            .all(&self.db)
            .await?;
        for cwe in cwes {
            if let Some(cve_id) = cve_id_by_db_id.get(&cwe.cve_db_id)
                && let Some(detail) = detail_by_cve_id.get_mut(cve_id)
            {
                detail.cwes.push(CveCweDetail {
                    id: cwe.id,
                    description: cwe.description,
                });
            }
        }

        let cvss = cve_cvss::Entity::find()
            .select_only()
            .column(cve_cvss::Column::CveDbId)
            .columns([
                cve_cvss::Column::Version,
                cve_cvss::Column::BaseScore,
                cve_cvss::Column::BaseSeverity,
                cve_cvss::Column::VectorString,
                cve_cvss::Column::Source,
            ])
            .filter(cve_cvss::Column::CveDbId.is_in(cve_db_ids.clone()))
            .order_by_asc(cve_cvss::Column::CveDbId)
            .order_by_desc(cve_cvss::Column::BaseScore)
            .order_by_asc(cve_cvss::Column::Version)
            .into_model::<CveCvssDetailRow>()
            .all(&self.db)
            .await?;
        for cvss in cvss {
            if let Some(cve_id) = cve_id_by_db_id.get(&cvss.cve_db_id)
                && let Some(detail) = detail_by_cve_id.get_mut(cve_id)
            {
                detail.cvss.push(CveCvssDetail {
                    version: cvss.version,
                    base_score: cvss.base_score,
                    base_severity: cvss.base_severity,
                    vector_string: cvss.vector_string,
                    source: cvss.source,
                });
            }
        }

        let affected = cve_affected::Entity::find()
            .select_only()
            .column(cve_affected::Column::CveDbId)
            .columns([
                cve_affected::Column::Vendor,
                cve_affected::Column::Product,
                cve_affected::Column::PackageName,
                cve_affected::Column::CollectionUrl,
                cve_affected::Column::DefaultStatus,
                cve_affected::Column::RawJson,
            ])
            .filter(cve_affected::Column::CveDbId.is_in(cve_db_ids))
            .order_by_asc(cve_affected::Column::CveDbId)
            .order_by_asc(cve_affected::Column::Vendor)
            .order_by_asc(cve_affected::Column::Product)
            .into_model::<CveAffectedDetailRow>()
            .all(&self.db)
            .await?;
        for affected in affected {
            if let Some(cve_id) = cve_id_by_db_id.get(&affected.cve_db_id)
                && let Some(detail) = detail_by_cve_id.get_mut(cve_id)
            {
                detail.affected.push(cve_affected_detail_from_row(affected));
            }
        }

        Ok(rows
            .into_iter()
            .map(|summary| {
                let detail = detail_by_cve_id.remove(&summary.cve_id).unwrap_or_default();
                CveSummaryWithDetail { summary, detail }
            })
            .collect())
    }

    /// Attaches lightweight detail without affected version expansion.
    pub async fn attach_cve_overview_details(
        &self,
        rows: Vec<CveSummary>,
    ) -> Result<Vec<CveSummaryWithDetail>, DbErr> {
        if rows.is_empty() {
            return Ok(Vec::new());
        }

        let cve_ids = rows
            .iter()
            .map(|row| row.cve_id.clone())
            .collect::<Vec<_>>();
        let id_rows = cve::Entity::find()
            .select_only()
            .columns([cve::Column::Id, cve::Column::CveId])
            .filter(cve::Column::CveId.is_in(cve_ids))
            .into_model::<CveDbIdByCveId>()
            .all(&self.db)
            .await?;
        let cve_db_ids = id_rows.iter().map(|row| row.id).collect::<Vec<_>>();
        let cve_id_by_db_id = id_rows
            .iter()
            .map(|row| (row.id, row.cve_id.clone()))
            .collect::<HashMap<_, _>>();
        let mut detail_by_cve_id = id_rows
            .into_iter()
            .map(|row| (row.cve_id, CveDetail::default()))
            .collect::<HashMap<_, _>>();

        let cwes = cve_cwe::Entity::find()
            .select_only()
            .column(cve_cwe::Column::CveDbId)
            .column_as(cve_cwe::Column::CweId, "id")
            .column_as(cwe::Column::Description, "description")
            .inner_join(cwe::Entity)
            .filter(cve_cwe::Column::CveDbId.is_in(cve_db_ids.clone()))
            .order_by_asc(cve_cwe::Column::CveDbId)
            .order_by_asc(cve_cwe::Column::CweId)
            .into_model::<CveCweDetailRow>()
            .all(&self.db)
            .await?;
        for cwe in cwes {
            if let Some(cve_id) = cve_id_by_db_id.get(&cwe.cve_db_id)
                && let Some(detail) = detail_by_cve_id.get_mut(cve_id)
            {
                detail.cwes.push(CveCweDetail {
                    id: cwe.id,
                    description: cwe.description,
                });
            }
        }

        let cvss = cve_cvss::Entity::find()
            .select_only()
            .column(cve_cvss::Column::CveDbId)
            .columns([
                cve_cvss::Column::Version,
                cve_cvss::Column::BaseScore,
                cve_cvss::Column::BaseSeverity,
                cve_cvss::Column::VectorString,
                cve_cvss::Column::Source,
            ])
            .filter(cve_cvss::Column::CveDbId.is_in(cve_db_ids.clone()))
            .order_by_asc(cve_cvss::Column::CveDbId)
            .order_by_desc(cve_cvss::Column::BaseScore)
            .order_by_asc(cve_cvss::Column::Version)
            .into_model::<CveCvssDetailRow>()
            .all(&self.db)
            .await?;
        for cvss in cvss {
            if let Some(cve_id) = cve_id_by_db_id.get(&cvss.cve_db_id)
                && let Some(detail) = detail_by_cve_id.get_mut(cve_id)
            {
                detail.cvss.push(CveCvssDetail {
                    version: cvss.version,
                    base_score: cvss.base_score,
                    base_severity: cvss.base_severity,
                    vector_string: cvss.vector_string,
                    source: cvss.source,
                });
            }
        }

        let affected = cve_affected::Entity::find()
            .select_only()
            .column(cve_affected::Column::CveDbId)
            .columns([
                cve_affected::Column::Vendor,
                cve_affected::Column::Product,
                cve_affected::Column::PackageName,
                cve_affected::Column::CollectionUrl,
                cve_affected::Column::DefaultStatus,
            ])
            .filter(cve_affected::Column::CveDbId.is_in(cve_db_ids))
            .order_by_asc(cve_affected::Column::CveDbId)
            .order_by_asc(cve_affected::Column::Vendor)
            .order_by_asc(cve_affected::Column::Product)
            .into_model::<CveAffectedOverviewRow>()
            .all(&self.db)
            .await?;
        for affected in affected {
            if let Some(cve_id) = cve_id_by_db_id.get(&affected.cve_db_id)
                && let Some(detail) = detail_by_cve_id.get_mut(cve_id)
            {
                detail.affected.push(CveAffectedDetail {
                    vendor: affected.vendor,
                    product: affected.product,
                    package_name: affected.package_name,
                    collection_url: affected.collection_url,
                    default_status: affected.default_status,
                    versions: Vec::new(),
                });
            }
        }

        Ok(rows
            .into_iter()
            .map(|summary| {
                let detail = detail_by_cve_id.remove(&summary.cve_id).unwrap_or_default();
                CveSummaryWithDetail { summary, detail }
            })
            .collect())
    }

    /// Searches published CVE base rows by CWE IDs.
    pub async fn search_cves_by_cwe(
        &self,
        cwe_ids: &[String],
        limit: u64,
        offset: u64,
    ) -> Result<Vec<cve::Model>, DbErr> {
        self.search_cves_by_cwe_with_state_scope(
            cwe_ids,
            CveStateScope::PublishedOnly,
            limit,
            offset,
        )
        .await
    }

    /// Searches CVE base rows by CWE IDs with explicit rejected-record handling.
    pub async fn search_cves_by_cwe_with_state_scope(
        &self,
        cwe_ids: &[String],
        state_scope: CveStateScope,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<cve::Model>, DbErr> {
        let cwe_ids = cwe_numbers(cwe_ids);
        if cwe_ids.is_empty() {
            return Ok(Vec::new());
        }

        if matches!(self.db.get_database_backend(), DbBackend::Sqlite) {
            return cve::Model::find_by_statement(Statement::from_string(
                DbBackend::Sqlite,
                cwe_model_sql(&cwe_ids, state_scope, limit, offset),
            ))
            .all(&self.db)
            .await;
        }

        let mut query = cve::Entity::find()
            .inner_join(cve_cwe::Entity)
            .filter(cve_cwe::Column::CweId.is_in(cwe_ids))
            .distinct();
        if !state_scope.includes_rejected() {
            query = query.filter(cve::Column::State.eq(PUBLISHED_STATE));
        }
        query
            .order_by_desc(cve::Column::PublishedAt)
            .order_by_asc(cve::Column::CveId)
            .limit(limit)
            .offset(offset)
            .all(&self.db)
            .await
    }

    /// Searches published CVE summary rows by CWE IDs.
    pub async fn search_cve_summaries_by_cwe(
        &self,
        cwe_ids: &[String],
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, DbErr> {
        self.search_cve_summaries_by_cwe_with_state_scope(
            cwe_ids,
            CveStateScope::PublishedOnly,
            limit,
            offset,
        )
        .await
    }

    /// Searches CVE summary rows by CWE IDs with explicit rejected-record handling.
    pub async fn search_cve_summaries_by_cwe_with_state_scope(
        &self,
        cwe_ids: &[String],
        state_scope: CveStateScope,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, DbErr> {
        let cwe_ids = cwe_numbers(cwe_ids);
        if cwe_ids.is_empty() {
            return Ok(Vec::new());
        }

        if matches!(self.db.get_database_backend(), DbBackend::Sqlite) {
            return CveSummary::find_by_statement(Statement::from_string(
                DbBackend::Sqlite,
                cwe_summary_index_sql(&cwe_ids, state_scope, limit, offset),
            ))
            .all(&self.db)
            .await;
        }

        let mut query = cve::Entity::find()
            .select_only()
            .columns(summary_columns())
            .inner_join(cve_cwe::Entity)
            .filter(cve_cwe::Column::CweId.is_in(cwe_ids))
            .distinct();
        if !state_scope.includes_rejected() {
            query = query.filter(cve::Column::State.eq(PUBLISHED_STATE));
        }
        query
            .order_by_desc(cve::Column::PublishedAt)
            .order_by_asc(cve::Column::CveId)
            .limit(limit)
            .offset(offset)
            .into_model::<CveSummary>()
            .all(&self.db)
            .await
    }

    /// Counts published CVE summaries matching the given CWE IDs.
    pub async fn count_cve_summaries_by_cwe(&self, cwe_ids: &[String]) -> Result<u64, DbErr> {
        self.count_cve_summaries_by_cwe_with_state_scope(cwe_ids, CveStateScope::PublishedOnly)
            .await
    }

    /// Counts CVE summaries by CWE IDs with explicit rejected-record handling.
    pub async fn count_cve_summaries_by_cwe_with_state_scope(
        &self,
        cwe_ids: &[String],
        state_scope: CveStateScope,
    ) -> Result<u64, DbErr> {
        let cwe_ids = cwe_numbers(cwe_ids);
        if cwe_ids.is_empty() {
            return Ok(0);
        }

        if matches!(self.db.get_database_backend(), DbBackend::Sqlite) {
            return self
                .count_by_sql(cwe_count_summary_index_sql(&cwe_ids, state_scope))
                .await;
        }

        let mut query = cve::Entity::find()
            .inner_join(cve_cwe::Entity)
            .filter(cve_cwe::Column::CweId.is_in(cwe_ids))
            .distinct();
        if !state_scope.includes_rejected() {
            query = query.filter(cve::Column::State.eq(PUBLISHED_STATE));
        }
        query.count(&self.db).await
    }

    /// Searches published CVE base rows by affected vendor/product substring.
    pub async fn search_cves_by_vendor_product(
        &self,
        vendor: Option<&str>,
        product: Option<&str>,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<cve::Model>, DbErr> {
        self.search_cves_by_vendor_product_with_state_scope(
            vendor,
            product,
            CveStateScope::PublishedOnly,
            limit,
            offset,
        )
        .await
    }

    /// Searches CVE base rows by affected vendor/product substring and state scope.
    pub async fn search_cves_by_vendor_product_with_state_scope(
        &self,
        vendor: Option<&str>,
        product: Option<&str>,
        state_scope: CveStateScope,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<cve::Model>, DbErr> {
        self.search_cves_by_vendor_product_exact_with_state_scope(
            vendor,
            product,
            None,
            None,
            state_scope,
            limit,
            offset,
        )
        .await
    }

    /// Searches CVE base rows by affected vendor/product with exact and substring filters.
    pub async fn search_cves_by_vendor_product_exact_with_state_scope(
        &self,
        vendor: Option<&str>,
        product: Option<&str>,
        vendor_exact: Option<&str>,
        product_exact: Option<&str>,
        state_scope: CveStateScope,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<cve::Model>, DbErr> {
        let mut query = cve::Entity::find().inner_join(cve_affected::Entity);

        if !state_scope.includes_rejected() {
            query = query.filter(cve::Column::State.eq(PUBLISHED_STATE));
        }
        query = apply_affected_filters(query, vendor, product, vendor_exact, product_exact);

        query
            .distinct()
            .order_by_desc(cve::Column::PublishedAt)
            .order_by_asc(cve::Column::CveId)
            .limit(limit)
            .offset(offset)
            .all(&self.db)
            .await
    }

    /// Searches published CVE summaries by affected vendor/product substring.
    pub async fn search_cve_summaries_by_vendor_product(
        &self,
        vendor: Option<&str>,
        product: Option<&str>,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, DbErr> {
        self.search_cve_summaries_by_vendor_product_with_state_scope(
            vendor,
            product,
            CveStateScope::PublishedOnly,
            limit,
            offset,
        )
        .await
    }

    /// Searches CVE summaries by affected vendor/product substring and state scope.
    pub async fn search_cve_summaries_by_vendor_product_with_state_scope(
        &self,
        vendor: Option<&str>,
        product: Option<&str>,
        state_scope: CveStateScope,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, DbErr> {
        self.search_cve_summaries_by_vendor_product_exact_with_state_scope(
            vendor,
            product,
            None,
            None,
            state_scope,
            limit,
            offset,
        )
        .await
    }

    /// Searches CVE summaries by affected vendor/product with exact and substring filters.
    pub async fn search_cve_summaries_by_vendor_product_exact_with_state_scope(
        &self,
        vendor: Option<&str>,
        product: Option<&str>,
        vendor_exact: Option<&str>,
        product_exact: Option<&str>,
        state_scope: CveStateScope,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, DbErr> {
        self.search_cve_summaries_by_vendor_product_exact_date_with_state_scope(
            vendor,
            product,
            vendor_exact,
            product_exact,
            None,
            None,
            state_scope,
            limit,
            offset,
        )
        .await
    }

    /// Searches CVE summaries by affected filters plus publication/update date bounds.
    pub async fn search_cve_summaries_by_vendor_product_exact_date_with_state_scope(
        &self,
        vendor: Option<&str>,
        product: Option<&str>,
        vendor_exact: Option<&str>,
        product_exact: Option<&str>,
        published_since: Option<&str>,
        updated_since: Option<&str>,
        state_scope: CveStateScope,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, DbErr> {
        if matches!(self.db.get_database_backend(), DbBackend::Sqlite)
            && vendor_exact.is_none()
            && product_exact.is_none()
            && published_since.is_none()
            && updated_since.is_none()
            && let Some(query) = affected_fts_query(vendor, product)
        {
            let match_count = self
                .count_by_statement(
                    "SELECT COUNT(*) AS count FROM cve_affected_summary_fts WHERE cve_affected_summary_fts MATCH ?",
                    vec![SeaValue::from(query.clone())],
                )
                .await?;
            let sql = if match_count >= FTS_ORDER_SCAN_THRESHOLD {
                affected_fts_ordered_rowid_summary_sql(state_scope)
            } else {
                affected_fts_summary_sql(state_scope)
            };
            return CveSummary::find_by_statement(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                sql,
                vec![
                    SeaValue::from(query),
                    SeaValue::from(limit as i64),
                    SeaValue::from(offset as i64),
                ],
            ))
            .all(&self.db)
            .await;
        }
        if matches!(self.db.get_database_backend(), DbBackend::Sqlite)
            && (vendor_exact.is_some() || product_exact.is_some())
        {
            return CveSummary::find_by_statement(Statement::from_string(
                DbBackend::Sqlite,
                affected_exact_summary_sql(
                    vendor,
                    product,
                    vendor_exact,
                    product_exact,
                    published_since,
                    None,
                    updated_since,
                    state_scope,
                    CveSummarySortOrder::PublishedDesc,
                    limit,
                    offset,
                ),
            ))
            .all(&self.db)
            .await;
        }

        let mut query = cve::Entity::find()
            .select_only()
            .columns(summary_columns())
            .inner_join(cve_affected::Entity);

        if !state_scope.includes_rejected() {
            query = query.filter(cve::Column::State.eq(PUBLISHED_STATE));
        }
        query = apply_affected_filters(query, vendor, product, vendor_exact, product_exact);
        if let Some(published_since) = published_since {
            query = query.filter(cve::Column::PublishedAt.gte(published_since));
        }
        if let Some(updated_since) = updated_since {
            query = query.filter(cve::Column::UpdatedAt.gte(updated_since));
        }

        query
            .distinct()
            .order_by_desc(cve::Column::PublishedAt)
            .order_by_asc(cve::Column::CveId)
            .limit(limit)
            .offset(offset)
            .into_model::<CveSummary>()
            .all(&self.db)
            .await
    }

    /// Counts published CVE summaries matching affected vendor/product substrings.
    pub async fn count_cve_summaries_by_vendor_product(
        &self,
        vendor: Option<&str>,
        product: Option<&str>,
    ) -> Result<u64, DbErr> {
        self.count_cve_summaries_by_vendor_product_with_state_scope(
            vendor,
            product,
            CveStateScope::PublishedOnly,
        )
        .await
    }

    /// Counts CVE summaries by affected vendor/product substring and state scope.
    pub async fn count_cve_summaries_by_vendor_product_with_state_scope(
        &self,
        vendor: Option<&str>,
        product: Option<&str>,
        state_scope: CveStateScope,
    ) -> Result<u64, DbErr> {
        self.count_cve_summaries_by_vendor_product_exact_with_state_scope(
            vendor,
            product,
            None,
            None,
            state_scope,
        )
        .await
    }

    /// Counts CVE summaries by affected vendor/product with exact and substring filters.
    pub async fn count_cve_summaries_by_vendor_product_exact_with_state_scope(
        &self,
        vendor: Option<&str>,
        product: Option<&str>,
        vendor_exact: Option<&str>,
        product_exact: Option<&str>,
        state_scope: CveStateScope,
    ) -> Result<u64, DbErr> {
        if matches!(self.db.get_database_backend(), DbBackend::Sqlite)
            && vendor_exact.is_none()
            && product_exact.is_none()
            && let Some(query) = affected_fts_query(vendor, product)
        {
            return self
                .count_by_statement(
                    affected_fts_count_sql(state_scope),
                    vec![SeaValue::from(query)],
                )
                .await;
        }
        if matches!(self.db.get_database_backend(), DbBackend::Sqlite)
            && (vendor_exact.is_some() || product_exact.is_some())
        {
            return self
                .count_by_sql(affected_exact_count_sql(
                    vendor,
                    product,
                    vendor_exact,
                    product_exact,
                    state_scope,
                ))
                .await;
        }

        let mut query = cve::Entity::find().inner_join(cve_affected::Entity);

        if !state_scope.includes_rejected() {
            query = query.filter(cve::Column::State.eq(PUBLISHED_STATE));
        }
        query = apply_affected_filters(query, vendor, product, vendor_exact, product_exact);

        query.distinct().count(&self.db).await
    }

    /// Searches published CVE summaries by affected component name.
    pub async fn search_cve_summaries_by_affected_component(
        &self,
        vendor: Option<&str>,
        component: &str,
        published_since: Option<&str>,
        updated_since: Option<&str>,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, DbErr> {
        self.search_cve_summaries_by_affected_component_with_state_scope(
            vendor,
            component,
            published_since,
            updated_since,
            CveStateScope::PublishedOnly,
            limit,
            offset,
        )
        .await
    }

    /// Searches CVE summaries by affected component name and state scope.
    pub async fn search_cve_summaries_by_affected_component_with_state_scope(
        &self,
        vendor: Option<&str>,
        component: &str,
        published_since: Option<&str>,
        updated_since: Option<&str>,
        state_scope: CveStateScope,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, DbErr> {
        self.search_cve_summaries_by_affected_component_exact_with_state_scope(
            vendor,
            component,
            None,
            None,
            published_since,
            updated_since,
            state_scope,
            limit,
            offset,
        )
        .await
    }

    /// Searches CVE summaries by affected component with exact vendor/product options.
    pub async fn search_cve_summaries_by_affected_component_exact_with_state_scope(
        &self,
        vendor: Option<&str>,
        component: &str,
        vendor_exact: Option<&str>,
        product_exact: Option<&str>,
        published_since: Option<&str>,
        updated_since: Option<&str>,
        state_scope: CveStateScope,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, DbErr> {
        let pattern = like_pattern(component);
        let mut query = cve::Entity::find()
            .select_only()
            .columns(summary_columns())
            .inner_join(cve_affected::Entity)
            .filter(
                cve_affected::Column::Product
                    .like(pattern.clone())
                    .or(cve_affected::Column::PackageName.like(pattern)),
            );

        if !state_scope.includes_rejected() {
            query = query.filter(cve::Column::State.eq(PUBLISHED_STATE));
        }
        query = apply_affected_filters(query, vendor, None, vendor_exact, product_exact);
        if let Some(published_since) = published_since {
            query = query.filter(cve::Column::PublishedAt.gte(published_since));
        }
        if let Some(updated_since) = updated_since {
            query = query.filter(cve::Column::UpdatedAt.gte(updated_since));
        }

        query
            .distinct()
            .order_by_desc(cve::Column::PublishedAt)
            .order_by_asc(cve::Column::CveId)
            .limit(limit)
            .offset(offset)
            .into_model::<CveSummary>()
            .all(&self.db)
            .await
    }

    /// Searches published CVE base rows by CVE ID, title, or description text.
    pub async fn search_cves_by_text(
        &self,
        query: &str,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<cve::Model>, DbErr> {
        self.search_cves_by_text_with_state_scope(
            query,
            CveStateScope::PublishedOnly,
            limit,
            offset,
        )
        .await
    }

    /// Searches CVE base rows by text with explicit rejected-record handling.
    pub async fn search_cves_by_text_with_state_scope(
        &self,
        query: &str,
        state_scope: CveStateScope,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<cve::Model>, DbErr> {
        let pattern = like_pattern(query);

        let mut query = cve::Entity::find().filter(
            cve::Column::CveId
                .like(pattern.clone())
                .or(cve::Column::Title.like(pattern.clone()))
                .or(cve::Column::DescriptionEn.like(pattern)),
        );
        if !state_scope.includes_rejected() {
            query = query.filter(cve::Column::State.eq(PUBLISHED_STATE));
        }
        query
            .order_by_desc(cve::Column::PublishedAt)
            .order_by_asc(cve::Column::CveId)
            .limit(limit)
            .offset(offset)
            .all(&self.db)
            .await
    }

    /// Searches published CVE summaries by text and recognized query prefixes.
    pub async fn search_cve_summaries_by_text(
        &self,
        query: &str,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, DbErr> {
        self.search_cve_summaries_by_text_with_state_scope(
            query,
            CveStateScope::PublishedOnly,
            limit,
            offset,
        )
        .await
    }

    /// Searches CVE summaries by text and recognized query prefixes with state scope.
    pub async fn search_cve_summaries_by_text_with_state_scope(
        &self,
        query: &str,
        state_scope: CveStateScope,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, DbErr> {
        let query = query.trim();
        if is_cve_id_prefix_query(query) {
            return self
                .search_cve_summaries_by_cve_id_prefix_with_state_scope(
                    query,
                    state_scope,
                    limit,
                    offset,
                )
                .await;
        }
        if is_cwe_id_query(query) {
            let Some(cwe_id) = cwe_number(query) else {
                return Ok(Vec::new());
            };
            return self
                .search_cve_summaries_by_cwe_with_state_scope(
                    &[cwe_id.to_string()],
                    state_scope,
                    limit,
                    offset,
                )
                .await;
        }
        if is_dateish_query(query) {
            return self
                .search_cve_summaries_by_date_prefix_with_state_scope(
                    query,
                    state_scope,
                    limit,
                    offset,
                )
                .await;
        }
        if matches!(self.db.get_database_backend(), DbBackend::Sqlite)
            && let Some(fts_query) = fts_query(query)
        {
            return self
                .search_cve_summaries_by_fts_text_with_state_scope(
                    &fts_query,
                    state_scope,
                    limit,
                    offset,
                )
                .await;
        }

        let pattern = like_pattern(query);

        let mut search = cve::Entity::find()
            .select_only()
            .columns(summary_columns())
            .filter(
                cve::Column::CveId
                    .like(pattern.clone())
                    .or(cve::Column::Title.like(pattern.clone()))
                    .or(cve::Column::DescriptionEn.like(pattern)),
            );
        if !state_scope.includes_rejected() {
            search = search.filter(cve::Column::State.eq(PUBLISHED_STATE));
        }
        search
            .order_by_desc(cve::Column::PublishedAt)
            .order_by_asc(cve::Column::CveId)
            .limit(limit)
            .offset(offset)
            .into_model::<CveSummary>()
            .all(&self.db)
            .await
    }

    /// Searches published CVE summaries whose IDs start with the prefix.
    pub async fn search_cve_summaries_by_cve_id_prefix(
        &self,
        prefix: &str,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, DbErr> {
        self.search_cve_summaries_by_cve_id_prefix_with_state_scope(
            prefix,
            CveStateScope::PublishedOnly,
            limit,
            offset,
        )
        .await
    }

    /// Searches CVE summaries by ID prefix with explicit rejected-record handling.
    pub async fn search_cve_summaries_by_cve_id_prefix_with_state_scope(
        &self,
        prefix: &str,
        state_scope: CveStateScope,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, DbErr> {
        let prefix = prefix.trim().to_ascii_uppercase();
        let Some(upper_bound) = ascii_prefix_upper_bound(&prefix) else {
            return Ok(Vec::new());
        };

        if !matches!(self.db.get_database_backend(), DbBackend::Sqlite) {
            let mut query = cve::Entity::find()
                .select_only()
                .columns(summary_columns())
                .filter(
                    cve::Column::CveId
                        .gte(prefix)
                        .and(cve::Column::CveId.lt(upper_bound)),
                );
            if !state_scope.includes_rejected() {
                query = query.filter(cve::Column::State.eq(PUBLISHED_STATE));
            }
            return query
                .order_by_asc(cve::Column::CveId)
                .limit(limit)
                .offset(offset)
                .into_model::<CveSummary>()
                .all(&self.db)
                .await;
        }

        CveSummary::find_by_statement(Statement::from_sql_and_values(
            self.db.get_database_backend(),
            cve_id_prefix_summary_index_sql(state_scope),
            vec![
                SeaValue::from(prefix),
                SeaValue::from(upper_bound),
                SeaValue::from(limit as i64),
                SeaValue::from(offset as i64),
            ],
        ))
        .all(&self.db)
        .await
    }

    /// Counts published CVE summaries whose IDs start with the prefix.
    pub async fn count_cve_summaries_by_cve_id_prefix(&self, prefix: &str) -> Result<u64, DbErr> {
        self.count_cve_summaries_by_cve_id_prefix_with_state_scope(
            prefix,
            CveStateScope::PublishedOnly,
        )
        .await
    }

    /// Counts CVE summaries by ID prefix with explicit rejected-record handling.
    pub async fn count_cve_summaries_by_cve_id_prefix_with_state_scope(
        &self,
        prefix: &str,
        state_scope: CveStateScope,
    ) -> Result<u64, DbErr> {
        let prefix = prefix.trim().to_ascii_uppercase();
        let Some(upper_bound) = ascii_prefix_upper_bound(&prefix) else {
            return Ok(0);
        };

        if !matches!(self.db.get_database_backend(), DbBackend::Sqlite) {
            let mut query = cve::Entity::find().filter(
                cve::Column::CveId
                    .gte(prefix)
                    .and(cve::Column::CveId.lt(upper_bound)),
            );
            if !state_scope.includes_rejected() {
                query = query.filter(cve::Column::State.eq(PUBLISHED_STATE));
            }
            return query.count(&self.db).await;
        }

        self.count_by_statement(
            cve_id_prefix_count_sql(state_scope),
            vec![SeaValue::from(prefix), SeaValue::from(upper_bound)],
        )
        .await
    }

    /// Searches published CVE summaries by publication or update date prefix.
    pub async fn search_cve_summaries_by_date_prefix(
        &self,
        prefix: &str,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, DbErr> {
        self.search_cve_summaries_by_date_prefix_with_state_scope(
            prefix,
            CveStateScope::PublishedOnly,
            limit,
            offset,
        )
        .await
    }

    /// Searches CVE summaries by date prefix with explicit rejected-record handling.
    pub async fn search_cve_summaries_by_date_prefix_with_state_scope(
        &self,
        prefix: &str,
        state_scope: CveStateScope,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, DbErr> {
        let prefix = prefix.trim();
        let Some(upper_bound) = ascii_prefix_upper_bound(prefix) else {
            return Ok(Vec::new());
        };

        if !matches!(self.db.get_database_backend(), DbBackend::Sqlite) {
            let condition = cve::Column::PublishedAt
                .gte(prefix.to_owned())
                .and(cve::Column::PublishedAt.lt(upper_bound.clone()))
                .or(cve::Column::UpdatedAt
                    .gte(prefix.to_owned())
                    .and(cve::Column::UpdatedAt.lt(upper_bound)));
            let mut query = cve::Entity::find()
                .select_only()
                .columns(summary_columns())
                .filter(condition)
                .distinct();
            if !state_scope.includes_rejected() {
                query = query.filter(cve::Column::State.eq(PUBLISHED_STATE));
            }
            return query
                .order_by_desc(cve::Column::PublishedAt)
                .order_by_asc(cve::Column::CveId)
                .limit(limit)
                .offset(offset)
                .into_model::<CveSummary>()
                .all(&self.db)
                .await;
        }

        CveSummary::find_by_statement(Statement::from_sql_and_values(
            self.db.get_database_backend(),
            date_prefix_summary_sql(state_scope),
            vec![
                SeaValue::from(prefix.to_owned()),
                SeaValue::from(upper_bound.clone()),
                SeaValue::from(prefix.to_owned()),
                SeaValue::from(upper_bound),
                SeaValue::from(limit as i64),
                SeaValue::from(offset as i64),
            ],
        ))
        .all(&self.db)
        .await
    }

    /// Counts published CVE summaries matching a publication or update date prefix.
    pub async fn count_cve_summaries_by_date_prefix(&self, prefix: &str) -> Result<u64, DbErr> {
        self.count_cve_summaries_by_date_prefix_with_state_scope(
            prefix,
            CveStateScope::PublishedOnly,
        )
        .await
    }

    /// Counts CVE summaries by date prefix with explicit rejected-record handling.
    pub async fn count_cve_summaries_by_date_prefix_with_state_scope(
        &self,
        prefix: &str,
        state_scope: CveStateScope,
    ) -> Result<u64, DbErr> {
        let prefix = prefix.trim();
        let Some(upper_bound) = ascii_prefix_upper_bound(prefix) else {
            return Ok(0);
        };

        if !matches!(self.db.get_database_backend(), DbBackend::Sqlite) {
            let condition = cve::Column::PublishedAt
                .gte(prefix.to_owned())
                .and(cve::Column::PublishedAt.lt(upper_bound.clone()))
                .or(cve::Column::UpdatedAt
                    .gte(prefix.to_owned())
                    .and(cve::Column::UpdatedAt.lt(upper_bound)));
            let mut query = cve::Entity::find().filter(condition).distinct();
            if !state_scope.includes_rejected() {
                query = query.filter(cve::Column::State.eq(PUBLISHED_STATE));
            }
            return query.count(&self.db).await;
        }

        self.count_by_statement(
            date_prefix_count_sql(state_scope),
            vec![
                SeaValue::from(prefix.to_owned()),
                SeaValue::from(upper_bound.clone()),
                SeaValue::from(prefix.to_owned()),
                SeaValue::from(upper_bound),
            ],
        )
        .await
    }

    /// Searches published CVE summaries using the same broad query behavior as the CLI.
    pub async fn search_cve_summaries_free_text(
        &self,
        query: &str,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, DbErr> {
        self.search_cve_summaries_free_text_with_state_scope(
            query,
            CveStateScope::PublishedOnly,
            limit,
            offset,
        )
        .await
    }

    /// Searches CVE summaries using broad CLI-style matching and state scope.
    pub async fn search_cve_summaries_free_text_with_state_scope(
        &self,
        query: &str,
        state_scope: CveStateScope,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, DbErr> {
        let query = query.trim();
        if query.is_empty() {
            return self
                .search_cve_summaries_by_date_with_state_scope(
                    None,
                    None,
                    state_scope,
                    limit,
                    offset,
                )
                .await;
        }

        let candidate_limit = limit.saturating_add(offset).max(limit);
        let cwe_id = cwe_number(query);
        let mut cves = Vec::new();
        let mut searched_osv = false;

        if is_cve_id_prefix_query(query) {
            append_unique_summaries(
                &mut cves,
                self.search_cve_summaries_by_cve_id_prefix_with_state_scope(
                    query,
                    state_scope,
                    candidate_limit,
                    0,
                )
                .await?,
            );
        } else if is_dateish_query(query) {
            append_unique_summaries(
                &mut cves,
                self.search_cve_summaries_by_date_prefix_with_state_scope(
                    query,
                    state_scope,
                    candidate_limit,
                    0,
                )
                .await?,
            );
        } else if is_cwe_id_query(query) {
            let Some(cwe_id) = cwe_id else {
                return Ok(Vec::new());
            };
            append_unique_summaries(
                &mut cves,
                self.search_cve_summaries_by_cwe_with_state_scope(
                    &[cwe_id.to_string()],
                    state_scope,
                    candidate_limit,
                    0,
                )
                .await?,
            );
        } else if let Some(cwe_id) = cwe_id {
            append_unique_summaries(
                &mut cves,
                self.search_cve_summaries_by_cwe_with_state_scope(
                    &[cwe_id.to_string()],
                    state_scope,
                    candidate_limit,
                    0,
                )
                .await?,
            );
        } else if matches!(self.db.get_database_backend(), DbBackend::Sqlite)
            && let Some(fts_query) = fts_query(query)
        {
            if cwe_id.is_none() {
                searched_osv = true;
                if is_identifier_like_query(query) {
                    append_unique_summaries(
                        &mut cves,
                        self.search_cve_summaries_by_osv_alias(
                            query,
                            state_scope,
                            candidate_limit,
                            0,
                        )
                        .await?,
                    );
                }
                let osv_cves = if let Some(token) = single_fts_token(query) {
                    self.search_cve_summaries_by_osv_token(&token, state_scope, candidate_limit, 0)
                        .await?
                } else {
                    self.search_cve_summaries_by_osv_free_text(
                        query,
                        state_scope,
                        candidate_limit,
                        0,
                    )
                    .await?
                };
                append_unique_summaries(&mut cves, osv_cves);
            }
            if cves.len() < candidate_limit as usize {
                append_unique_summaries(
                    &mut cves,
                    self.search_cve_summaries_by_fts_text_with_state_scope(
                        &fts_query,
                        state_scope,
                        candidate_limit,
                        0,
                    )
                    .await?,
                );
            }
        } else {
            append_unique_summaries(
                &mut cves,
                self.search_cve_summaries_by_cve_free_text(query, state_scope, candidate_limit, 0)
                    .await?,
            );
        }

        if cwe_id.is_none()
            && !matches!(self.db.get_database_backend(), DbBackend::Sqlite)
            && should_search_affected_text(query)
        {
            append_unique_summaries(
                &mut cves,
                self.search_cve_summaries_by_affected_text(query, state_scope, candidate_limit, 0)
                    .await?,
            );
        }
        if cwe_id.is_none()
            && matches!(self.db.get_database_backend(), DbBackend::Sqlite)
            && !searched_osv
        {
            append_unique_summaries(
                &mut cves,
                self.search_cve_summaries_by_osv_free_text(query, state_scope, candidate_limit, 0)
                    .await?,
            );
        }

        cves.sort_by(|left, right| {
            right
                .published_at
                .cmp(&left.published_at)
                .then_with(|| left.cve_id.cmp(&right.cve_id))
        });
        let cves = cves
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .collect();

        Ok(cves)
    }

    /// Counts published CVE summaries matching broad CLI-style text search.
    pub async fn count_cve_summaries_free_text(&self, query: &str) -> Result<u64, DbErr> {
        self.count_cve_summaries_free_text_with_state_scope(query, CveStateScope::PublishedOnly)
            .await
    }

    /// Counts CVE summaries matching broad CLI-style text search and state scope.
    pub async fn count_cve_summaries_free_text_with_state_scope(
        &self,
        query: &str,
        state_scope: CveStateScope,
    ) -> Result<u64, DbErr> {
        let query = query.trim();
        if query.is_empty() {
            if matches!(self.db.get_database_backend(), DbBackend::Sqlite) {
                let sql = if state_scope.includes_rejected() {
                    "SELECT COUNT(*) AS count FROM cve_summary_index INDEXED BY idx_cve_summary_cve_id"
                } else {
                    "SELECT COUNT(*) AS count FROM cve_summary_index INDEXED BY idx_cve_summary_state_published WHERE state = 0"
                };
                return self.count_by_sql(sql.to_owned()).await;
            }
            let mut count = cve::Entity::find();
            if !state_scope.includes_rejected() {
                count = count.filter(cve::Column::State.eq(PUBLISHED_STATE));
            }
            return count.count(&self.db).await;
        }

        let cwe_id = cwe_number(query);
        if is_cve_id_prefix_query(query) {
            self.count_cve_summaries_by_cve_id_prefix_with_state_scope(query, state_scope)
                .await
        } else if is_dateish_query(query) {
            self.count_cve_summaries_by_date_prefix_with_state_scope(query, state_scope)
                .await
        } else if is_cwe_id_query(query) {
            let Some(cwe_id) = cwe_id else {
                return Ok(0);
            };
            self.count_cve_summaries_by_cwe_with_state_scope(&[cwe_id.to_string()], state_scope)
                .await
        } else if let Some(cwe_id) = cwe_id {
            self.count_cve_summaries_by_cwe_with_state_scope(&[cwe_id.to_string()], state_scope)
                .await
        } else if matches!(self.db.get_database_backend(), DbBackend::Sqlite)
            && let Some(fts_query) = fts_query(query)
        {
            if let Some(token) = single_fts_token(query) {
                self.count_cve_summaries_by_fts_or_osv_token(&token, state_scope)
                    .await
            } else {
                self.count_cve_summaries_by_fts_or_osv_text(&fts_query, query, state_scope)
                    .await
            }
        } else {
            let pattern = like_pattern(query);
            let mut count = cve::Entity::find().filter(
                cve::Column::CveId
                    .like(pattern.clone())
                    .or(cve::Column::Title.like(pattern.clone()))
                    .or(cve::Column::DescriptionEn.like(pattern.clone()))
                    .or(cve::Column::PublishedAt.like(pattern.clone()))
                    .or(cve::Column::UpdatedAt.like(pattern)),
            );
            if !state_scope.includes_rejected() {
                count = count.filter(cve::Column::State.eq(PUBLISHED_STATE));
            }
            count.count(&self.db).await
        }
    }

    /// Searches published CVE summaries using a SQLite FTS query string.
    pub async fn search_cve_summaries_by_fts_text(
        &self,
        query: &str,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, DbErr> {
        self.search_cve_summaries_by_fts_text_with_state_scope(
            query,
            CveStateScope::PublishedOnly,
            limit,
            offset,
        )
        .await
    }

    /// Searches CVE summaries using SQLite FTS with explicit rejected-record handling.
    pub async fn search_cve_summaries_by_fts_text_with_state_scope(
        &self,
        query: &str,
        state_scope: CveStateScope,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, DbErr> {
        let match_count = self
            .count_by_statement(
                "SELECT COUNT(*) AS count FROM cve_summary_fts WHERE cve_summary_fts MATCH ?",
                vec![SeaValue::from(query.to_owned())],
            )
            .await?;
        let sql = if match_count >= FTS_ORDER_SCAN_THRESHOLD {
            fts_ordered_summary_sql(state_scope)
        } else {
            fts_summary_sql(state_scope)
        };
        CveSummary::find_by_statement(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            sql,
            vec![
                SeaValue::from(query.to_owned()),
                SeaValue::from(limit as i64),
                SeaValue::from(offset as i64),
            ],
        ))
        .all(&self.db)
        .await
    }

    /// Counts published CVE summaries matching a SQLite FTS query string.
    pub async fn count_cve_summaries_by_fts_text(&self, query: &str) -> Result<u64, DbErr> {
        self.count_cve_summaries_by_fts_text_with_state_scope(query, CveStateScope::PublishedOnly)
            .await
    }

    /// Counts CVE summaries matching SQLite FTS with explicit rejected-record handling.
    pub async fn count_cve_summaries_by_fts_text_with_state_scope(
        &self,
        query: &str,
        state_scope: CveStateScope,
    ) -> Result<u64, DbErr> {
        self.count_by_statement(
            fts_count_sql(state_scope),
            vec![SeaValue::from(query.to_owned())],
        )
        .await
    }

    async fn search_cve_summaries_by_osv_free_text(
        &self,
        query: &str,
        state_scope: CveStateScope,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, DbErr> {
        if !matches!(self.db.get_database_backend(), DbBackend::Sqlite) {
            return Ok(Vec::new());
        }
        let Some(fts_query) = fts_query(query) else {
            return Ok(Vec::new());
        };
        let mut values = vec![SeaValue::from(fts_query)];
        values.push(SeaValue::from(limit as i64));
        values.push(SeaValue::from(offset as i64));
        CveSummary::find_by_statement(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            osv_free_text_summary_sql(state_scope),
            values,
        ))
        .all(&self.db)
        .await
    }

    async fn search_cve_summaries_by_osv_token(
        &self,
        token: &str,
        state_scope: CveStateScope,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, DbErr> {
        if !matches!(self.db.get_database_backend(), DbBackend::Sqlite) {
            return Ok(Vec::new());
        }
        let upper = token_prefix_upper_bound(token);
        let mut values = vec![SeaValue::from(token.to_owned())];
        values.push(SeaValue::from(upper));
        values.push(SeaValue::from(limit as i64));
        values.push(SeaValue::from(offset as i64));
        CveSummary::find_by_statement(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            osv_token_summary_sql(state_scope),
            values,
        ))
        .all(&self.db)
        .await
    }

    async fn count_cve_summaries_by_fts_or_osv_text(
        &self,
        cve_fts_query: &str,
        raw_query: &str,
        state_scope: CveStateScope,
    ) -> Result<u64, DbErr> {
        let pattern = like_pattern(raw_query);
        let mut values = vec![SeaValue::from(cve_fts_query.to_owned())];
        values.push(SeaValue::from(
            fts_query(raw_query).unwrap_or_else(|| pattern.clone()),
        ));
        let alias = normalize_identifier(raw_query);
        values.push(SeaValue::from(alias.clone()));
        let alias_upper = token_prefix_upper_bound(&alias);
        values.push(SeaValue::from(alias_upper.clone()));
        values.push(SeaValue::from(alias));
        values.push(SeaValue::from(alias_upper));
        self.count_by_statement(fts_or_osv_count_sql(state_scope), values)
            .await
    }

    async fn count_cve_summaries_by_fts_or_osv_token(
        &self,
        token: &str,
        state_scope: CveStateScope,
    ) -> Result<u64, DbErr> {
        let upper = token_prefix_upper_bound(token);
        let alias = normalize_identifier(token);
        let alias_upper = token_prefix_upper_bound(&alias);
        self.count_by_statement(
            fts_or_osv_token_count_sql(state_scope),
            vec![
                SeaValue::from(format!("{token}*")),
                SeaValue::from(token.to_owned()),
                SeaValue::from(upper),
                SeaValue::from(alias.clone()),
                SeaValue::from(alias_upper.clone()),
                SeaValue::from(alias),
                SeaValue::from(alias_upper),
            ],
        )
        .await
    }

    async fn search_cve_summaries_by_osv_alias(
        &self,
        query: &str,
        state_scope: CveStateScope,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, DbErr> {
        if !matches!(self.db.get_database_backend(), DbBackend::Sqlite) {
            return Ok(Vec::new());
        }
        let alias = normalize_identifier(query);
        if alias.len() < 2 {
            return Ok(Vec::new());
        }
        let upper = token_prefix_upper_bound(&alias);
        CveSummary::find_by_statement(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            osv_alias_summary_sql(state_scope),
            vec![
                SeaValue::from(alias),
                SeaValue::from(upper),
                SeaValue::from(limit as i64),
                SeaValue::from(offset as i64),
            ],
        ))
        .all(&self.db)
        .await
    }

    async fn search_cve_summaries_by_cve_free_text(
        &self,
        query: &str,
        state_scope: CveStateScope,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, DbErr> {
        let pattern = like_pattern(query);
        let condition = Condition::any()
            .add(cve::Column::CveId.like(pattern.clone()))
            .add(cve::Column::Title.like(pattern.clone()))
            .add(cve::Column::DescriptionEn.like(pattern.clone()))
            .add(cve::Column::PublishedAt.like(pattern.clone()))
            .add(cve::Column::UpdatedAt.like(pattern));

        let mut query = cve::Entity::find()
            .select_only()
            .columns(summary_columns())
            .filter(condition);
        if !state_scope.includes_rejected() {
            query = query.filter(cve::Column::State.eq(PUBLISHED_STATE));
        }
        query
            .order_by_desc(cve::Column::PublishedAt)
            .order_by_asc(cve::Column::CveId)
            .limit(limit)
            .offset(offset)
            .into_model::<CveSummary>()
            .all(&self.db)
            .await
    }

    async fn search_cve_summaries_by_affected_text(
        &self,
        query: &str,
        state_scope: CveStateScope,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, DbErr> {
        let pattern = like_pattern(query);
        let condition = Condition::any()
            .add(cve_affected::Column::Vendor.like(pattern.clone()))
            .add(cve_affected::Column::Product.like(pattern.clone()))
            .add(cve_affected::Column::PackageName.like(pattern));

        let mut search = cve::Entity::find()
            .select_only()
            .columns(summary_columns())
            .inner_join(cve_affected::Entity)
            .filter(condition)
            .distinct();
        if !state_scope.includes_rejected() {
            search = search.filter(cve::Column::State.eq(PUBLISHED_STATE));
        }
        let cves = search
            .order_by_desc(cve::Column::PublishedAt)
            .order_by_asc(cve::Column::CveId)
            .limit(limit)
            .offset(offset)
            .into_model::<CveSummary>()
            .all(&self.db)
            .await?;

        Ok(dedupe_summaries_by_cve_id(cves))
    }

    /// Searches published CVE summaries by CVSS score, severity, and version.
    pub async fn search_cve_summaries_by_cvss(
        &self,
        min_score: Option<f64>,
        max_score: Option<f64>,
        severity: Option<&str>,
        version: Option<&str>,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, DbErr> {
        self.search_cve_summaries_by_cvss_with_state_scope(
            min_score,
            max_score,
            severity,
            version,
            CveStateScope::PublishedOnly,
            limit,
            offset,
        )
        .await
    }

    /// Searches CVE summaries by CVSS filters with explicit rejected-record handling.
    pub async fn search_cve_summaries_by_cvss_with_state_scope(
        &self,
        min_score: Option<f64>,
        max_score: Option<f64>,
        severity: Option<&str>,
        version: Option<&str>,
        state_scope: CveStateScope,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, DbErr> {
        if matches!(self.db.get_database_backend(), DbBackend::Sqlite) {
            return CveSummary::find_by_statement(Statement::from_string(
                DbBackend::Sqlite,
                cvss_summary_index_sql(
                    min_score,
                    max_score,
                    severity,
                    version,
                    state_scope,
                    limit,
                    offset,
                ),
            ))
            .all(&self.db)
            .await;
        }
        let mut query = cve::Entity::find()
            .select_only()
            .columns(summary_columns())
            .inner_join(cve_cvss::Entity);

        if !state_scope.includes_rejected() {
            query = query.filter(cve::Column::State.eq(PUBLISHED_STATE));
        }
        if let Some(min_score) = min_score {
            query = query.filter(cve_cvss::Column::BaseScore.gte(min_score));
        }
        if let Some(max_score) = max_score {
            query = query.filter(cve_cvss::Column::BaseScore.lte(max_score));
        }
        if let Some(severity) = severity {
            query = query.filter(cve_cvss::Column::BaseSeverity.eq(severity.to_ascii_uppercase()));
        }
        if let Some(version) = version {
            query = query.filter(cve_cvss::Column::Version.eq(version));
        }

        query
            .distinct()
            .order_by_desc(cve::Column::PublishedAt)
            .order_by_asc(cve::Column::CveId)
            .limit(limit)
            .offset(offset)
            .into_model::<CveSummary>()
            .all(&self.db)
            .await
    }

    /// Searches published CVE summaries by affected product plus CVSS risk filters.
    pub async fn search_cve_summaries_by_product_cvss(
        &self,
        vendor: Option<&str>,
        product: Option<&str>,
        min_score: Option<f64>,
        severity: Option<&str>,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, DbErr> {
        self.search_cve_summaries_by_product_cvss_with_state_scope(
            vendor,
            product,
            min_score,
            severity,
            CveStateScope::PublishedOnly,
            limit,
            offset,
        )
        .await
    }

    /// Searches CVE summaries by affected product and CVSS filters with state scope.
    pub async fn search_cve_summaries_by_product_cvss_with_state_scope(
        &self,
        vendor: Option<&str>,
        product: Option<&str>,
        min_score: Option<f64>,
        severity: Option<&str>,
        state_scope: CveStateScope,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, DbErr> {
        self.search_cve_summaries_by_product_cvss_exact_with_state_scope(
            vendor,
            product,
            None,
            None,
            min_score,
            None,
            severity,
            None,
            state_scope,
            limit,
            offset,
        )
        .await
    }

    /// Searches CVE summaries by exact affected filters plus CVSS filters.
    pub async fn search_cve_summaries_by_product_cvss_exact_with_state_scope(
        &self,
        vendor: Option<&str>,
        product: Option<&str>,
        vendor_exact: Option<&str>,
        product_exact: Option<&str>,
        min_score: Option<f64>,
        max_score: Option<f64>,
        severity: Option<&str>,
        version: Option<&str>,
        state_scope: CveStateScope,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, DbErr> {
        if matches!(self.db.get_database_backend(), DbBackend::Sqlite)
            && vendor_exact.is_none()
            && product_exact.is_none()
        {
            return CveSummary::find_by_statement(Statement::from_string(
                DbBackend::Sqlite,
                product_cvss_summary_index_sql(
                    vendor,
                    product,
                    min_score,
                    max_score,
                    severity,
                    version,
                    state_scope,
                    limit,
                    offset,
                ),
            ))
            .all(&self.db)
            .await;
        }
        let mut query = cve::Entity::find()
            .select_only()
            .columns(summary_columns())
            .inner_join(cve_affected::Entity)
            .inner_join(cve_cvss::Entity);

        if !state_scope.includes_rejected() {
            query = query.filter(cve::Column::State.eq(PUBLISHED_STATE));
        }
        query = apply_affected_filters(query, vendor, product, vendor_exact, product_exact);
        if let Some(min_score) = min_score {
            query = query.filter(cve_cvss::Column::BaseScore.gte(min_score));
        }
        if let Some(max_score) = max_score {
            query = query.filter(cve_cvss::Column::BaseScore.lte(max_score));
        }
        if let Some(severity) = severity {
            query = query.filter(cve_cvss::Column::BaseSeverity.eq(severity.to_ascii_uppercase()));
        }
        if let Some(version) = version {
            query = query.filter(cve_cvss::Column::Version.eq(version));
        }

        query
            .distinct()
            .order_by_desc(cve::Column::PublishedAt)
            .order_by_asc(cve::Column::CveId)
            .limit(limit)
            .offset(offset)
            .into_model::<CveSummary>()
            .all(&self.db)
            .await
    }

    /// Searches published CVE summaries by publication and update lower bounds.
    pub async fn search_cve_summaries_by_date(
        &self,
        published_since: Option<&str>,
        updated_since: Option<&str>,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, DbErr> {
        self.search_cve_summaries_by_date_with_state_scope(
            published_since,
            updated_since,
            CveStateScope::PublishedOnly,
            limit,
            offset,
        )
        .await
    }

    /// Searches CVE summaries by publication and update lower bounds with state scope.
    pub async fn search_cve_summaries_by_date_with_state_scope(
        &self,
        published_since: Option<&str>,
        updated_since: Option<&str>,
        state_scope: CveStateScope,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, DbErr> {
        if matches!(self.db.get_database_backend(), DbBackend::Sqlite) {
            return CveSummary::find_by_statement(Statement::from_string(
                DbBackend::Sqlite,
                date_summary_index_sql(published_since, updated_since, state_scope, limit, offset),
            ))
            .all(&self.db)
            .await;
        }

        let mut query = cve::Entity::find().select_only().columns(summary_columns());

        if !state_scope.includes_rejected() {
            query = query.filter(cve::Column::State.eq(PUBLISHED_STATE));
        }
        if let Some(published_since) = published_since {
            query = query.filter(cve::Column::PublishedAt.gte(published_since));
        }
        if let Some(updated_since) = updated_since {
            query = query.filter(cve::Column::UpdatedAt.gte(updated_since));
        }

        query
            .order_by_desc(cve::Column::PublishedAt)
            .order_by_asc(cve::Column::CveId)
            .limit(limit)
            .offset(offset)
            .into_model::<CveSummary>()
            .all(&self.db)
            .await
    }

    /// Executes the structured advanced search used by the TUI.
    pub async fn search_cve_summaries_advanced(
        &self,
        options: &CveAdvancedSearch,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, DbErr> {
        if let Some(cwe) = options.cwe.as_deref().filter(|cwe| !cwe.trim().is_empty())
            && cwe_number(cwe).is_none()
        {
            return Ok(Vec::new());
        }
        if matches!(options.query_mode, Some(CveAdvancedQueryMode::Cwe))
            && let Some(query) = options
                .query
                .as_deref()
                .filter(|query| !query.trim().is_empty())
            && cwe_number(query).is_none()
        {
            return Ok(Vec::new());
        }

        if matches!(self.db.get_database_backend(), DbBackend::Sqlite) {
            if (option_text(options.vendor_exact.as_deref()).is_some()
                || option_text(options.product_exact.as_deref()).is_some())
                && option_text(options.query.as_deref()).is_none()
                && option_text(options.cwe.as_deref()).is_none()
            {
                return CveSummary::find_by_statement(Statement::from_string(
                    DbBackend::Sqlite,
                    affected_exact_summary_sql(
                        option_text(options.vendor.as_deref()),
                        option_text(options.product.as_deref()),
                        option_text(options.vendor_exact.as_deref()),
                        option_text(options.product_exact.as_deref()),
                        option_text(options.published_from.as_deref()),
                        option_text(options.published_to.as_deref()),
                        None,
                        options.state_scope,
                        options.sort_order,
                        limit,
                        offset,
                    ),
                ))
                .all(&self.db)
                .await;
            }
            return CveSummary::find_by_statement(Statement::from_string(
                DbBackend::Sqlite,
                advanced_summary_sql(options, limit, offset),
            ))
            .all(&self.db)
            .await;
        }

        let mut query = cve::Entity::find().select_only().columns(summary_columns());

        if !options.state_scope.includes_rejected() {
            query = query.filter(cve::Column::State.eq(PUBLISHED_STATE));
        }
        if let Some(search_query) = option_text(options.query.as_deref()) {
            query = apply_advanced_query_filter(query, options.query_mode, search_query);
        }
        if let Some(published_from) = option_text(options.published_from.as_deref()) {
            query = query.filter(cve::Column::PublishedAt.gte(published_from.to_owned()));
        }
        if let Some(published_to) = option_text(options.published_to.as_deref()) {
            query = query.filter(cve::Column::PublishedAt.lte(published_to.to_owned()));
        }
        if let Some(cwe) = option_text(options.cwe.as_deref())
            && let Some(cwe_id) = cwe_number(cwe)
        {
            query = query
                .inner_join(cve_cwe::Entity)
                .filter(cve_cwe::Column::CweId.eq(cwe_id));
        }
        if option_text(options.vendor.as_deref()).is_some()
            || option_text(options.product.as_deref()).is_some()
            || option_text(options.vendor_exact.as_deref()).is_some()
            || option_text(options.product_exact.as_deref()).is_some()
        {
            query = query.inner_join(cve_affected::Entity);
            query = apply_affected_filters(
                query,
                option_text(options.vendor.as_deref()),
                option_text(options.product.as_deref()),
                option_text(options.vendor_exact.as_deref()),
                option_text(options.product_exact.as_deref()),
            );
        }

        let query = match options.sort_order {
            CveSummarySortOrder::PublishedAsc => query.order_by_asc(cve::Column::PublishedAt),
            CveSummarySortOrder::UpdatedAsc => query.order_by_asc(cve::Column::UpdatedAt),
            CveSummarySortOrder::UpdatedDesc => query.order_by_desc(cve::Column::UpdatedAt),
            CveSummarySortOrder::PublishedDesc
            | CveSummarySortOrder::RelationRankAsc
            | CveSummarySortOrder::RelationRankDesc
            | CveSummarySortOrder::ScoreAsc
            | CveSummarySortOrder::ScoreDesc => query.order_by_desc(cve::Column::PublishedAt),
            CveSummarySortOrder::CveIdAsc => query.order_by_asc(cve::Column::CveId),
            CveSummarySortOrder::CveIdDesc => query.order_by_desc(cve::Column::CveId),
        };

        query
            .distinct()
            .order_by_asc(cve::Column::CveId)
            .limit(limit)
            .offset(offset)
            .into_model::<CveSummary>()
            .all(&self.db)
            .await
    }

    /// Counts rows for the structured advanced search used by the TUI.
    pub async fn count_cve_summaries_advanced(
        &self,
        options: &CveAdvancedSearch,
    ) -> Result<u64, DbErr> {
        if let Some(cwe) = options.cwe.as_deref().filter(|cwe| !cwe.trim().is_empty())
            && cwe_number(cwe).is_none()
        {
            return Ok(0);
        }
        if matches!(options.query_mode, Some(CveAdvancedQueryMode::Cwe))
            && let Some(query) = options
                .query
                .as_deref()
                .filter(|query| !query.trim().is_empty())
            && cwe_number(query).is_none()
        {
            return Ok(0);
        }

        if matches!(self.db.get_database_backend(), DbBackend::Sqlite) {
            if (option_text(options.vendor_exact.as_deref()).is_some()
                || option_text(options.product_exact.as_deref()).is_some())
                && option_text(options.query.as_deref()).is_none()
                && option_text(options.cwe.as_deref()).is_none()
            {
                return self
                    .count_by_sql(affected_exact_count_sql(
                        option_text(options.vendor.as_deref()),
                        option_text(options.product.as_deref()),
                        option_text(options.vendor_exact.as_deref()),
                        option_text(options.product_exact.as_deref()),
                        options.state_scope,
                    ))
                    .await;
            }
            return self.count_by_sql(advanced_count_sql(options)).await;
        }

        let mut query = cve::Entity::find();

        if !options.state_scope.includes_rejected() {
            query = query.filter(cve::Column::State.eq(PUBLISHED_STATE));
        }
        if let Some(search_query) = option_text(options.query.as_deref()) {
            query = apply_advanced_query_filter(query, options.query_mode, search_query);
        }
        if let Some(published_from) = option_text(options.published_from.as_deref()) {
            query = query.filter(cve::Column::PublishedAt.gte(published_from.to_owned()));
        }
        if let Some(published_to) = option_text(options.published_to.as_deref()) {
            query = query.filter(cve::Column::PublishedAt.lte(published_to.to_owned()));
        }
        if let Some(cwe) = option_text(options.cwe.as_deref())
            && let Some(cwe_id) = cwe_number(cwe)
        {
            query = query
                .inner_join(cve_cwe::Entity)
                .filter(cve_cwe::Column::CweId.eq(cwe_id));
        }
        if option_text(options.vendor.as_deref()).is_some()
            || option_text(options.product.as_deref()).is_some()
            || option_text(options.vendor_exact.as_deref()).is_some()
            || option_text(options.product_exact.as_deref()).is_some()
        {
            query = query.inner_join(cve_affected::Entity);
            query = apply_affected_filters(
                query,
                option_text(options.vendor.as_deref()),
                option_text(options.product.as_deref()),
                option_text(options.vendor_exact.as_deref()),
                option_text(options.product_exact.as_deref()),
            );
        }

        query.distinct().count(&self.db).await
    }

    async fn count_by_sql(&self, sql: String) -> Result<u64, DbErr> {
        self.count_by_statement(&sql, Vec::new()).await
    }

    async fn count_by_statement(&self, sql: &str, values: Vec<SeaValue>) -> Result<u64, DbErr> {
        let row = self
            .db
            .query_one(Statement::from_sql_and_values(
                self.db.get_database_backend(),
                sql,
                values,
            ))
            .await?;
        let Some(row) = row else {
            return Ok(0);
        };
        let count = row.try_get::<i64>("", "count")?;
        Ok(count.max(0) as u64)
    }

    /// Marks one CVE JSON file as read for incremental import bookkeeping.
    pub async fn mark_json_file_read(&self, filename: &str, md5hash: &str) -> Result<(), DbErr> {
        self.mark_json_files_read(vec![ReadJsonFileRecord {
            filename: filename.to_owned(),
            md5hash: md5hash.to_owned(),
        }])
        .await?;

        Ok(())
    }

    /// Marks multiple CVE JSON files as read for incremental import bookkeeping.
    pub async fn mark_json_files_read(
        &self,
        files: Vec<ReadJsonFileRecord>,
    ) -> Result<usize, DbErr> {
        mark_json_files_read_on(&self.db, files, true).await
    }

    /// Finds an import bookkeeping row for a CVE JSON file and content hash.
    pub async fn find_read_json_file(
        &self,
        filename: &str,
        md5hash: &str,
    ) -> Result<Option<read_json_file::Model>, DbErr> {
        read_json_file::Entity::find()
            .filter(read_json_file::Column::Filename.eq(filename))
            .filter(read_json_file::Column::Md5hash.eq(md5hash))
            .one(&self.db)
            .await
    }

    /// Records that a CVE zip archive has been applied.
    pub async fn mark_cve_zip_file_applied(&self, record: CveZipFileRecord) -> Result<(), DbErr> {
        let now = Utc::now().to_rfc3339();
        cve_zip_file::Entity::insert(cve_zip_file::ActiveModel {
            id: Default::default(),
            created_at: Set(now),
            zip_filename: Set(record.zip_filename),
            zip_datetime: Set(record.zip_datetime),
            zip_type: Set(record.zip_type),
        })
        .on_conflict(
            OnConflict::column(cve_zip_file::Column::ZipFilename)
                .update_columns([
                    cve_zip_file::Column::ZipDatetime,
                    cve_zip_file::Column::ZipType,
                ])
                .to_owned(),
        )
        .exec(&self.db)
        .await?;
        Ok(())
    }

    /// Returns the newest applied CVE zip timestamp.
    pub async fn latest_cve_zip_datetime(&self) -> Result<Option<String>, DbErr> {
        cve_zip_file::Entity::find()
            .order_by_desc(cve_zip_file::Column::ZipDatetime)
            .order_by_desc(cve_zip_file::Column::Id)
            .one(&self.db)
            .await
            .map(|row| row.map(|row| row.zip_datetime))
    }

    /// Returns the newest `updated_at` value currently stored for CVEs.
    pub async fn latest_cve_updated_at(&self) -> Result<Option<String>, DbErr> {
        cve::Entity::find()
            .select_only()
            .column_as(cve::Column::UpdatedAt.max(), "updated_at")
            .into_tuple::<Option<String>>()
            .one(&self.db)
            .await
            .map(|value| value.flatten().filter(|value| !value.is_empty()))
    }

    /// Returns aggregate status for CVE, CWE, affected, CVSS, and zip data.
    pub async fn database_status(&self) -> Result<CveDatabaseStatus, DbErr> {
        CveDatabaseStatus::find_by_statement(Statement::from_string(
            DbBackend::Sqlite,
            r#"
            SELECT
                (SELECT COUNT(*) FROM cve) AS cve_count,
                (SELECT COUNT(*) FROM cve WHERE state = 0) AS published_count,
                (SELECT COUNT(*) FROM cve WHERE state = 1) AS rejected_count,
                (SELECT COUNT(*) FROM cwe) AS cwe_count,
                (SELECT COUNT(*) FROM cve_affected) AS affected_count,
                (SELECT COUNT(*) FROM cve_cvss) AS cvss_count,
                (SELECT MAX(updated_at) FROM cve) AS latest_cve_updated_at,
                (SELECT zip_datetime FROM cve_zip_file ORDER BY zip_datetime DESC, id DESC LIMIT 1) AS latest_zip_datetime,
                (SELECT zip_filename FROM cve_zip_file ORDER BY zip_datetime DESC, id DESC LIMIT 1) AS latest_zip_filename
            "#
            .to_owned(),
        ))
        .one(&self.db)
        .await?
        .ok_or_else(|| DbErr::Custom("database status query returned no row".to_owned()))
    }

    /// Returns aggregate status for CVE data plus enrichment tables.
    pub async fn database_status_enriched(&self) -> Result<DatabaseStatus, DbErr> {
        let cve = self.database_status().await?;
        let sources = self.db_sources().await?;
        let enrichment = EnrichmentDatabaseStatus::find_by_statement(Statement::from_string(
            DbBackend::Sqlite,
            r#"
            SELECT
                (SELECT COUNT(*) FROM osv_advisories) AS osv_record_count,
                (SELECT COUNT(*) FROM kev_entries) AS kev_entry_count,
                (SELECT COUNT(*) FROM epss_current) AS epss_current_count,
                (SELECT COUNT(*) FROM vulnerability_identifiers) AS identifier_node_count,
                (SELECT COUNT(*) FROM vulnerability_identifier_edges) AS identifier_edge_count
            "#
            .to_owned(),
        ))
        .one(&self.db)
        .await?
        .ok_or_else(|| DbErr::Custom("enrichment status query returned no row".to_owned()))?;
        Ok(DatabaseStatus {
            cve,
            sources,
            enrichment,
        })
    }

    /// Returns synchronization state for all registered enrichment sources.
    pub async fn source_sync_states(&self) -> Result<Vec<SourceSyncState>, DbErr> {
        SourceSyncState::find_by_statement(Statement::from_string(
            DbBackend::Sqlite,
            "SELECT * FROM source_sync_state ORDER BY source".to_owned(),
        ))
        .all(&self.db)
        .await
    }

    /// Returns registered enrichment source definitions.
    pub async fn db_sources(&self) -> Result<Vec<DbSource>, DbErr> {
        DbSource::find_by_statement(Statement::from_string(
            DbBackend::Sqlite,
            "SELECT source, display_name, source_type, default_filename, raw_format FROM db_sources ORDER BY source".to_owned(),
        ))
        .all(&self.db)
        .await
    }

    async fn raw_record_hashes(
        &self,
        source: &str,
        source_record_ids: &[String],
    ) -> Result<HashMap<String, String>, DbErr> {
        if source_record_ids.is_empty() {
            return Ok(HashMap::new());
        }
        let rows = self
            .db
            .query_all(Statement::from_string(
                DbBackend::Sqlite,
                format!(
                    "SELECT source_record_id, content_hash FROM source_raw_records WHERE source = {} AND source_record_id IN ({})",
                    sql_string_literal(source),
                    sql_string_list(source_record_ids)
                ),
            ))
            .await?;
        rows.into_iter()
            .map(|row| {
                Ok((
                    row.try_get::<String>("", "source_record_id")?,
                    row.try_get::<String>("", "content_hash")?,
                ))
            })
            .collect()
    }

    /// Reads one application metadata value by key.
    pub async fn metadata_value(&self, key: &str) -> Result<Option<String>, DbErr> {
        Ok(app_metadata::Entity::find_by_id(key.to_owned())
            .one(&self.db)
            .await?
            .map(|row| row.value))
    }

    /// Stores one application metadata value by key.
    pub async fn set_metadata_value(&self, key: &str, value: &str) -> Result<(), DbErr> {
        let model = app_metadata::ActiveModel {
            key: Set(key.to_owned()),
            value: Set(value.to_owned()),
            updated_at: Set(Utc::now().to_rfc3339()),
        };
        app_metadata::Entity::insert(model)
            .on_conflict(
                OnConflict::column(app_metadata::Column::Key)
                    .update_columns([app_metadata::Column::Value, app_metadata::Column::UpdatedAt])
                    .to_owned(),
            )
            .exec(&self.db)
            .await?;
        Ok(())
    }

    /// Imports raw OSV advisory records without an external cursor.
    pub async fn import_osv_records(
        &self,
        records: Vec<OsvRawRecord>,
    ) -> Result<ImportSummary, DbErr> {
        self.import_osv_records_with_cursor(records, None).await
    }

    /// Imports raw OSV advisory records and stores the source cursor.
    pub async fn import_osv_records_with_cursor(
        &self,
        records: Vec<OsvRawRecord>,
        last_cursor: Option<&str>,
    ) -> Result<ImportSummary, DbErr> {
        self.import_osv_records_with_cursor_and_count(records, last_cursor, None)
            .await
    }

    /// Imports raw OSV records with cursor and an optional total record count.
    pub async fn import_osv_records_with_cursor_and_count(
        &self,
        records: Vec<OsvRawRecord>,
        last_cursor: Option<&str>,
        record_count_override: Option<usize>,
    ) -> Result<ImportSummary, DbErr> {
        self.import_osv_records_with_cursor_count_and_timings(
            records,
            last_cursor,
            record_count_override,
        )
        .await
        .map(|(summary, _timings)| summary)
    }

    /// Imports raw OSV records and returns both summary and timing breakdown.
    pub async fn import_osv_records_with_cursor_count_and_timings(
        &self,
        records: Vec<OsvRawRecord>,
        last_cursor: Option<&str>,
        record_count_override: Option<usize>,
    ) -> Result<(ImportSummary, ImportTimings), DbErr> {
        self.import_osv_records_with_cursor_count_timings_and_mode(
            records,
            last_cursor,
            record_count_override,
            false,
        )
        .await
    }

    /// Imports OSV records in bulk-initialization mode and returns timings.
    pub async fn import_osv_records_bulk_init_with_cursor_count_and_timings(
        &self,
        records: Vec<OsvRawRecord>,
        last_cursor: Option<&str>,
        record_count_override: Option<usize>,
    ) -> Result<(ImportSummary, ImportTimings), DbErr> {
        self.import_osv_records_with_cursor_count_timings_and_mode(
            records,
            last_cursor,
            record_count_override,
            true,
        )
        .await
    }

    async fn import_osv_records_with_cursor_count_timings_and_mode(
        &self,
        records: Vec<OsvRawRecord>,
        last_cursor: Option<&str>,
        record_count_override: Option<usize>,
        bulk_init: bool,
    ) -> Result<(ImportSummary, ImportTimings), DbErr> {
        let total_start = std::time::Instant::now();
        let fetched_at = Utc::now().to_rfc3339();
        let hash_start = std::time::Instant::now();
        let source_hash = md5_hex_concat(records.iter().map(|record| record.raw_json.as_bytes()));
        let content_hashes = records
            .iter()
            .map(|record| md5_hex(record.raw_json.as_bytes()))
            .collect::<Vec<_>>();
        let hash_elapsed = hash_start.elapsed();
        let parse_start = std::time::Instant::now();
        let parsed_records = records
            .into_par_iter()
            .zip(content_hashes)
            .map(|(record, content_hash)| parse_osv_raw_record(record, content_hash))
            .collect::<Vec<_>>()
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;
        let parse_elapsed = parse_start.elapsed();
        let parsed_osv_ids = parsed_records
            .iter()
            .map(|record| record.osv_id.clone())
            .collect::<Vec<_>>();
        let hash_lookup_start = std::time::Instant::now();
        let existing_hashes = if bulk_init {
            HashMap::new()
        } else {
            self.raw_record_hashes("OSV", &parsed_osv_ids).await?
        };
        let hash_lookup_elapsed = hash_lookup_start.elapsed();
        let db_write_start = std::time::Instant::now();
        let txn = self.db.begin().await?;
        mark_source_attempt(&txn, "OSV", Some(&source_hash)).await?;
        let mut imported = 0usize;
        let mut skipped = 0usize;
        for record in parsed_records {
            if existing_hashes.get(&record.osv_id).map(String::as_str)
                == Some(record.content_hash.as_str())
            {
                skipped += 1;
                continue;
            }
            let input = RawRecordInput {
                source: "OSV",
                source_record_id: &record.osv_id,
                source_path: record.source_path.as_deref(),
                provider_published_at: record.parsed.published.as_deref(),
                provider_modified_at: record.parsed.modified.as_deref(),
                score_date: None,
                fetched_at: &fetched_at,
                content_hash: &record.content_hash,
                raw_content: &record.raw_json,
                content_type: "application/json",
            };
            let raw_record_id = if bulk_init {
                insert_raw_record(&txn, input).await?
            } else {
                upsert_raw_record(&txn, input).await?
            };
            if bulk_init {
                insert_osv_normalized(&txn, &record.parsed, raw_record_id).await?;
            } else {
                replace_osv_normalized(&txn, &record.parsed, raw_record_id).await?;
            }
            imported += 1;
        }
        mark_source_success(
            &txn,
            "OSV",
            Some(&source_hash),
            last_cursor,
            Some(record_count_override.unwrap_or(imported + skipped) as i64),
            Some(OSV_SCHEMA_VERSION),
        )
        .await?;
        txn.commit().await?;
        let db_write_elapsed = db_write_start.elapsed();
        if imported > 0 && !bulk_init {
            rebuild_osv_text_search(&self.db).await?;
        }
        Ok((
            ImportSummary {
                source: "OSV".to_owned(),
                imported,
                skipped,
                record_count: record_count_override.unwrap_or(imported + skipped),
                content_hash: Some(source_hash),
            },
            ImportTimings {
                hash: hash_elapsed,
                parse: parse_elapsed,
                hash_lookup: hash_lookup_elapsed,
                db_write: db_write_elapsed,
                total: total_start.elapsed(),
            },
        ))
    }

    /// Replaces local CISA KEV data from the official JSON catalog.
    pub async fn import_kev_json(&self, raw_json: &str) -> Result<ImportSummary, DbErr> {
        let fetched_at = Utc::now().to_rfc3339();
        let content_hash = md5_hex(raw_json.as_bytes());
        let parsed = KevCatalog::parse_json(raw_json.as_bytes())
            .map_err(|err| DbErr::Custom(format!("failed to parse KEV JSON: {err}")))?;
        parsed
            .validate_schema_shape()
            .map_err(|err| DbErr::Custom(format!("invalid KEV JSON: {err}")))?;
        let txn = self.db.begin().await?;
        mark_source_attempt(&txn, "KEV", Some(&content_hash)).await?;
        let _catalog_raw_record_id = upsert_raw_record(
            &txn,
            RawRecordInput {
                source: "KEV",
                source_record_id: "known_exploited_vulnerabilities.json",
                source_path: Some("known_exploited_vulnerabilities.json"),
                provider_published_at: None,
                provider_modified_at: Some(parsed.date_released.as_str()),
                score_date: None,
                fetched_at: &fetched_at,
                content_hash: &content_hash,
                raw_content: raw_json,
                content_type: "application/json",
            },
        )
        .await?;
        txn.execute(Statement::from_string(
            DbBackend::Sqlite,
            "DELETE FROM kev_entries".to_owned(),
        ))
        .await?;
        for entry in &parsed.vulnerabilities {
            let cve_id = normalize_identifier(&entry.cve_id);
            let entry_raw = serde_json::to_string(entry)
                .map_err(|err| DbErr::Custom(format!("failed to encode KEV entry: {err}")))?;
            let raw_record_id = upsert_raw_record(
                &txn,
                RawRecordInput {
                    source: "KEV",
                    source_record_id: &cve_id,
                    source_path: Some("known_exploited_vulnerabilities.json"),
                    provider_published_at: None,
                    provider_modified_at: None,
                    score_date: Some(entry.date_added.as_str()),
                    fetched_at: &fetched_at,
                    content_hash: &md5_hex(entry_raw.as_bytes()),
                    raw_content: &entry_raw,
                    content_type: "application/json",
                },
            )
            .await?;
            execute_values(
                &txn,
                r#"
                INSERT INTO kev_entries (
                    cve_id, vendor_project, product, vulnerability_name, date_added,
                    short_description, required_action, due_date,
                    known_ransomware_campaign_use, notes, fetched_at, raw_record_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(cve_id) DO UPDATE SET
                    vendor_project = excluded.vendor_project,
                    product = excluded.product,
                    vulnerability_name = excluded.vulnerability_name,
                    date_added = excluded.date_added,
                    short_description = excluded.short_description,
                    required_action = excluded.required_action,
                    due_date = excluded.due_date,
                    known_ransomware_campaign_use = excluded.known_ransomware_campaign_use,
                    notes = excluded.notes,
                    fetched_at = excluded.fetched_at,
                    raw_record_id = excluded.raw_record_id
                "#,
                vec![
                    SeaValue::from(cve_id.clone()),
                    SeaValue::from(entry.vendor_project.clone()),
                    SeaValue::from(entry.product.clone()),
                    SeaValue::from(entry.vulnerability_name.clone()),
                    SeaValue::from(entry.date_added.clone()),
                    SeaValue::from(entry.short_description.clone()),
                    SeaValue::from(entry.required_action.clone()),
                    SeaValue::from(entry.due_date.clone()),
                    SeaValue::from(entry.known_ransomware_campaign_use.clone()),
                    SeaValue::from(entry.notes.clone()),
                    SeaValue::from(fetched_at.clone()),
                    SeaValue::from(raw_record_id),
                ],
            )
            .await?;
            upsert_identifier(&txn, &cve_id, "KEV", &fetched_at).await?;
        }
        let count = parsed.vulnerabilities.len();
        mark_source_success(
            &txn,
            "KEV",
            Some(&content_hash),
            None,
            Some(count as i64),
            Some(parsed.catalog_version.as_str()),
        )
        .await?;
        txn.commit().await?;
        Ok(ImportSummary {
            source: "KEV".to_owned(),
            imported: count,
            skipped: 0,
            record_count: count,
            content_hash: Some(content_hash),
        })
    }

    /// Replaces local FIRST EPSS current scores from the official CSV.
    pub async fn import_epss_csv(&self, csv: &str) -> Result<ImportSummary, DbErr> {
        let parsed = EpssCurrentCsv::parse(csv)
            .map_err(|err| DbErr::Custom(format!("failed to parse EPSS CSV: {err}")))?;
        let fetched_at = Utc::now().to_rfc3339();
        let content_hash = md5_hex(csv.as_bytes());
        let txn = self.db.begin().await?;
        mark_source_attempt(&txn, "EPSS", Some(&content_hash)).await?;
        let raw_record_id = upsert_raw_record(
            &txn,
            RawRecordInput {
                source: "EPSS",
                source_record_id: parsed.score_date.as_deref().unwrap_or("current"),
                source_path: Some("epss_scores-current.csv"),
                provider_published_at: None,
                provider_modified_at: None,
                score_date: parsed.score_date.as_deref(),
                fetched_at: &fetched_at,
                content_hash: &content_hash,
                raw_content: csv,
                content_type: "text/csv",
            },
        )
        .await?;
        txn.execute(Statement::from_string(
            DbBackend::Sqlite,
            "DELETE FROM epss_current".to_owned(),
        ))
        .await?;
        for row in &parsed.rows {
            execute_values(
                &txn,
                r#"
                INSERT INTO epss_current (
                    cve_id, epss, percentile, score_date, model_version, fetched_at, raw_record_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                "#,
                vec![
                    SeaValue::from(row.cve_id.clone()),
                    SeaValue::from(row.epss),
                    SeaValue::from(row.percentile),
                    text_value(parsed.score_date.clone()),
                    text_value(parsed.model_version.clone()),
                    SeaValue::from(fetched_at.clone()),
                    SeaValue::from(raw_record_id),
                ],
            )
            .await?;
            upsert_identifier(&txn, &row.cve_id, "EPSS", &fetched_at).await?;
        }
        mark_source_success(
            &txn,
            "EPSS",
            Some(&content_hash),
            parsed.score_date.as_deref(),
            Some(parsed.rows.len() as i64),
            parsed.model_version.as_deref(),
        )
        .await?;
        let count = parsed.rows.len();
        txn.commit().await?;
        Ok(ImportSummary {
            source: "EPSS".to_owned(),
            imported: count,
            skipped: 0,
            record_count: count,
            content_hash: Some(content_hash),
        })
    }

    /// Rebuilds local vulnerability identifier nodes and alias edges.
    pub async fn rebuild_identifier_graph(&self) -> Result<ImportSummary, DbErr> {
        let txn = self.db.begin().await?;
        txn.execute(Statement::from_string(
            DbBackend::Sqlite,
            "DELETE FROM vulnerability_identifier_edges".to_owned(),
        ))
        .await?;
        txn.execute(Statement::from_string(
            DbBackend::Sqlite,
            "DELETE FROM vulnerability_identifiers".to_owned(),
        ))
        .await?;
        refresh_identifier_nodes_for_source(&txn, "CVE").await?;
        refresh_identifier_nodes_for_source(&txn, "OSV").await?;
        refresh_identifier_nodes_for_source(&txn, "KEV").await?;
        refresh_identifier_nodes_for_source(&txn, "EPSS").await?;
        refresh_osv_alias_edges(&txn).await?;
        txn.commit().await?;
        let edge_count = self
            .count_by_statement(
                "SELECT COUNT(*) AS count FROM vulnerability_identifier_edges",
                Vec::new(),
            )
            .await
            .unwrap_or(0) as usize;
        Ok(ImportSummary {
            source: "identifier_graph".to_owned(),
            imported: edge_count,
            skipped: 0,
            record_count: edge_count,
            content_hash: None,
        })
    }

    /// Resolves a CVE, OSV, GHSA, RUSTSEC, PYSEC, GO, or related ID through the graph.
    pub async fn resolve_identifier(&self, id: &str) -> Result<IdentifierResolution, DbErr> {
        let normalized_id = normalize_identifier(id);
        let edges = self.related_edges(&normalized_id).await?;
        let connected = IdentifierNodeRow::find_by_statement(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            r#"
            WITH RECURSIVE connected(identifier) AS (
                VALUES (?)
                UNION
                SELECT CASE
                    WHEN edge.from_identifier = connected.identifier THEN edge.to_identifier
                    ELSE edge.from_identifier
                END
                FROM vulnerability_identifier_edges edge
                INNER JOIN connected
                    ON edge.from_identifier = connected.identifier
                    OR edge.to_identifier = connected.identifier
            )
            SELECT identifier FROM connected ORDER BY identifier
            "#,
            vec![SeaValue::from(normalized_id.clone())],
        ))
        .all(&self.db)
        .await?;
        let connected_ids = connected
            .into_iter()
            .map(|row| row.identifier)
            .collect::<Vec<_>>();
        let osv_ids = load_existing_osv_ids(&self.db, &connected_ids)
            .await?
            .into_iter()
            .collect::<HashSet<_>>();
        let queried_identifier_type = resolved_identifier_type(&normalized_id, &osv_ids);
        let mut related_cve_ids = Vec::new();
        let mut related_osv_ids = Vec::new();
        let mut related_aliases = Vec::new();
        for id in connected_ids {
            match resolved_identifier_type(&id, &osv_ids).as_str() {
                "cve" => related_cve_ids.push(id),
                "osv" => related_osv_ids.push(id),
                _ => related_aliases.push(id),
            }
        }
        related_cve_ids.sort();
        related_osv_ids.sort();
        related_aliases.sort();
        Ok(IdentifierResolution {
            queried_id: id.to_owned(),
            normalized_id,
            identifier_type: queried_identifier_type,
            related_cve_ids,
            related_osv_ids,
            related_aliases,
            edges,
            source_sync: self.source_sync_states().await?,
        })
    }

    /// Returns graph edges directly connected to one vulnerability identifier.
    pub async fn related_edges(&self, id: &str) -> Result<Vec<IdentifierEdgeEvidence>, DbErr> {
        let id = normalize_identifier(id);
        IdentifierEdgeEvidence::find_by_statement(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            r#"
            SELECT from_identifier, to_identifier, relation_type, source, confidence, evidence_json, created_at
            FROM vulnerability_identifier_edges
            WHERE from_identifier = ? OR to_identifier = ?
            ORDER BY source, from_identifier, to_identifier
            "#,
            vec![SeaValue::from(id.clone()), SeaValue::from(id)],
        ))
        .all(&self.db)
        .await
    }

    /// Returns one CVE with joined OSV, KEV, EPSS, alias, and source status data.
    pub async fn get_enriched_cve(&self, cve_id: &str) -> Result<EnrichedCve, DbErr> {
        let cve_id = normalize_identifier(cve_id);
        let cve = self.find_cve_summary_with_detail(&cve_id).await?;
        let osv_ids = load_osv_ids_for_cve(&self.db, &cve_id).await?;
        let aliases = load_aliases_for_cve(&self.db, &cve_id).await?;
        let osv_advisories = load_osv_summaries(&self.db, &osv_ids).await?;
        let affected_packages = load_affected_packages(&self.db, &osv_ids).await?;
        let kev = load_kev(&self.db, &cve_id).await?;
        let epss = load_epss(&self.db, &cve_id).await?;
        let mut evidence = Vec::new();
        if kev.is_some() {
            evidence.push(Evidence {
                kind: "kev_join".to_owned(),
                source: "CISA KEV".to_owned(),
                from: None,
                to: None,
                cve_id: Some(cve_id.clone()),
                osv_id: None,
                detail: None,
            });
        }
        if epss.is_some() {
            evidence.push(Evidence {
                kind: "epss_join".to_owned(),
                source: "FIRST EPSS".to_owned(),
                from: None,
                to: None,
                cve_id: Some(cve_id.clone()),
                osv_id: None,
                detail: None,
            });
        }
        let (severity, cwe) = cve
            .as_ref()
            .map(|cve| {
                (
                    cve.detail.cvss.clone(),
                    cve.detail
                        .cwes
                        .iter()
                        .map(|cwe| format!("CWE-{}", cwe.id))
                        .collect(),
                )
            })
            .unwrap_or_default();
        Ok(EnrichedCve {
            cve_id,
            cve,
            aliases,
            osv_advisories,
            affected_packages,
            kev,
            epss,
            severity,
            cwe,
            evidence,
            database_status: EnrichmentStatusSummary {
                source_sync: self.source_sync_states().await?,
            },
        })
    }

    /// Enriches a list of CVE summaries while preserving input order.
    pub async fn enrich_cve_summaries_full(
        &self,
        summaries: Vec<CveSummary>,
    ) -> Result<Vec<EnrichedCve>, DbErr> {
        if summaries.is_empty() {
            return Ok(Vec::new());
        }
        let cve_ids = summaries
            .iter()
            .map(|summary| normalize_identifier(&summary.cve_id))
            .collect::<Vec<_>>();
        let details = summaries
            .into_iter()
            .map(|summary| CveSummaryWithDetail {
                summary,
                detail: CveDetail::default(),
            })
            .collect::<Vec<_>>();
        let summary_rows = self.enriched_cve_summaries(&cve_ids).await?;
        let all_osv_ids = summary_rows
            .iter()
            .flat_map(|row| split_concat_values(&row.osv_ids))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let osv_rows = load_osv_summaries(&self.db, &all_osv_ids).await?;
        let package_rows = load_affected_packages(&self.db, &all_osv_ids).await?;
        let kev_rows = load_kev_many(&self.db, &cve_ids).await?;
        let epss_rows = load_epss_many(&self.db, &cve_ids).await?;
        let source_sync = self.source_sync_states().await?;

        let mut detail_by_cve_id = details
            .into_iter()
            .map(|row| (row.summary.cve_id.clone(), row))
            .collect::<HashMap<_, _>>();
        let summary_by_cve_id = summary_rows
            .into_iter()
            .map(|row| (row.cve_id.clone(), row))
            .collect::<HashMap<_, _>>();
        let osv_by_id = osv_rows
            .into_iter()
            .map(|row| (row.osv_id.clone(), row))
            .collect::<HashMap<_, _>>();
        let mut packages_by_osv_id: HashMap<String, Vec<AffectedPackageSummary>> = HashMap::new();
        for package in package_rows {
            packages_by_osv_id
                .entry(package.osv_id.clone())
                .or_default()
                .push(package);
        }
        let kev_by_cve_id = kev_rows
            .into_iter()
            .map(|row| (row.cve_id.clone(), row))
            .collect::<HashMap<_, _>>();
        let epss_by_cve_id = epss_rows
            .into_iter()
            .map(|row| (row.cve_id.clone(), row))
            .collect::<HashMap<_, _>>();

        Ok(cve_ids
            .into_iter()
            .map(|cve_id| {
                let cve = detail_by_cve_id.remove(&cve_id);
                let summary = summary_by_cve_id.get(&cve_id);
                let osv_ids = summary
                    .map(|row| split_concat_values(&row.osv_ids))
                    .unwrap_or_default();
                let aliases = summary
                    .map(|row| split_concat_values(&row.aliases))
                    .unwrap_or_default();
                let osv_advisories = osv_ids
                    .iter()
                    .filter_map(|osv_id| osv_by_id.get(osv_id).cloned())
                    .collect::<Vec<_>>();
                let affected_packages = osv_ids
                    .iter()
                    .flat_map(|osv_id| packages_by_osv_id.get(osv_id).cloned().unwrap_or_default())
                    .collect::<Vec<_>>();
                let kev = kev_by_cve_id.get(&cve_id).cloned();
                let epss = epss_by_cve_id.get(&cve_id).cloned();
                let mut evidence = Vec::new();
                if kev.is_some() {
                    evidence.push(Evidence {
                        kind: "kev_join".to_owned(),
                        source: "CISA KEV".to_owned(),
                        from: None,
                        to: None,
                        cve_id: Some(cve_id.clone()),
                        osv_id: None,
                        detail: None,
                    });
                }
                if epss.is_some() {
                    evidence.push(Evidence {
                        kind: "epss_join".to_owned(),
                        source: "FIRST EPSS".to_owned(),
                        from: None,
                        to: None,
                        cve_id: Some(cve_id.clone()),
                        osv_id: None,
                        detail: None,
                    });
                }
                EnrichedCve {
                    cve_id,
                    cve,
                    aliases,
                    osv_advisories,
                    affected_packages,
                    kev,
                    epss,
                    severity: Vec::new(),
                    cwe: Vec::new(),
                    evidence,
                    database_status: EnrichmentStatusSummary {
                        source_sync: source_sync.clone(),
                    },
                }
            })
            .collect())
    }

    /// Returns KEV entries, optionally narrowed to one CVE ID.
    pub async fn kev_entries(&self, cve_id: Option<&str>) -> Result<Vec<KevInfo>, DbErr> {
        if let Some(cve_id) = cve_id {
            return Ok(load_kev(&self.db, cve_id).await?.into_iter().collect());
        }
        self.kev_entries_paged(i64::MAX as u64, 0).await
    }

    /// Returns paged KEV entries ordered by date added.
    pub async fn kev_entries_paged(&self, limit: u64, offset: u64) -> Result<Vec<KevInfo>, DbErr> {
        KevInfo::find_by_statement(Statement::from_string(
            DbBackend::Sqlite,
            format!(
                r#"
            SELECT cve_id, vendor_project, product, vulnerability_name, date_added,
                   short_description, required_action, due_date,
                   known_ransomware_campaign_use, notes, fetched_at
            FROM kev_entries
            ORDER BY date_added DESC, cve_id
            LIMIT {limit} OFFSET {offset}
            "#
            ),
        ))
        .all(&self.db)
        .await
    }

    /// Counts locally stored KEV entries.
    pub async fn kev_entries_count(&self) -> Result<u64, DbErr> {
        self.count_by_sql("SELECT COUNT(*) AS count FROM kev_entries".to_owned())
            .await
    }

    /// Returns compact enrichment rows for the requested CVE IDs.
    pub async fn enriched_cve_summaries(
        &self,
        cve_ids: &[String],
    ) -> Result<Vec<EnrichedCveSummary>, DbErr> {
        if cve_ids.is_empty() {
            return Ok(Vec::new());
        }
        let cve_ids = cve_ids
            .iter()
            .map(|id| normalize_identifier(id))
            .collect::<Vec<_>>();
        EnrichedCveSummary::find_by_statement(Statement::from_string(
            DbBackend::Sqlite,
            format!(
                r#"
                WITH requested(cve_id, ordinal) AS (
                    VALUES {}
                ),
                related_osv AS (
                    SELECT r.cve_id, s.osv_id
                    FROM requested r
                    INNER JOIN osv_cve_search s ON s.cve_id = r.cve_id
                ),
                aliases AS (
                    SELECT ro.cve_id,
                           COALESCE(GROUP_CONCAT(DISTINCT a.alias_id), '') AS aliases
                    FROM related_osv ro
                    INNER JOIN osv_aliases a ON a.osv_id = ro.osv_id
                    WHERE a.alias_id NOT LIKE 'CVE-%'
                    GROUP BY ro.cve_id
                ),
                osv AS (
                    SELECT ro.cve_id,
                           COALESCE(GROUP_CONCAT(DISTINCT o.osv_id), '') AS osv_ids,
                           COALESCE(GROUP_CONCAT(DISTINCT o.osv_id || ': ' || COALESCE(o.summary, '')), '') AS osv_summaries
                    FROM related_osv ro
                    INNER JOIN osv_advisories o ON o.osv_id = ro.osv_id
                    GROUP BY ro.cve_id
                ),
                packages AS (
                    SELECT ro.cve_id,
                           COALESCE(GROUP_CONCAT(DISTINCT
                               COALESCE(p.ecosystem, '-') || '/' || COALESCE(p.package_name, '-')
                           ), '') AS affected_packages
                    FROM related_osv ro
                    INNER JOIN osv_affected_packages p ON p.osv_id = ro.osv_id
                    GROUP BY ro.cve_id
                )
                SELECT
                    r.cve_id,
                    COALESCE(aliases.aliases, '') AS aliases,
                    COALESCE(osv.osv_ids, '') AS osv_ids,
                    COALESCE(osv.osv_summaries, '') AS osv_summaries,
                    COALESCE(packages.affected_packages, '') AS affected_packages,
                    CASE WHEN kev.cve_id IS NULL THEN 0 ELSE 1 END AS kev_listed,
                    kev.date_added AS kev_date_added,
                    kev.due_date AS kev_due_date,
                    kev.known_ransomware_campaign_use AS kev_known_ransomware_campaign_use,
                    epss.epss AS epss,
                    epss.percentile AS epss_percentile,
                    epss.score_date AS epss_score_date,
                    epss.model_version AS epss_model_version
                FROM requested r
                LEFT JOIN aliases ON aliases.cve_id = r.cve_id
                LEFT JOIN osv ON osv.cve_id = r.cve_id
                LEFT JOIN packages ON packages.cve_id = r.cve_id
                LEFT JOIN kev_entries kev ON kev.cve_id = r.cve_id
                LEFT JOIN epss_current epss ON epss.cve_id = r.cve_id
                ORDER BY r.ordinal
                "#,
                sql_values_list(&cve_ids)
            ),
        ))
        .all(&self.db)
        .await
    }

    /// Returns compact risk rows for the requested CVE IDs in input order.
    pub async fn cve_risk_summaries(
        &self,
        cve_ids: &[String],
    ) -> Result<Vec<CveRiskSummary>, DbErr> {
        if cve_ids.is_empty() {
            return Ok(Vec::new());
        }
        let cve_ids = cve_ids
            .iter()
            .map(|id| normalize_identifier(id))
            .collect::<Vec<_>>();
        CveRiskSummary::find_by_statement(Statement::from_string(
            DbBackend::Sqlite,
            format!(
                r#"
                WITH requested(cve_id, ordinal) AS (
                    VALUES {}
                )
                SELECT
                    r.cve_id,
                    cve.title,
                    cve.published_at,
                    cve.updated_at,
                    cve.state,
                    CASE WHEN kev.cve_id IS NULL THEN 0 ELSE 1 END AS kev_listed,
                    kev.date_added AS kev_date_added,
                    kev.due_date AS kev_due_date,
                    kev.known_ransomware_campaign_use AS kev_known_ransomware_campaign_use,
                    epss.epss AS epss,
                    epss.percentile AS epss_percentile,
                    epss.score_date AS epss_score_date,
                    epss.model_version AS epss_model_version,
                    COALESCE(cvss.max_cvss_score, summary.max_cvss_score, (
                        SELECT MAX(base_score) FROM cve_cvss WHERE cve_cvss.cve_db_id = cve.id
                    )) AS max_cvss_score,
                    COALESCE(cvss.max_cvss_severity, summary.max_cvss_severity, (
                        SELECT base_severity
                        FROM cve_cvss
                        WHERE cve_cvss.cve_db_id = cve.id AND base_severity IS NOT NULL
                        ORDER BY COALESCE(base_score, -1) DESC
                        LIMIT 1
                    )) AS max_cvss_severity,
                    NULL AS max_cvss_version
                FROM requested r
                LEFT JOIN cve ON cve.cve_id = r.cve_id
                LEFT JOIN kev_entries kev ON kev.cve_id = r.cve_id
                LEFT JOIN epss_current epss ON epss.cve_id = r.cve_id
                LEFT JOIN cve_cvss_search cvss ON cvss.cve_id = r.cve_id
                LEFT JOIN cve_summary_index summary ON summary.cve_id = r.cve_id
                ORDER BY r.ordinal
                "#,
                sql_values_list(&cve_ids)
            ),
        ))
        .all(&self.db)
        .await
    }

    /// Searches CVE risk rows by EPSS score or percentile.
    pub async fn search_cve_risk_by_epss(
        &self,
        min_score: Option<f64>,
        min_percentile: Option<f64>,
        state_scope: CveStateScope,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveRiskSummary>, DbErr> {
        let mut conditions = Vec::new();
        if let Some(min_score) = min_score {
            conditions.push(format!("epss.epss >= {min_score}"));
        }
        if let Some(min_percentile) = min_percentile {
            conditions.push(format!("epss.percentile >= {min_percentile}"));
        }
        if !state_scope.includes_rejected() {
            conditions.push("cve.state = 0".to_owned());
        }
        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conditions.join(" AND "))
        };
        CveRiskSummary::find_by_statement(Statement::from_string(
            DbBackend::Sqlite,
            format!(
                r#"
                SELECT
                    cve.cve_id,
                    cve.title,
                    cve.published_at,
                    cve.updated_at,
                    cve.state,
                    CASE WHEN kev.cve_id IS NULL THEN 0 ELSE 1 END AS kev_listed,
                    kev.date_added AS kev_date_added,
                    kev.due_date AS kev_due_date,
                    kev.known_ransomware_campaign_use AS kev_known_ransomware_campaign_use,
                    epss.epss AS epss,
                    epss.percentile AS epss_percentile,
                    epss.score_date AS epss_score_date,
                    epss.model_version AS epss_model_version,
                    COALESCE(cvss.max_cvss_score, summary.max_cvss_score, (
                        SELECT MAX(base_score) FROM cve_cvss WHERE cve_cvss.cve_db_id = cve.id
                    )) AS max_cvss_score,
                    COALESCE(cvss.max_cvss_severity, summary.max_cvss_severity, (
                        SELECT base_severity
                        FROM cve_cvss
                        WHERE cve_cvss.cve_db_id = cve.id AND base_severity IS NOT NULL
                        ORDER BY COALESCE(base_score, -1) DESC
                        LIMIT 1
                    )) AS max_cvss_severity,
                    NULL AS max_cvss_version
                FROM epss_current epss
                INNER JOIN cve ON cve.cve_id = epss.cve_id
                LEFT JOIN kev_entries kev ON kev.cve_id = cve.cve_id
                LEFT JOIN cve_cvss_search cvss ON cvss.cve_id = cve.cve_id
                LEFT JOIN cve_summary_index summary ON summary.cve_id = cve.cve_id
                {where_clause}
                ORDER BY epss.epss DESC, epss.percentile DESC, cve.published_at DESC, cve.cve_id ASC
                LIMIT {limit} OFFSET {offset}
                "#
            ),
        ))
        .all(&self.db)
        .await
    }

    /// Returns one OSV advisory summary by exact advisory ID.
    pub async fn get_enriched_osv(&self, osv_id: &str) -> Result<Option<OsvSummary>, DbErr> {
        load_osv_summaries(&self.db, &[normalize_identifier(osv_id)])
            .await
            .map(|mut rows| rows.pop())
    }

    /// Finds OSV advisories affecting a package/version and attaches CVE risk data.
    pub async fn query_package_enriched(
        &self,
        ecosystem: &str,
        package: &str,
        version: &str,
        purl: Option<&str>,
    ) -> Result<Vec<EnrichedFinding>, DbErr> {
        let package_rows = PackageOsvRow::find_by_statement(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            r#"
            SELECT p.id, p.osv_id, p.ecosystem, p.package_name, p.purl
            FROM osv_affected_packages p
            INNER JOIN osv_advisories a ON a.osv_id = p.osv_id
            WHERE lower(p.ecosystem) = lower(?)
              AND lower(p.package_name) = lower(?)
              AND a.withdrawn_at IS NULL
            ORDER BY p.osv_id
            "#,
            vec![
                SeaValue::from(ecosystem.to_owned()),
                SeaValue::from(package.to_owned()),
            ],
        ))
        .all(&self.db)
        .await?;

        let package_ids = package_rows.iter().map(|row| row.id).collect::<Vec<_>>();
        let mut ranges_by_package = load_osv_ranges_many(&self.db, &package_ids).await?;
        let mut resolution_by_osv_id: HashMap<String, IdentifierResolution> = HashMap::new();
        let mut matches = Vec::new();
        let mut all_cve_ids = BTreeSet::new();
        for package_row in package_rows {
            if purl.is_some()
                && package_row.purl.as_deref().is_some()
                && package_row.purl.as_deref() != purl
            {
                continue;
            }
            let ranges = ranges_by_package
                .remove(&package_row.id)
                .unwrap_or_default();
            let fixed_versions = fixed_versions_from_ranges(&ranges);
            let affected =
                match_version(ecosystem, version, &ranges).unwrap_or_else(|| AffectedStatus {
                    status: "unknown".to_owned(),
                    confidence: "low".to_owned(),
                });
            if affected.status == "not_affected" {
                continue;
            }
            let resolution = if let Some(resolution) = resolution_by_osv_id.get(&package_row.osv_id)
            {
                resolution.clone()
            } else {
                let resolution = self.resolve_identifier(&package_row.osv_id).await?;
                resolution_by_osv_id.insert(package_row.osv_id.clone(), resolution.clone());
                resolution
            };
            all_cve_ids.extend(resolution.related_cve_ids.iter().cloned());
            matches.push(PackageMatch {
                package_row,
                fixed_versions,
                affected,
                resolution,
            });
        }

        let all_cve_ids = all_cve_ids.into_iter().collect::<Vec<_>>();
        let kev_by_cve_id = load_kev_many(&self.db, &all_cve_ids)
            .await?
            .into_iter()
            .map(|row| (row.cve_id.clone(), row))
            .collect::<HashMap<_, _>>();
        let epss_by_cve_id = load_epss_many(&self.db, &all_cve_ids)
            .await?
            .into_iter()
            .map(|row| (row.cve_id.clone(), row))
            .collect::<HashMap<_, _>>();

        let mut findings = Vec::with_capacity(matches.len());
        for package_match in matches {
            let PackageMatch {
                package_row,
                fixed_versions,
                affected,
                resolution,
            } = package_match;
            let cve_ids = resolution.related_cve_ids.clone();
            let kev = cve_ids
                .iter()
                .find_map(|cve_id| kev_by_cve_id.get(cve_id).cloned());
            let epss = cve_ids
                .iter()
                .find_map(|cve_id| epss_by_cve_id.get(cve_id).cloned());
            let mut evidence = vec![Evidence {
                kind: "osv_range_match".to_owned(),
                source: "OSV".to_owned(),
                from: None,
                to: None,
                cve_id: None,
                osv_id: Some(package_row.osv_id.clone()),
                detail: Some(format!(
                    "{} {} {}",
                    affected.status,
                    package_row.ecosystem.unwrap_or_default(),
                    package_row.package_name.unwrap_or_default()
                )),
            }];
            evidence.extend(resolution.edges.iter().map(|edge| Evidence {
                kind: "alias_resolution".to_owned(),
                source: edge.source.clone(),
                from: Some(edge.from_identifier.clone()),
                to: Some(edge.to_identifier.clone()),
                cve_id: None,
                osv_id: None,
                detail: Some(edge.evidence_json.clone()),
            }));
            for cve_id in &cve_ids {
                if kev.is_some() {
                    evidence.push(Evidence {
                        kind: "kev_join".to_owned(),
                        source: "CISA KEV".to_owned(),
                        from: None,
                        to: None,
                        cve_id: Some(cve_id.clone()),
                        osv_id: None,
                        detail: None,
                    });
                }
                if epss.is_some() {
                    evidence.push(Evidence {
                        kind: "epss_join".to_owned(),
                        source: "FIRST EPSS".to_owned(),
                        from: None,
                        to: None,
                        cve_id: Some(cve_id.clone()),
                        osv_id: None,
                        detail: None,
                    });
                }
            }
            let priority_signals = priority_signals(
                kev.as_ref(),
                epss.as_ref(),
                !fixed_versions.is_empty(),
                &affected,
            );
            findings.push(EnrichedFinding {
                primary_id: package_row.osv_id,
                cve_ids,
                aliases: resolution.related_aliases,
                package: PackageQuery {
                    ecosystem: ecosystem.to_owned(),
                    package: package.to_owned(),
                    version: version.to_owned(),
                    purl: purl.map(ToOwned::to_owned),
                },
                affected,
                fixed_versions,
                enrichment: FindingEnrichment { kev, epss },
                priority_signals,
                evidence,
            });
        }
        Ok(findings)
    }

    pub async fn find_cve_summary_with_detail(
        &self,
        cve_id: &str,
    ) -> Result<Option<CveSummaryWithDetail>, DbErr> {
        let Some(summary) = cve::Entity::find()
            .select_only()
            .columns(summary_columns())
            .filter(cve::Column::CveId.eq(cve_id))
            .into_model::<CveSummary>()
            .one(&self.db)
            .await?
        else {
            return Ok(None);
        };
        let mut rows = self.attach_cve_details(vec![summary]).await?;
        Ok(rows.pop())
    }

    pub async fn find_cve_references(&self, cve_id: &str) -> Result<Vec<CveReference>, DbErr> {
        let Some(raw_json) = self.find_cve_raw_json_by_id(cve_id).await? else {
            return Ok(Vec::new());
        };
        Ok(cve_references_from_raw_json(&raw_json))
    }

    pub async fn search_cve_summaries_by_reference_text(
        &self,
        query: &str,
        state_scope: CveStateScope,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, DbErr> {
        if matches!(self.db.get_database_backend(), DbBackend::Sqlite) {
            return CveSummary::find_by_statement(Statement::from_string(
                DbBackend::Sqlite,
                reference_summary_index_sql(query, state_scope, limit, offset),
            ))
            .all(&self.db)
            .await;
        }
        self.search_cve_summaries_by_text_with_state_scope(query, state_scope, limit, offset)
            .await
    }

    pub async fn search_cve_summaries_by_vendor_product_version(
        &self,
        vendor: Option<&str>,
        product: Option<&str>,
        version: Option<&str>,
        state_scope: CveStateScope,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, DbErr> {
        let mut query = cve::Entity::find()
            .select_only()
            .columns(summary_columns())
            .inner_join(cve_affected::Entity);
        if !state_scope.includes_rejected() {
            query = query.filter(cve::Column::State.eq(PUBLISHED_STATE));
        }
        query = apply_affected_filters(query, vendor, product, None, None);
        if let Some(version) = option_text(version) {
            query = query.filter(cve_affected::Column::VersionText.like(like_pattern(version)));
        }
        query
            .distinct()
            .order_by_desc(cve::Column::PublishedAt)
            .order_by_asc(cve::Column::CveId)
            .limit(limit)
            .offset(offset)
            .into_model::<CveSummary>()
            .all(&self.db)
            .await
    }

    pub async fn search_cve_summaries_by_date_range(
        &self,
        published_from: Option<&str>,
        published_to: Option<&str>,
        updated_from: Option<&str>,
        updated_to: Option<&str>,
        state_scope: CveStateScope,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, DbErr> {
        if matches!(self.db.get_database_backend(), DbBackend::Sqlite) {
            return CveSummary::find_by_statement(Statement::from_string(
                DbBackend::Sqlite,
                date_range_summary_index_sql(
                    published_from,
                    published_to,
                    updated_from,
                    updated_to,
                    state_scope,
                    limit,
                    offset,
                ),
            ))
            .all(&self.db)
            .await;
        }
        let options = CveAdvancedSearch {
            query: None,
            query_mode: None,
            cwe: None,
            vendor: None,
            product: None,
            vendor_exact: None,
            product_exact: None,
            published_from: published_from.map(ToOwned::to_owned),
            published_to: published_to.map(ToOwned::to_owned),
            state_scope,
            sort_order: CveSummarySortOrder::PublishedDesc,
        };
        let rows = self
            .search_cve_summaries_advanced(&options, limit, offset)
            .await?;
        if updated_from.is_none() && updated_to.is_none() {
            return Ok(rows);
        }
        Ok(rows
            .into_iter()
            .filter(|row| {
                updated_from.is_none_or(|from| row.updated_at.as_str() >= from)
                    && updated_to.is_none_or(|to| row.updated_at.as_str() <= to)
            })
            .collect())
    }

    pub async fn list_recent_updates(
        &self,
        since: Option<&str>,
        state_scope: CveStateScope,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, DbErr> {
        self.search_cve_summaries_by_date_with_state_scope(None, since, state_scope, limit, offset)
            .await
    }

    pub async fn get_cwe_entry(&self, cwe_id: i32) -> Result<Option<CweEntry>, DbErr> {
        let Some(row) = cwe::Entity::find()
            .select_only()
            .columns([
                cwe::Column::Id,
                cwe::Column::Description,
                cwe::Column::Status,
                cwe::Column::ParentId,
            ])
            .filter(cwe::Column::Id.eq(cwe_id))
            .into_model::<CweEntryRow>()
            .one(&self.db)
            .await?
        else {
            return Ok(None);
        };
        Ok(cwe_entries_with_relation_counts(vec![row])
            .into_iter()
            .next())
    }

    pub async fn search_cwe_entries(
        &self,
        query: &str,
        limit: u64,
        statuses: &[String],
    ) -> Result<Vec<CweEntry>, DbErr> {
        let query = query.trim();
        let limit = limit.max(1);
        let mut search = cwe::Entity::find()
            .select_only()
            .columns([
                cwe::Column::Id,
                cwe::Column::Description,
                cwe::Column::Status,
                cwe::Column::ParentId,
            ])
            .order_by_asc(cwe::Column::Id);

        if statuses.is_empty() {
            return Ok(Vec::new());
        }
        if statuses.len() < 6 {
            search = search.filter(cwe::Column::Status.is_in(statuses.iter().cloned()));
        }

        if !query.is_empty() {
            let id = cwe_number(query);
            let mut condition =
                Condition::any().add(cwe::Column::Description.like(like_pattern(query)));
            if let Some(id) = id {
                condition = condition.add(cwe::Column::Id.eq(id));
            }
            search = search.filter(condition);
        }

        search
            .into_model::<CweEntryRow>()
            .all(&self.db)
            .await
            .map(|entries| {
                cwe_entries_tree_order(cwe_entries_with_relation_counts(entries), limit as usize)
            })
    }

    pub async fn get_metadata(&self, key: &str) -> Result<Option<String>, DbErr> {
        app_metadata::Entity::find_by_id(key.to_owned())
            .one(&self.db)
            .await
            .map(|row| row.map(|row| row.value))
    }

    pub async fn set_metadata(&self, key: &str, value: &str) -> Result<(), DbErr> {
        app_metadata::Entity::insert(app_metadata::ActiveModel {
            key: Set(key.to_owned()),
            value: Set(value.to_owned()),
            updated_at: Set(Utc::now().to_rfc3339()),
        })
        .on_conflict(
            OnConflict::column(app_metadata::Column::Key)
                .update_columns([app_metadata::Column::Value, app_metadata::Column::UpdatedAt])
                .to_owned(),
        )
        .exec(&self.db)
        .await?;
        Ok(())
    }

    pub async fn is_cve_asset_applied(&self, asset_name: &str) -> Result<bool, DbErr> {
        self.get_metadata(&cve_asset_metadata_key(asset_name))
            .await
            .map(|value| value.is_some())
    }

    pub async fn mark_cve_asset_applied(&self, asset_name: &str, value: &str) -> Result<(), DbErr> {
        self.set_metadata(&cve_asset_metadata_key(asset_name), value)
            .await
    }
}

impl CveBulkReplaceSession {
    pub async fn insert_cve_records(
        &self,
        records: Vec<RawCveRecord<CveStatusData>>,
    ) -> Result<usize, DbErr> {
        self.insert_cve_models(records.into_iter().map(CveActiveModels::from).collect())
            .await
    }

    pub async fn insert_cve_models(&self, models: Vec<CveActiveModels>) -> Result<usize, DbErr> {
        if models.is_empty() {
            return Ok(0);
        }

        insert_cve_models_on(&self.txn, models, false).await
    }

    pub async fn insert_cve_raw_json_strings(&self, values: Vec<String>) -> Result<usize, DbErr> {
        self.insert_cve_models(
            values
                .into_iter()
                .map(CveActiveModels::from_raw_json_string)
                .collect::<Result<Vec<_>, _>>()?,
        )
        .await
    }

    pub async fn mark_json_files_read(
        &self,
        files: Vec<ReadJsonFileRecord>,
    ) -> Result<usize, DbErr> {
        mark_json_files_read_on(&self.txn, files, false).await
    }

    pub async fn finish(self, db: &CveDatabase) -> Result<(), DbErr> {
        self.txn.commit().await?;
        finish_bulk_replace_all_on(&db.db).await
    }

    pub async fn finish_storage_only(self, db: &CveDatabase) -> Result<(), DbErr> {
        self.txn.commit().await?;
        finish_bulk_replace_all_storage_on(&db.db).await
    }

    pub async fn finish_storage_with_text_search(self, db: &CveDatabase) -> Result<(), DbErr> {
        self.txn.commit().await?;
        finish_bulk_replace_all_storage_with_text_search_on(&db.db).await
    }
}

pub async fn connect_database(database_url: &str) -> Result<DatabaseConnection, DbErr> {
    let db = Database::connect(database_url).await?;
    db.execute(Statement::from_string(
        DbBackend::Sqlite,
        "PRAGMA foreign_keys = ON;".to_owned(),
    ))
    .await?;
    db.execute(Statement::from_string(
        DbBackend::Sqlite,
        "PRAGMA journal_mode = WAL;".to_owned(),
    ))
    .await?;
    db.execute(Statement::from_string(
        DbBackend::Sqlite,
        "PRAGMA synchronous = NORMAL;".to_owned(),
    ))
    .await?;
    db.execute(Statement::from_string(
        DbBackend::Sqlite,
        "PRAGMA temp_store = MEMORY;".to_owned(),
    ))
    .await?;
    db.execute(Statement::from_string(
        DbBackend::Sqlite,
        "PRAGMA cache_size = -200000;".to_owned(),
    ))
    .await?;
    db.execute(Statement::from_string(
        DbBackend::Sqlite,
        "PRAGMA mmap_size = 1073741824;".to_owned(),
    ))
    .await?;
    Ok(db)
}

async fn upsert_cve_on<C>(db: &C, model: cve::ActiveModel) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    cve::Entity::insert(model)
        .on_conflict(cve_upsert_conflict())
        .exec(db)
        .await?;

    Ok(())
}

async fn upsert_cve_model_batch(
    txn: &DatabaseTransaction,
    models: Vec<CveActiveModels>,
) -> Result<usize, DbErr> {
    let mut cve_ids = Vec::with_capacity(models.len());
    let mut cve_rows = Vec::with_capacity(models.len());

    for model in &models {
        cve_ids.push(model.cve_id.clone());
        cve_rows.push(model.cve.clone());
    }

    let inserted = cve_rows.len();

    let cve_db_ids = upsert_cve_rows_returning(txn, cve_rows).await?;
    let (cvss_rows, affected_rows, cwe_master_rows, cwe_rows) =
        child_rows_with_cve_db_ids(models, &cve_db_ids)?;
    let cve_db_id_values = cve_ids
        .iter()
        .filter_map(|cve_id| cve_db_ids.get(cve_id).copied())
        .collect::<Vec<_>>();

    cve_cvss::Entity::delete_many()
        .filter(cve_cvss::Column::CveDbId.is_in(cve_db_id_values.iter().copied()))
        .exec(txn)
        .await?;
    cve_affected::Entity::delete_many()
        .filter(cve_affected::Column::CveDbId.is_in(cve_db_id_values.iter().copied()))
        .exec(txn)
        .await?;
    cve_cwe::Entity::delete_many()
        .filter(cve_cwe::Column::CveDbId.is_in(cve_db_id_values.iter().copied()))
        .exec(txn)
        .await?;

    for chunk in take_chunks(cvss_rows, CVSS_CHUNK_SIZE) {
        cve_cvss::Entity::insert_many(chunk).exec(txn).await?;
    }
    for chunk in take_chunks(affected_rows, AFFECTED_CHUNK_SIZE) {
        cve_affected::Entity::insert_many(chunk).exec(txn).await?;
    }
    for chunk in take_chunks(cwe_master_rows, CWE_MASTER_CHUNK_SIZE) {
        cwe::Entity::insert_many(chunk)
            .on_conflict(cwe_upsert_conflict())
            .exec(txn)
            .await?;
    }
    for chunk in take_chunks(cwe_rows, CWE_CHUNK_SIZE) {
        cve_cwe::Entity::insert_many(chunk).exec(txn).await?;
    }
    upsert_cve_summary_index_rows(txn, &cve_ids).await?;

    Ok(inserted)
}

async fn insert_cve_models_on(
    txn: &DatabaseTransaction,
    models: Vec<CveActiveModels>,
    update_search_index: bool,
) -> Result<usize, DbErr> {
    let mut inserted = 0usize;
    let mut batch = Vec::with_capacity(CVE_CHUNK_SIZE);

    for models in models {
        batch.push(models);
        if batch.len() == CVE_CHUNK_SIZE {
            inserted +=
                insert_cve_model_batch(txn, std::mem::take(&mut batch), update_search_index)
                    .await?;
            batch = Vec::with_capacity(CVE_CHUNK_SIZE);
        }
    }

    if !batch.is_empty() {
        inserted += insert_cve_model_batch(txn, batch, update_search_index).await?;
    }

    Ok(inserted)
}

async fn insert_cve_model_batch(
    txn: &DatabaseTransaction,
    models: Vec<CveActiveModels>,
    update_search_index: bool,
) -> Result<usize, DbErr> {
    let mut cve_rows = Vec::with_capacity(models.len());
    let mut cve_ids = Vec::with_capacity(models.len());

    for model in &models {
        cve_ids.push(model.cve_id.clone());
        cve_rows.push(model.cve.clone());
    }

    let inserted = cve_rows.len();

    let cve_db_ids = insert_cve_rows_returning(txn, cve_rows).await?;
    let (cvss_rows, affected_rows, cwe_master_rows, cwe_rows) =
        child_rows_with_cve_db_ids(models, &cve_db_ids)?;

    for chunk in take_chunks(cvss_rows, CVSS_CHUNK_SIZE) {
        insert_cvss_rows(txn, chunk).await?;
    }
    for chunk in take_chunks(affected_rows, AFFECTED_CHUNK_SIZE) {
        insert_affected_rows(txn, chunk).await?;
    }
    for chunk in take_chunks(cwe_master_rows, CWE_MASTER_CHUNK_SIZE) {
        upsert_cwe_rows(txn, chunk).await?;
    }
    for chunk in take_chunks(cwe_rows, CWE_CHUNK_SIZE) {
        insert_cwe_rows(txn, chunk).await?;
    }
    if update_search_index {
        upsert_cve_summary_index_rows(txn, &cve_ids).await?;
    }

    Ok(inserted)
}

type CveChildRows = (
    Vec<cve_cvss::ActiveModel>,
    Vec<cve_affected::ActiveModel>,
    Vec<cwe::ActiveModel>,
    Vec<cve_cwe::ActiveModel>,
);

fn child_rows_with_cve_db_ids(
    models: Vec<CveActiveModels>,
    cve_db_ids: &HashMap<String, i32>,
) -> Result<CveChildRows, DbErr> {
    let mut cvss_rows = Vec::new();
    let mut affected_rows = Vec::new();
    let mut cwe_master_rows = Vec::new();
    let mut cwe_rows = Vec::new();

    for mut model in models {
        let Some(cve_db_id) = cve_db_ids.get(&model.cve_id).copied() else {
            return Err(DbErr::Custom(format!(
                "missing cve.id for {}",
                model.cve_id
            )));
        };
        set_cvss_cve_db_id(&mut model.cvss_rows, cve_db_id);
        set_affected_cve_db_id(&mut model.affected_rows, cve_db_id);
        set_cwe_cve_db_id(&mut model.cwe_rows, cve_db_id);
        cvss_rows.extend(model.cvss_rows);
        affected_rows.extend(model.affected_rows);
        cwe_master_rows.extend(model.cwe_master_rows);
        cwe_rows.extend(model.cwe_rows);
    }

    Ok((cvss_rows, affected_rows, cwe_master_rows, cwe_rows))
}

fn set_cvss_cve_db_id(rows: &mut [cve_cvss::ActiveModel], cve_db_id: i32) {
    for row in rows {
        row.cve_db_id = Set(cve_db_id);
    }
}

fn set_affected_cve_db_id(rows: &mut [cve_affected::ActiveModel], cve_db_id: i32) {
    for row in rows {
        row.cve_db_id = Set(cve_db_id);
    }
}

fn set_cwe_cve_db_id(rows: &mut [cve_cwe::ActiveModel], cve_db_id: i32) {
    for row in rows {
        row.cve_db_id = Set(cve_db_id);
    }
}

fn take_chunks<T>(mut rows: Vec<T>, chunk_size: usize) -> Vec<Vec<T>> {
    if rows.is_empty() {
        return Vec::new();
    }

    let mut chunks = Vec::with_capacity(rows.len().div_ceil(chunk_size));
    while rows.len() > chunk_size {
        let rest = rows.split_off(chunk_size);
        chunks.push(rows);
        rows = rest;
    }
    chunks.push(rows);
    chunks
}

async fn cve_db_id_by_cve_id<C>(db: &C, cve_id: &str) -> Result<i32, DbErr>
where
    C: ConnectionTrait,
{
    cve::Entity::find()
        .select_only()
        .column(cve::Column::Id)
        .filter(cve::Column::CveId.eq(cve_id))
        .into_model::<CveIdMapping>()
        .one(db)
        .await?
        .map(|row| row.id)
        .ok_or_else(|| DbErr::Custom(format!("missing cve.id for {cve_id}")))
}

async fn clear_cve_tables_on(txn: &DatabaseTransaction) -> Result<(), DbErr> {
    clear_cve_summary_indexes(txn).await?;
    cve_cwe::Entity::delete_many().exec(txn).await?;
    cwe::Entity::delete_many().exec(txn).await?;
    cve_affected::Entity::delete_many().exec(txn).await?;
    cve_cvss::Entity::delete_many().exec(txn).await?;
    cve::Entity::delete_many().exec(txn).await?;
    Ok(())
}

async fn insert_cve_rows_returning(
    txn: &DatabaseTransaction,
    rows: Vec<cve::ActiveModel>,
) -> Result<HashMap<String, i32>, DbErr> {
    let mut map = HashMap::with_capacity(rows.len());
    for chunk in take_chunks(rows, CVE_CHUNK_SIZE) {
        let inserted = cve::Entity::insert_many(chunk)
            .exec_with_returning_many(txn)
            .await?;
        for row in inserted {
            map.insert(row.cve_id, row.id);
        }
    }
    Ok(map)
}

async fn upsert_cve_rows_returning(
    txn: &DatabaseTransaction,
    rows: Vec<cve::ActiveModel>,
) -> Result<HashMap<String, i32>, DbErr> {
    let mut map = HashMap::with_capacity(rows.len());
    for chunk in take_chunks(rows, CVE_CHUNK_SIZE) {
        let inserted = cve::Entity::insert_many(chunk)
            .on_conflict(cve_upsert_conflict())
            .exec_with_returning_many(txn)
            .await?;
        for row in inserted {
            map.insert(row.cve_id, row.id);
        }
    }
    Ok(map)
}

async fn insert_cvss_rows(
    txn: &DatabaseTransaction,
    rows: Vec<cve_cvss::ActiveModel>,
) -> Result<(), DbErr> {
    cve_cvss::Entity::insert_many(rows).exec(txn).await?;
    Ok(())
}

async fn insert_affected_rows(
    txn: &DatabaseTransaction,
    rows: Vec<cve_affected::ActiveModel>,
) -> Result<(), DbErr> {
    cve_affected::Entity::insert_many(rows).exec(txn).await?;
    Ok(())
}

async fn upsert_cwe_rows(
    txn: &DatabaseTransaction,
    rows: Vec<cwe::ActiveModel>,
) -> Result<(), DbErr> {
    let (described_rows, id_only_rows): (Vec<_>, Vec<_>) = rows
        .into_iter()
        .partition(|row| matches!(&row.description, sea_orm::ActiveValue::Set(Some(_))));

    if !described_rows.is_empty() {
        cwe::Entity::insert_many(described_rows)
            .on_conflict(cwe_upsert_conflict())
            .exec(txn)
            .await?;
    }

    if !id_only_rows.is_empty() {
        let ids = id_only_rows
            .iter()
            .filter_map(cwe_active_model_id)
            .collect::<Vec<_>>();
        let existing_ids = cwe::Entity::find()
            .filter(cwe::Column::Id.is_in(ids))
            .all(txn)
            .await?
            .into_iter()
            .map(|row| row.id)
            .collect::<HashSet<_>>();
        let missing_rows = id_only_rows
            .into_iter()
            .filter(|row| {
                cwe_active_model_id(row)
                    .map(|id| !existing_ids.contains(&id))
                    .unwrap_or(false)
            })
            .collect::<Vec<_>>();

        if !missing_rows.is_empty() {
            cwe::Entity::insert_many(missing_rows).exec(txn).await?;
        }
    }

    Ok(())
}

async fn upsert_cwe_catalog_on(
    txn: &DatabaseTransaction,
    catalog: &WeaknessCatalog,
) -> Result<usize, DbErr> {
    let mut rows = Vec::new();

    if let Some(weaknesses) = &catalog.weaknesses {
        for weakness in &weaknesses.weakness {
            rows.push(cwe_catalog_row(
                weakness.id,
                weakness.description.clone(),
                Some(&weakness.status),
                cwe_parent_id(&weakness.related_weaknesses)?,
            )?);
        }
    }

    if let Some(categories) = &catalog.categories {
        for category in &categories.category {
            rows.push(cwe_catalog_row(
                category.id,
                category.name.clone(),
                Some(&category.status),
                None,
            )?);
        }
    }

    if let Some(views) = &catalog.views {
        for view in &views.view {
            rows.push(cwe_catalog_row(
                view.id,
                view.name.clone(),
                Some(&view.status),
                None,
            )?);
        }
    }

    let count = rows.len();

    for chunk in take_chunks(rows, CWE_MASTER_CHUNK_SIZE) {
        upsert_cwe_rows(txn, chunk).await?;
    }

    Ok(count)
}

fn cwe_catalog_row(
    id: i64,
    description: String,
    status: Option<&qanvuli_models::cwe::enumeration::Status>,
    parent_id: Option<i32>,
) -> Result<cwe::ActiveModel, DbErr> {
    Ok(cwe::ActiveModel {
        id: Set(i32::try_from(id)
            .map_err(|err| DbErr::Custom(format!("CWE ID {id} does not fit in i32: {err}")))?),
        description: Set(Some(description)),
        status: Set(status.map(|status| status.as_ref().to_owned())),
        parent_id: Set(parent_id),
    })
}

fn cwe_parent_id(
    related_weaknesses: &Option<qanvuli_models::cwe::common::RelatedWeaknesses>,
) -> Result<Option<i32>, DbErr> {
    let Some(related_weaknesses) = related_weaknesses else {
        return Ok(None);
    };
    related_weaknesses
        .related_weakness
        .iter()
        .find(|related| matches!(related.nature, RelatedNature::ChildOf))
        .map(|related| {
            i32::try_from(related.cwe_id).map_err(|err| {
                DbErr::Custom(format!(
                    "parent CWE ID {} does not fit in i32: {err}",
                    related.cwe_id
                ))
            })
        })
        .transpose()
}

async fn insert_cwe_rows(
    txn: &DatabaseTransaction,
    rows: Vec<cve_cwe::ActiveModel>,
) -> Result<(), DbErr> {
    cve_cwe::Entity::insert_many(rows).exec(txn).await?;
    Ok(())
}

async fn prepare_bulk_replace_all_on<C>(db: &C) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    if !matches!(db.get_database_backend(), DbBackend::Sqlite) {
        return Ok(());
    }

    db.execute_unprepared("PRAGMA foreign_keys = OFF").await?;
    db.execute_unprepared("PRAGMA journal_mode = MEMORY")
        .await?;
    db.execute_unprepared("PRAGMA synchronous = OFF").await?;
    db.execute_unprepared("PRAGMA temp_store = MEMORY").await?;
    db.execute_unprepared("PRAGMA cache_size = -400000").await?;
    db.execute_unprepared("PRAGMA locking_mode = EXCLUSIVE")
        .await?;
    for index_name in BULK_LOAD_DROPPED_INDEXES {
        db.execute_unprepared(&format!("DROP INDEX IF EXISTS {index_name}"))
            .await?;
    }
    Ok(())
}

async fn finish_bulk_replace_all_on<C>(db: &C) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    if !matches!(db.get_database_backend(), DbBackend::Sqlite) {
        return Ok(());
    }

    for sql in BULK_LOAD_FINAL_INDEXES {
        db.execute_unprepared(sql).await?;
    }
    db.execute_unprepared("ANALYZE").await?;
    db.execute_unprepared("PRAGMA optimize").await?;
    rebuild_cve_summary_indexes(db).await?;
    restore_sqlite_bulk_pragmas(db).await?;
    Ok(())
}

async fn finish_bulk_replace_all_storage_on<C>(db: &C) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    if !matches!(db.get_database_backend(), DbBackend::Sqlite) {
        return Ok(());
    }

    restore_sqlite_bulk_pragmas(db).await
}

async fn finish_bulk_replace_all_storage_with_text_search_on<C>(db: &C) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    if !matches!(db.get_database_backend(), DbBackend::Sqlite) {
        return Ok(());
    }

    rebuild_minimal_cve_text_search(db).await?;
    create_cve_overview_indexes(db).await?;
    restore_sqlite_bulk_pragmas(db).await
}

async fn create_cve_overview_indexes<C>(db: &C) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    if !matches!(db.get_database_backend(), DbBackend::Sqlite) {
        return Ok(());
    }
    for sql in [
        "CREATE INDEX IF NOT EXISTS idx_cve_cvss_cve_db_id ON cve_cvss (cve_db_id)",
        "CREATE INDEX IF NOT EXISTS idx_cve_cvss_cve_db_id_base_score ON cve_cvss (cve_db_id, base_score)",
        "CREATE INDEX IF NOT EXISTS idx_cve_affected_cve_db_id ON cve_affected (cve_db_id)",
        "CREATE INDEX IF NOT EXISTS idx_cve_affected_cve_db_id_vendor_product ON cve_affected (cve_db_id, vendor, product)",
        "CREATE INDEX IF NOT EXISTS idx_cve_affected_vendor_cve_db_id ON cve_affected (vendor, cve_db_id)",
        "CREATE INDEX IF NOT EXISTS idx_cve_affected_product_cve_db_id ON cve_affected (product, cve_db_id)",
        "CREATE INDEX IF NOT EXISTS idx_cve_cwe_cve_db_id ON cve_cwe (cve_db_id)",
    ] {
        db.execute_unprepared(sql).await?;
    }
    Ok(())
}

async fn prepare_bulk_osv_import_on<C>(db: &C) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    if !matches!(db.get_database_backend(), DbBackend::Sqlite) {
        return Ok(());
    }

    db.execute_unprepared("PRAGMA foreign_keys = OFF").await?;
    db.execute_unprepared("PRAGMA journal_mode = MEMORY")
        .await?;
    db.execute_unprepared("PRAGMA synchronous = OFF").await?;
    db.execute_unprepared("PRAGMA temp_store = MEMORY").await?;
    db.execute_unprepared("PRAGMA cache_size = -400000").await?;
    db.execute_unprepared("PRAGMA locking_mode = EXCLUSIVE")
        .await?;
    for index_name in OSV_BULK_LOAD_DROPPED_INDEXES {
        db.execute_unprepared(&format!("DROP INDEX IF EXISTS {index_name}"))
            .await?;
    }
    Ok(())
}

async fn finish_bulk_osv_import_on<C>(db: &C) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    if !matches!(db.get_database_backend(), DbBackend::Sqlite) {
        return Ok(());
    }

    for sql in OSV_BULK_LOAD_FINAL_INDEXES {
        db.execute_unprepared(sql).await?;
    }
    restore_sqlite_bulk_pragmas(db).await
}

async fn finish_bulk_osv_import_storage_on<C>(db: &C) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    if !matches!(db.get_database_backend(), DbBackend::Sqlite) {
        return Ok(());
    }

    rebuild_osv_text_search(db).await?;
    restore_sqlite_bulk_pragmas(db).await
}

async fn restore_sqlite_bulk_pragmas<C>(db: &C) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    db.execute_unprepared("PRAGMA foreign_keys = ON").await?;
    db.execute_unprepared("PRAGMA journal_mode = WAL").await?;
    db.execute_unprepared("PRAGMA synchronous = NORMAL").await?;
    db.execute_unprepared("PRAGMA locking_mode = NORMAL")
        .await?;
    db.execute_unprepared("PRAGMA wal_checkpoint(TRUNCATE)")
        .await?;
    Ok(())
}

async fn compact_storage_on<C>(db: &C) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    if !matches!(db.get_database_backend(), DbBackend::Sqlite) {
        return Ok(());
    }

    db.execute_unprepared("PRAGMA wal_checkpoint(TRUNCATE)")
        .await?;
    db.execute_unprepared("VACUUM").await?;
    Ok(())
}

const BULK_LOAD_DROPPED_INDEXES: &[&str] = &[
    "idx_read_json_file_filename",
    "idx_cve_published_at",
    "idx_cve_updated_at",
    "idx_cve_reference_text",
    "idx_cve_cvss_cve_db_id",
    "idx_cve_cvss_version",
    "idx_cve_cvss_base_score",
    "idx_cve_cvss_base_severity",
    "idx_cve_cvss_severity_score",
    "idx_cve_cvss_version_score",
    "idx_cve_cvss_cve_db_id_score_version",
    "idx_cve_affected_cve_db_id",
    "idx_cve_affected_vendor",
    "idx_cve_affected_product",
    "idx_cve_affected_package",
    "idx_cve_affected_version_text",
    "idx_cve_affected_cve_db_id_vendor_product",
    "idx_cve_affected_vendor_cve_db_id",
    "idx_cve_affected_product_cve_db_id",
    "idx_cve_affected_vendor_product_cve_db_id",
    "idx_cve_cwe_cve_id",
    "idx_cve_cwe_cve_db_id",
    "idx_cve_cwe_cwe_id",
    "idx_cve_cwe_cwe_id_cve_id",
    "idx_cve_cwe_cwe_id_cve_db_id",
    "idx_cwe_id",
    "idx_cve_published_at_cve_id",
    "idx_cve_updated_at_cve_id",
];

const BULK_LOAD_FINAL_INDEXES: &[&str] = &[
    "CREATE INDEX IF NOT EXISTS idx_read_json_file_filename ON read_json_file (filename)",
    "CREATE INDEX IF NOT EXISTS idx_cve_published_at ON cve (published_at)",
    "CREATE INDEX IF NOT EXISTS idx_cve_updated_at ON cve (updated_at)",
    "CREATE INDEX IF NOT EXISTS idx_cve_published_at_cve_id ON cve (published_at, cve_id)",
    "CREATE INDEX IF NOT EXISTS idx_cve_updated_at_cve_id ON cve (updated_at, cve_id)",
    "CREATE INDEX IF NOT EXISTS idx_cve_reference_text ON cve (reference_text)",
    "CREATE INDEX IF NOT EXISTS idx_cve_cvss_cve_db_id ON cve_cvss (cve_db_id)",
    "CREATE INDEX IF NOT EXISTS idx_cve_cvss_version ON cve_cvss (version)",
    "CREATE INDEX IF NOT EXISTS idx_cve_cvss_base_score ON cve_cvss (base_score)",
    "CREATE INDEX IF NOT EXISTS idx_cve_cvss_base_severity ON cve_cvss (base_severity)",
    "CREATE INDEX IF NOT EXISTS idx_cve_cvss_severity_score ON cve_cvss (base_severity, base_score)",
    "CREATE INDEX IF NOT EXISTS idx_cve_cvss_version_score ON cve_cvss (version, base_score)",
    "CREATE INDEX IF NOT EXISTS idx_cve_cvss_cve_db_id_score_version ON cve_cvss (cve_db_id, base_score, version)",
    "CREATE INDEX IF NOT EXISTS idx_cve_affected_cve_db_id ON cve_affected (cve_db_id)",
    "CREATE INDEX IF NOT EXISTS idx_cve_affected_vendor ON cve_affected (vendor)",
    "CREATE INDEX IF NOT EXISTS idx_cve_affected_product ON cve_affected (product)",
    "CREATE INDEX IF NOT EXISTS idx_cve_affected_package ON cve_affected (package_name)",
    "CREATE INDEX IF NOT EXISTS idx_cve_affected_version_text ON cve_affected (version_text)",
    "CREATE INDEX IF NOT EXISTS idx_cve_affected_cve_db_id_vendor_product ON cve_affected (cve_db_id, vendor, product)",
    "CREATE INDEX IF NOT EXISTS idx_cve_affected_vendor_cve_db_id ON cve_affected (vendor, cve_db_id)",
    "CREATE INDEX IF NOT EXISTS idx_cve_affected_product_cve_db_id ON cve_affected (product, cve_db_id)",
    "CREATE INDEX IF NOT EXISTS idx_cve_affected_vendor_product_cve_db_id ON cve_affected (vendor, product, cve_db_id)",
    "CREATE INDEX IF NOT EXISTS idx_cve_cwe_cwe_id_cve_db_id ON cve_cwe (cwe_id, cve_db_id)",
];

const OSV_BULK_LOAD_DROPPED_INDEXES: &[&str] = &[
    "idx_source_raw_records_source_hash",
    "idx_osv_aliases_alias",
    "idx_osv_cve_search_cve_id",
    "idx_osv_affected_packages_lookup",
    "idx_osv_ranges_package",
    "idx_osv_range_events_range",
    "idx_identifier_edges_to",
    "idx_identifier_edges_from",
];

const OSV_BULK_LOAD_FINAL_INDEXES: &[&str] = &[
    "CREATE INDEX IF NOT EXISTS idx_source_raw_records_source_hash ON source_raw_records (source, content_hash)",
    "CREATE INDEX IF NOT EXISTS idx_osv_aliases_alias ON osv_aliases (alias_id)",
    "CREATE INDEX IF NOT EXISTS idx_osv_cve_search_cve_id ON osv_cve_search (cve_id)",
    "CREATE INDEX IF NOT EXISTS idx_osv_affected_packages_lookup ON osv_affected_packages (ecosystem, package_name)",
    "CREATE INDEX IF NOT EXISTS idx_osv_ranges_package ON osv_ranges (affected_package_id)",
    "CREATE INDEX IF NOT EXISTS idx_osv_range_events_range ON osv_range_events (range_id, event_order)",
    "CREATE INDEX IF NOT EXISTS idx_identifier_edges_to ON vulnerability_identifier_edges (to_identifier)",
    "CREATE INDEX IF NOT EXISTS idx_identifier_edges_from ON vulnerability_identifier_edges (from_identifier)",
];

async fn create_cve_summary_indexes<C>(db: &C) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    if !matches!(db.get_database_backend(), DbBackend::Sqlite) {
        return Ok(());
    }

    db.execute_unprepared(
        r#"
        CREATE TABLE IF NOT EXISTS cve_summary_index (
            cve_db_id INTEGER PRIMARY KEY NOT NULL,
            cve_id TEXT NOT NULL UNIQUE,
            state INTEGER NOT NULL,
            published_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            title TEXT NOT NULL,
            description_en TEXT,
            max_cvss_score REAL,
            max_cvss_severity TEXT,
            cwe_ids TEXT NOT NULL DEFAULT '',
            affected_text TEXT NOT NULL DEFAULT '',
            vendor_text TEXT NOT NULL DEFAULT '',
            product_text TEXT NOT NULL DEFAULT '',
            reference_text TEXT NOT NULL DEFAULT ''
        )
        "#,
    )
    .await?;
    db.execute_unprepared(
        "CREATE INDEX IF NOT EXISTS idx_cve_summary_state_published ON cve_summary_index (state, published_at DESC, cve_id)",
    )
    .await?;
    db.execute_unprepared(
        "CREATE INDEX IF NOT EXISTS idx_cve_summary_published ON cve_summary_index (published_at DESC, cve_id)",
    )
    .await?;
    db.execute_unprepared(
        "CREATE INDEX IF NOT EXISTS idx_cve_summary_updated ON cve_summary_index (updated_at DESC, cve_id)",
    )
    .await?;
    db.execute_unprepared(
        "CREATE INDEX IF NOT EXISTS idx_cve_summary_cve_id ON cve_summary_index (cve_id)",
    )
    .await?;
    db.execute_unprepared(
        "CREATE INDEX IF NOT EXISTS idx_cve_summary_score ON cve_summary_index (max_cvss_score DESC, published_at DESC, cve_id)",
    )
    .await?;
    db.execute_unprepared(
        r#"
        CREATE VIRTUAL TABLE IF NOT EXISTS cve_summary_fts USING fts5(
            cve_id UNINDEXED,
            title,
            description_en,
            affected_text,
            reference_text,
            tokenize = 'unicode61'
        )
        "#,
    )
    .await?;
    db.execute_unprepared(
        r#"
        CREATE VIRTUAL TABLE IF NOT EXISTS cve_affected_summary_fts USING fts5(
            cve_id UNINDEXED,
            vendor_text,
            product_text,
            affected_text,
            tokenize = 'unicode61'
        )
        "#,
    )
    .await?;
    db.execute_unprepared(
        r#"
        CREATE TABLE IF NOT EXISTS cve_cwe_search (
            cwe_id INTEGER NOT NULL,
            cve_id TEXT NOT NULL,
            state INTEGER NOT NULL,
            published_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            title TEXT NOT NULL,
            description_en TEXT,
            PRIMARY KEY (cwe_id, cve_id)
        )
        "#,
    )
    .await?;
    db.execute_unprepared(
        "CREATE INDEX IF NOT EXISTS idx_cve_cwe_search_sort ON cve_cwe_search (cwe_id, state, published_at DESC, cve_id)",
    )
    .await?;
    db.execute_unprepared(
        r#"
        CREATE TABLE IF NOT EXISTS cve_cvss_search (
            cve_id TEXT PRIMARY KEY NOT NULL,
            state INTEGER NOT NULL,
            published_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            title TEXT NOT NULL,
            description_en TEXT,
            max_cvss_score REAL,
            max_cvss_severity TEXT,
            cvss_versions TEXT NOT NULL DEFAULT ''
        )
        "#,
    )
    .await?;
    db.execute_unprepared(
        "CREATE INDEX IF NOT EXISTS idx_cve_cvss_search_score ON cve_cvss_search (state, max_cvss_score DESC, published_at DESC, cve_id)",
    )
    .await?;
    db.execute_unprepared(
        "CREATE INDEX IF NOT EXISTS idx_cve_cvss_search_severity ON cve_cvss_search (max_cvss_severity, state, max_cvss_score DESC, published_at DESC, cve_id)",
    )
    .await?;
    db.execute_unprepared(
        r#"
        CREATE TABLE IF NOT EXISTS cve_affected_search (
            cve_id TEXT PRIMARY KEY NOT NULL,
            state INTEGER NOT NULL,
            published_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            title TEXT NOT NULL,
            description_en TEXT,
            vendor_text TEXT NOT NULL DEFAULT '',
            product_text TEXT NOT NULL DEFAULT '',
            affected_text TEXT NOT NULL DEFAULT ''
        )
        "#,
    )
    .await?;
    db.execute_unprepared(
        "CREATE INDEX IF NOT EXISTS idx_cve_affected_search_sort ON cve_affected_search (state, published_at DESC, cve_id)",
    )
    .await?;

    Ok(())
}

async fn clear_cve_summary_indexes<C>(db: &C) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    if !matches!(db.get_database_backend(), DbBackend::Sqlite) {
        return Ok(());
    }
    create_cve_summary_indexes(db).await?;
    for sql in [
        "DELETE FROM cve_summary_index",
        "DELETE FROM cve_summary_fts",
        "DELETE FROM cve_affected_summary_fts",
        "DELETE FROM cve_cwe_search",
        "DELETE FROM cve_cvss_search",
        "DELETE FROM cve_affected_search",
    ] {
        db.execute_unprepared(sql).await?;
    }
    Ok(())
}

async fn rebuild_cve_summary_indexes<C>(db: &C) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    if !matches!(db.get_database_backend(), DbBackend::Sqlite) {
        return Ok(());
    }
    create_cve_summary_indexes(db).await?;
    for sql in [
        "DELETE FROM cve_summary_index",
        "DELETE FROM cve_summary_fts",
        "DELETE FROM cve_affected_summary_fts",
        "DELETE FROM cve_cwe_search",
        "DELETE FROM cve_cvss_search",
        "DELETE FROM cve_affected_search",
    ] {
        db.execute_unprepared(sql).await?;
    }
    insert_cve_summary_index_sql(db, None).await?;
    insert_cve_summary_fts_sql(db, None).await?;
    insert_cve_cwe_search_sql(db, None).await?;
    insert_cve_cvss_search_sql(db, None).await?;
    insert_cve_affected_search_sql(db, None).await?;
    Ok(())
}

async fn rebuild_minimal_cve_text_search<C>(db: &C) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    if !matches!(db.get_database_backend(), DbBackend::Sqlite) {
        return Ok(());
    }
    create_cve_summary_indexes(db).await?;
    for sql in [
        "DELETE FROM cve_summary_index",
        "DELETE FROM cve_summary_fts",
        "DELETE FROM cve_affected_summary_fts",
    ] {
        db.execute_unprepared(sql).await?;
    }
    db.execute_unprepared(
        r#"
        INSERT INTO cve_summary_index (
            cve_db_id, cve_id, state, published_at, updated_at, title, description_en,
            reference_text
        )
        SELECT id, cve_id, state, published_at, updated_at, title, description_en,
            COALESCE(reference_text, '')
        FROM cve
        "#,
    )
    .await?;
    db.execute_unprepared(
        r#"
        INSERT INTO cve_summary_fts (
            rowid, cve_id, title, description_en, affected_text, reference_text
        )
        SELECT cve_db_id, cve_id, title, COALESCE(description_en, ''), '', reference_text
        FROM cve_summary_index
        "#,
    )
    .await?;
    db.execute_unprepared(
        r#"
        INSERT INTO cve_affected_summary_fts (
            rowid, cve_id, vendor_text, product_text, affected_text
        )
        SELECT
            cve.id,
            cve.cve_id,
            COALESCE(GROUP_CONCAT(COALESCE(cve_affected.vendor, ''), ' '), ''),
            COALESCE(GROUP_CONCAT(
                COALESCE(cve_affected.product, '') || ' ' || COALESCE(cve_affected.package_name, ''),
                ' '
            ), ''),
            COALESCE(GROUP_CONCAT(
                COALESCE(cve_affected.vendor, '') || ' ' || COALESCE(cve_affected.product, '') || ' ' || COALESCE(cve_affected.package_name, ''),
                ' '
            ), '')
        FROM cve
        LEFT JOIN cve_affected ON cve_affected.cve_db_id = cve.id
        GROUP BY cve.id
        "#,
    )
    .await?;
    Ok(())
}

async fn rebuild_osv_text_search<C>(db: &C) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    if !matches!(db.get_database_backend(), DbBackend::Sqlite) {
        return Ok(());
    }
    db.execute_unprepared(
        r#"
        CREATE VIRTUAL TABLE IF NOT EXISTS osv_text_fts USING fts5(
            osv_id UNINDEXED,
            summary,
            details,
            aliases,
            packages,
            tokenize = 'unicode61'
        )
        "#,
    )
    .await?;
    db.execute_unprepared("DELETE FROM osv_text_fts").await?;
    db.execute_unprepared(
        "CREATE TABLE IF NOT EXISTS osv_cve_search (osv_id TEXT NOT NULL, cve_id TEXT NOT NULL, PRIMARY KEY(osv_id, cve_id))",
    )
    .await?;
    db.execute_unprepared(
        "CREATE TABLE IF NOT EXISTS osv_token_cve_search (token TEXT NOT NULL, cve_id TEXT NOT NULL, state INTEGER NOT NULL, published_at TEXT NOT NULL, PRIMARY KEY(token, cve_id))",
    )
    .await?;
    db.execute_unprepared("DELETE FROM osv_cve_search").await?;
    db.execute_unprepared("DELETE FROM osv_token_cve_search")
        .await?;
    db.execute_unprepared(
        r#"
        INSERT OR IGNORE INTO osv_cve_search (osv_id, cve_id)
        SELECT osv_id, osv_id
        FROM osv_advisories
        WHERE osv_id LIKE 'CVE-%'
        UNION
        SELECT osv_id, alias_id
        FROM osv_aliases
        WHERE alias_id LIKE 'CVE-%'
        "#,
    )
    .await?;
    db.execute_unprepared(
        r#"
        INSERT INTO osv_text_fts (osv_id, summary, details, aliases, packages)
        WITH
            alias_agg AS (
                SELECT osv_id, GROUP_CONCAT(alias_id, ' ') AS aliases
                FROM osv_aliases
                GROUP BY osv_id
            ),
            package_agg AS (
                SELECT
                    osv_id,
                    GROUP_CONCAT(
                        COALESCE(ecosystem, '') || ' ' || COALESCE(package_name, '') || ' ' || COALESCE(purl, ''),
                        ' '
                    ) AS packages
                FROM osv_affected_packages
                GROUP BY osv_id
            )
        SELECT
            o.osv_id,
            COALESCE(o.summary, ''),
            COALESCE(o.details, ''),
            COALESCE(alias_agg.aliases, ''),
            COALESCE(package_agg.packages, '')
        FROM osv_advisories o
        LEFT JOIN alias_agg ON alias_agg.osv_id = o.osv_id
        LEFT JOIN package_agg ON package_agg.osv_id = o.osv_id
        "#,
    )
    .await?;
    db.execute_unprepared(
        "CREATE VIRTUAL TABLE IF NOT EXISTS osv_text_vocab USING fts5vocab(osv_text_fts, 'instance')",
    )
    .await?;
    db.execute_unprepared(
        r#"
        INSERT OR IGNORE INTO osv_token_cve_search (token, cve_id, state, published_at)
        SELECT vocab.term, search.cve_id, cve.state, cve.published_at
        FROM osv_text_vocab vocab
        INNER JOIN osv_text_fts fts ON fts.rowid = vocab.doc
        INNER JOIN osv_cve_search search ON search.osv_id = fts.osv_id
        INNER JOIN cve ON cve.cve_id = search.cve_id
        WHERE LENGTH(vocab.term) >= 2
        "#,
    )
    .await?;
    Ok(())
}

async fn upsert_cve_summary_index_rows<C>(db: &C, cve_ids: &[String]) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    if cve_ids.is_empty() || !matches!(db.get_database_backend(), DbBackend::Sqlite) {
        return Ok(());
    }
    create_cve_summary_indexes(db).await?;
    let cve_ids = sql_cve_id_list(cve_ids);
    for sql in [
        format!("DELETE FROM cve_summary_index WHERE cve_id IN ({cve_ids})"),
        format!("DELETE FROM cve_summary_fts WHERE cve_id IN ({cve_ids})"),
        format!("DELETE FROM cve_affected_summary_fts WHERE cve_id IN ({cve_ids})"),
        format!("DELETE FROM cve_cwe_search WHERE cve_id IN ({cve_ids})"),
        format!("DELETE FROM cve_cvss_search WHERE cve_id IN ({cve_ids})"),
        format!("DELETE FROM cve_affected_search WHERE cve_id IN ({cve_ids})"),
    ] {
        db.execute_unprepared(&sql).await?;
    }
    insert_cve_summary_index_sql(db, Some(&cve_ids)).await?;
    insert_cve_summary_fts_sql(db, Some(&cve_ids)).await?;
    insert_cve_cwe_search_sql(db, Some(&cve_ids)).await?;
    insert_cve_cvss_search_sql(db, Some(&cve_ids)).await?;
    insert_cve_affected_search_sql(db, Some(&cve_ids)).await?;
    Ok(())
}

async fn insert_cve_summary_index_sql<C>(db: &C, cve_ids: Option<&str>) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    if cve_ids.is_none() {
        db.execute_unprepared(
            r#"
            INSERT INTO cve_summary_index (
                cve_db_id, cve_id, state, published_at, updated_at, title, description_en,
                max_cvss_score, max_cvss_severity, cwe_ids, affected_text, vendor_text,
                product_text, reference_text
            )
            WITH
                cvss_max AS (
                    SELECT cve_db_id, MAX(base_score) AS max_cvss_score
                    FROM cve_cvss
                    GROUP BY cve_db_id
                ),
                cvss_severity AS (
                    SELECT cve_db_id, base_severity AS max_cvss_severity
                    FROM (
                        SELECT
                            cve_db_id,
                            base_severity,
                            ROW_NUMBER() OVER (
                                PARTITION BY cve_db_id
                                ORDER BY COALESCE(base_score, -1) DESC
                            ) AS rank
                        FROM cve_cvss
                        WHERE base_severity IS NOT NULL
                    )
                    WHERE rank = 1
                ),
                cwe_agg AS (
                    SELECT cve_db_id, '|' || GROUP_CONCAT(cwe_id, '|') || '|' AS cwe_ids
                    FROM cve_cwe
                    GROUP BY cve_db_id
                ),
                affected_agg AS (
                    SELECT
                        cve_db_id,
                        GROUP_CONCAT(
                            COALESCE(vendor, '') || ' ' || COALESCE(product, '') || ' ' || COALESCE(package_name, ''),
                            ' '
                        ) AS affected_text,
                        GROUP_CONCAT(COALESCE(vendor, ''), ' ') AS vendor_text,
                        GROUP_CONCAT(COALESCE(product, '') || ' ' || COALESCE(package_name, ''), ' ') AS product_text
                    FROM cve_affected
                    GROUP BY cve_db_id
                )
            SELECT
                cve.id,
                cve.cve_id,
                cve.state,
                cve.published_at,
                cve.updated_at,
                cve.title,
                cve.description_en,
                cvss_max.max_cvss_score,
                cvss_severity.max_cvss_severity,
                COALESCE(cwe_agg.cwe_ids, ''),
                COALESCE(affected_agg.affected_text, ''),
                COALESCE(affected_agg.vendor_text, ''),
                COALESCE(affected_agg.product_text, ''),
                COALESCE(cve.reference_text, '')
            FROM cve
            LEFT JOIN cvss_max ON cvss_max.cve_db_id = cve.id
            LEFT JOIN cvss_severity ON cvss_severity.cve_db_id = cve.id
            LEFT JOIN cwe_agg ON cwe_agg.cve_db_id = cve.id
            LEFT JOIN affected_agg ON affected_agg.cve_db_id = cve.id
            "#,
        )
        .await?;
        return Ok(());
    }

    let where_clause = cve_ids
        .map(|ids| format!("WHERE cve.cve_id IN ({ids})"))
        .unwrap_or_default();
    db.execute_unprepared(&format!(
        r#"
        INSERT INTO cve_summary_index (
            cve_db_id, cve_id, state, published_at, updated_at, title, description_en,
            max_cvss_score, max_cvss_severity, cwe_ids, affected_text, vendor_text,
            product_text, reference_text
        )
        SELECT
            cve.id,
            cve.cve_id,
            cve.state,
            cve.published_at,
            cve.updated_at,
            cve.title,
            cve.description_en,
            (SELECT MAX(base_score) FROM cve_cvss WHERE cve_cvss.cve_db_id = cve.id),
            (
                SELECT base_severity
                FROM cve_cvss
                WHERE cve_cvss.cve_db_id = cve.id AND base_severity IS NOT NULL
                ORDER BY COALESCE(base_score, -1) DESC
                LIMIT 1
            ),
            COALESCE((SELECT '|' || GROUP_CONCAT(cwe_id, '|') || '|' FROM cve_cwe WHERE cve_cwe.cve_db_id = cve.id), ''),
            COALESCE((
                SELECT GROUP_CONCAT(
                    COALESCE(vendor, '') || ' ' || COALESCE(product, '') || ' ' || COALESCE(package_name, ''),
                    ' '
                )
                FROM cve_affected
                WHERE cve_affected.cve_db_id = cve.id
            ), ''),
            COALESCE((
                SELECT GROUP_CONCAT(COALESCE(vendor, ''), ' ')
                FROM cve_affected
                WHERE cve_affected.cve_db_id = cve.id
            ), ''),
            COALESCE((
                SELECT GROUP_CONCAT(COALESCE(product, '') || ' ' || COALESCE(package_name, ''), ' ')
                FROM cve_affected
                WHERE cve_affected.cve_db_id = cve.id
            ), ''),
            COALESCE(cve.reference_text, '')
        FROM cve
        {where_clause}
        "#
    ))
    .await?;
    Ok(())
}

async fn insert_cve_summary_fts_sql<C>(db: &C, cve_ids: Option<&str>) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    let where_clause = cve_ids
        .map(|ids| format!("WHERE cve_id IN ({ids})"))
        .unwrap_or_default();
    db.execute_unprepared(&format!(
        "INSERT INTO cve_summary_fts (rowid, cve_id, title, description_en, affected_text, reference_text) SELECT cve_db_id, cve_id, title, COALESCE(description_en, ''), affected_text, reference_text FROM cve_summary_index {where_clause}"
    ))
    .await?;
    db.execute_unprepared(&format!(
        "INSERT INTO cve_affected_summary_fts (rowid, cve_id, vendor_text, product_text, affected_text) SELECT cve_db_id, cve_id, vendor_text, product_text, affected_text FROM cve_summary_index {where_clause}"
    ))
    .await?;
    Ok(())
}

async fn insert_cve_cwe_search_sql<C>(db: &C, cve_ids: Option<&str>) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    let where_clause = cve_ids
        .map(|ids| format!("AND cve.cve_id IN ({ids})"))
        .unwrap_or_default();
    db.execute_unprepared(&format!(
        r#"
        INSERT OR REPLACE INTO cve_cwe_search (
            cwe_id, cve_id, state, published_at, updated_at, title, description_en
        )
        SELECT
            cve_cwe.cwe_id,
            cve.cve_id,
            cve.state,
            cve.published_at,
            cve.updated_at,
            cve.title,
            cve.description_en
        FROM cve_cwe
        INNER JOIN cve ON cve.id = cve_cwe.cve_db_id
        WHERE 1 = 1 {where_clause}
        "#
    ))
    .await?;
    Ok(())
}

async fn insert_cve_cvss_search_sql<C>(db: &C, cve_ids: Option<&str>) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    let where_clause = cve_ids
        .map(|ids| format!("WHERE cve.cve_id IN ({ids})"))
        .unwrap_or_default();
    db.execute_unprepared(&format!(
        r#"
        INSERT OR REPLACE INTO cve_cvss_search (
            cve_id, state, published_at, updated_at, title, description_en,
            max_cvss_score, max_cvss_severity, cvss_versions
        )
        SELECT
            cve.cve_id,
            cve.state,
            cve.published_at,
            cve.updated_at,
            cve.title,
            cve.description_en,
            (SELECT MAX(base_score) FROM cve_cvss WHERE cve_cvss.cve_db_id = cve.id),
            (
                SELECT base_severity
                FROM cve_cvss
                WHERE cve_cvss.cve_db_id = cve.id AND base_severity IS NOT NULL
                ORDER BY COALESCE(base_score, -1) DESC
                LIMIT 1
            ),
            COALESCE((
                SELECT '|' || REPLACE(GROUP_CONCAT(DISTINCT version), ',', '|') || '|'
                FROM cve_cvss
                WHERE cve_cvss.cve_db_id = cve.id
            ), '')
        FROM cve
        {where_clause}
        "#
    ))
    .await?;
    Ok(())
}

async fn insert_cve_affected_search_sql<C>(db: &C, cve_ids: Option<&str>) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    let where_clause = cve_ids
        .map(|ids| format!("WHERE cve_id IN ({ids})"))
        .unwrap_or_default();
    db.execute_unprepared(&format!(
        r#"
        INSERT OR REPLACE INTO cve_affected_search (
            cve_id, state, published_at, updated_at, title, description_en,
            vendor_text, product_text, affected_text
        )
        SELECT cve_id, state, published_at, updated_at, title, description_en,
            vendor_text, product_text, affected_text
        FROM cve_summary_index
        {where_clause}
        "#
    ))
    .await?;
    Ok(())
}

fn sql_cve_id_list(cve_ids: &[String]) -> String {
    cve_ids
        .iter()
        .map(|cve_id| sql_string_literal(cve_id))
        .collect::<Vec<_>>()
        .join(",")
}

fn cve_upsert_conflict() -> OnConflict {
    OnConflict::column(cve::Column::CveId)
        .update_columns([
            cve::Column::State,
            cve::Column::PublishedAt,
            cve::Column::UpdatedAt,
            cve::Column::Serial,
            cve::Column::Title,
            cve::Column::DescriptionEn,
            cve::Column::ReferenceText,
            cve::Column::RawJson,
        ])
        .to_owned()
}

fn cwe_upsert_conflict() -> OnConflict {
    OnConflict::column(cwe::Column::Id)
        .update_column(cwe::Column::Description)
        .update_column(cwe::Column::Status)
        .update_column(cwe::Column::ParentId)
        .to_owned()
}

fn cwe_active_model_id(row: &cwe::ActiveModel) -> Option<i32> {
    match &row.id {
        sea_orm::ActiveValue::Set(id) => Some(*id),
        sea_orm::ActiveValue::Unchanged(id) => Some(*id),
        sea_orm::ActiveValue::NotSet => None,
    }
}

fn cwe_entries_with_relation_counts(rows: Vec<CweEntryRow>) -> Vec<CweEntry> {
    let mut sibling_groups = HashMap::<Option<i32>, usize>::new();
    let mut child_counts = HashMap::<i32, usize>::new();
    for row in &rows {
        *sibling_groups.entry(row.parent_id).or_default() += 1;
        if let Some(parent_id) = row.parent_id {
            *child_counts.entry(parent_id).or_default() += 1;
        }
    }

    rows.into_iter()
        .map(|row| CweEntry {
            id: row.id,
            description: row.description,
            status: row.status,
            parent_id: row.parent_id,
            parent_count: usize::from(row.parent_id.is_some()),
            sibling_count: sibling_groups
                .get(&row.parent_id)
                .copied()
                .unwrap_or_default()
                .saturating_sub(1),
            child_count: child_counts.get(&row.id).copied().unwrap_or_default(),
        })
        .collect()
}

fn cwe_entries_tree_order(entries: Vec<CweEntry>, limit: usize) -> Vec<CweEntry> {
    let ids = entries.iter().map(|entry| entry.id).collect::<HashSet<_>>();
    let mut children = HashMap::<i32, Vec<i32>>::new();
    for entry in &entries {
        if let Some(parent_id) = entry.parent_id
            && ids.contains(&parent_id)
        {
            children.entry(parent_id).or_default().push(entry.id);
        }
    }
    for child_ids in children.values_mut() {
        child_ids.sort_unstable();
    }

    let by_id = entries
        .into_iter()
        .map(|entry| (entry.id, entry))
        .collect::<HashMap<_, _>>();
    let mut roots = by_id
        .values()
        .filter(|entry| {
            entry
                .parent_id
                .is_none_or(|parent_id| !by_id.contains_key(&parent_id))
        })
        .map(|entry| entry.id)
        .collect::<Vec<_>>();
    roots.sort_unstable();

    let mut ordered_ids = Vec::with_capacity(by_id.len());
    let mut seen = HashSet::new();
    for root_id in roots {
        push_cwe_entry_tree_id(root_id, &children, &mut seen, &mut ordered_ids);
    }
    let mut remaining = by_id.keys().copied().collect::<Vec<_>>();
    remaining.sort_unstable();
    for id in remaining {
        push_cwe_entry_tree_id(id, &children, &mut seen, &mut ordered_ids);
    }

    ordered_ids
        .into_iter()
        .take(limit)
        .filter_map(|id| by_id.get(&id).cloned())
        .collect()
}

fn push_cwe_entry_tree_id(
    id: i32,
    children: &HashMap<i32, Vec<i32>>,
    seen: &mut HashSet<i32>,
    ordered_ids: &mut Vec<i32>,
) {
    if !seen.insert(id) {
        return;
    }
    ordered_ids.push(id);
    if let Some(child_ids) = children.get(&id) {
        for child_id in child_ids {
            push_cwe_entry_tree_id(*child_id, children, seen, ordered_ids);
        }
    }
}

fn cve_references_from_raw_json(raw_json: &Value) -> Vec<CveReference> {
    let mut references = Vec::new();
    collect_reference_values(
        raw_json.pointer("/containers/cna/references"),
        &mut references,
    );
    if let Some(adps) = raw_json
        .pointer("/containers/adp")
        .and_then(Value::as_array)
    {
        for adp in adps {
            collect_reference_values(adp.get("references"), &mut references);
        }
    }
    references
}

fn collect_reference_values(value: Option<&Value>, references: &mut Vec<CveReference>) {
    let Some(items) = value.and_then(Value::as_array) else {
        return;
    };
    for item in items {
        let Some(object) = item.as_object() else {
            continue;
        };
        let tags = object
            .get("tags")
            .and_then(Value::as_array)
            .map(|tags| {
                tags.iter()
                    .filter_map(Value::as_str)
                    .map(ToOwned::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        references.push(CveReference {
            url: object
                .get("url")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            name: object
                .get("name")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            tags,
        });
    }
}

fn read_json_file_upsert_conflict() -> OnConflict {
    OnConflict::columns([
        read_json_file::Column::Filename,
        read_json_file::Column::Md5hash,
    ])
    .update_column(read_json_file::Column::UpdatedAt)
    .to_owned()
}

async fn mark_json_files_read_on<C>(
    db: &C,
    files: Vec<ReadJsonFileRecord>,
    upsert: bool,
) -> Result<usize, DbErr>
where
    C: ConnectionTrait,
{
    if files.is_empty() {
        return Ok(0);
    }

    if matches!(db.get_database_backend(), DbBackend::Sqlite) {
        return mark_json_files_read_sqlite(db, files, upsert).await;
    }

    let now = Utc::now().to_rfc3339();
    let count = files.len();
    let mut rows = Vec::with_capacity(READ_JSON_FILE_CHUNK_SIZE);

    for file in files {
        rows.push(read_json_file::ActiveModel {
            created_at: Set(now.clone()),
            updated_at: Set(now.clone()),
            filename: Set(file.filename),
            md5hash: Set(file.md5hash),
        });

        if rows.len() == READ_JSON_FILE_CHUNK_SIZE {
            insert_read_json_file_rows(std::mem::take(&mut rows), db).await?;
            rows = Vec::with_capacity(READ_JSON_FILE_CHUNK_SIZE);
        }
    }

    if !rows.is_empty() {
        insert_read_json_file_rows(rows, db).await?;
    }

    Ok(count)
}

async fn insert_read_json_file_rows<C>(
    rows: Vec<read_json_file::ActiveModel>,
    db: &C,
) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    read_json_file::Entity::insert_many(rows)
        .on_conflict(read_json_file_upsert_conflict())
        .exec(db)
        .await?;

    Ok(())
}

async fn mark_json_files_read_sqlite<C>(
    db: &C,
    files: Vec<ReadJsonFileRecord>,
    upsert: bool,
) -> Result<usize, DbErr>
where
    C: ConnectionTrait,
{
    let now = Utc::now().to_rfc3339();
    let count = files.len();
    for chunk in files.chunks(READ_JSON_FILE_CHUNK_SIZE) {
        insert_read_json_file_sqlite_chunk(db, chunk, &now, upsert).await?;
    }
    Ok(count)
}

async fn insert_read_json_file_sqlite_chunk<C>(
    db: &C,
    chunk: &[ReadJsonFileRecord],
    now: &str,
    upsert: bool,
) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    let mut sql = String::with_capacity(
        "INSERT INTO read_json_file (created_at, updated_at, filename, md5hash) VALUES ".len()
            + chunk.len() * "(?, ?, ?, ?),".len()
            + 80,
    );
    sql.push_str("INSERT INTO read_json_file (created_at, updated_at, filename, md5hash) VALUES ");

    let mut values = Vec::with_capacity(chunk.len() * 4);
    for (index, file) in chunk.iter().enumerate() {
        if index > 0 {
            sql.push_str(", ");
        }
        sql.push_str("(?, ?, ?, ?)");
        values.push(SeaValue::from(now.to_owned()));
        values.push(SeaValue::from(now.to_owned()));
        values.push(SeaValue::from(file.filename.clone()));
        values.push(SeaValue::from(file.md5hash.clone()));
    }

    if upsert {
        sql.push_str(
            " ON CONFLICT(filename, md5hash) DO UPDATE SET updated_at = excluded.updated_at",
        );
    }

    db.execute(Statement::from_sql_and_values(
        DbBackend::Sqlite,
        sql,
        values,
    ))
    .await?;
    Ok(())
}

fn summary_columns() -> [cve::Column; 6] {
    [
        cve::Column::CveId,
        cve::Column::State,
        cve::Column::PublishedAt,
        cve::Column::UpdatedAt,
        cve::Column::Title,
        cve::Column::DescriptionEn,
    ]
}

fn cve_id_prefix_summary_index_sql(state_scope: CveStateScope) -> &'static str {
    if state_scope.includes_rejected() {
        r#"
    SELECT cve_id, state, published_at, updated_at, title, description_en
    FROM cve_summary_index
    WHERE cve_id >= ? AND cve_id < ?
    ORDER BY cve_id ASC
    LIMIT ? OFFSET ?
    "#
    } else {
        r#"
    SELECT cve_id, state, published_at, updated_at, title, description_en
    FROM cve_summary_index
    WHERE cve_id >= ? AND cve_id < ? AND state = 0
    ORDER BY cve_id ASC
    LIMIT ? OFFSET ?
    "#
    }
}

fn cve_id_prefix_count_sql(state_scope: CveStateScope) -> &'static str {
    if state_scope.includes_rejected() {
        "SELECT COUNT(*) AS count FROM cve WHERE cve_id >= ? AND cve_id < ?"
    } else {
        "SELECT COUNT(*) AS count FROM cve WHERE cve_id >= ? AND cve_id < ? AND state = 0"
    }
}

fn date_prefix_summary_sql(state_scope: CveStateScope) -> &'static str {
    if state_scope.includes_rejected() {
        r#"
    SELECT DISTINCT
        cve_id,
        state,
        published_at,
        updated_at,
        title,
        description_en
    FROM (
        SELECT
            cve_id,
            state,
            published_at,
            updated_at,
            title,
            description_en
        FROM cve INDEXED BY idx_cve_published_at
        WHERE published_at >= ? AND published_at < ?
        UNION ALL
        SELECT
            cve_id,
            state,
            published_at,
            updated_at,
            title,
            description_en
        FROM cve INDEXED BY idx_cve_updated_at
        WHERE updated_at >= ? AND updated_at < ?
    )
    ORDER BY published_at DESC, cve_id ASC
    LIMIT ? OFFSET ?
    "#
    } else {
        r#"
    SELECT DISTINCT
        cve_id,
        state,
        published_at,
        updated_at,
        title,
        description_en
    FROM (
        SELECT
            cve_id,
            state,
            published_at,
            updated_at,
            title,
            description_en
        FROM cve INDEXED BY idx_cve_published_at
        WHERE published_at >= ? AND published_at < ? AND state = 0
        UNION ALL
        SELECT
            cve_id,
            state,
            published_at,
            updated_at,
            title,
            description_en
        FROM cve INDEXED BY idx_cve_updated_at
        WHERE updated_at >= ? AND updated_at < ? AND state = 0
    )
    ORDER BY published_at DESC, cve_id ASC
    LIMIT ? OFFSET ?
    "#
    }
}

fn date_prefix_count_sql(state_scope: CveStateScope) -> &'static str {
    if state_scope.includes_rejected() {
        r#"
            SELECT COUNT(DISTINCT cve_id) AS count
            FROM (
                SELECT cve_id FROM cve INDEXED BY idx_cve_published_at
                WHERE published_at >= ? AND published_at < ?
                UNION ALL
                SELECT cve_id FROM cve INDEXED BY idx_cve_updated_at
                WHERE updated_at >= ? AND updated_at < ?
            )
            "#
    } else {
        r#"
            SELECT COUNT(DISTINCT cve_id) AS count
            FROM (
                SELECT cve_id FROM cve INDEXED BY idx_cve_published_at
                WHERE published_at >= ? AND published_at < ? AND state = 0
                UNION ALL
                SELECT cve_id FROM cve INDEXED BY idx_cve_updated_at
                WHERE updated_at >= ? AND updated_at < ? AND state = 0
            )
            "#
    }
}

fn date_summary_index_sql(
    published_since: Option<&str>,
    updated_since: Option<&str>,
    state_scope: CveStateScope,
    limit: u64,
    offset: u64,
) -> String {
    let mut conditions = Vec::new();
    if !state_scope.includes_rejected() {
        conditions.push("state = 0".to_owned());
    }
    if let Some(published_since) = option_text(published_since) {
        conditions.push(format!(
            "published_at >= {}",
            sql_string_literal(published_since)
        ));
    }
    if let Some(updated_since) = option_text(updated_since) {
        conditions.push(format!(
            "updated_at >= {}",
            sql_string_literal(updated_since)
        ));
    }
    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };
    format!(
        r#"
        SELECT cve_id, state, published_at, updated_at, title, description_en
        FROM cve_summary_index
        {where_clause}
        ORDER BY published_at DESC, cve_id ASC
        LIMIT {limit} OFFSET {offset}
        "#
    )
}

fn cvss_summary_index_sql(
    min_score: Option<f64>,
    max_score: Option<f64>,
    severity: Option<&str>,
    version: Option<&str>,
    state_scope: CveStateScope,
    limit: u64,
    offset: u64,
) -> String {
    let mut conditions = Vec::new();
    if !state_scope.includes_rejected() {
        conditions.push("state = 0".to_owned());
    }
    if let Some(min_score) = min_score {
        conditions.push(format!("max_cvss_score >= {min_score}"));
    }
    if let Some(max_score) = max_score {
        conditions.push(format!("max_cvss_score <= {max_score}"));
    }
    if let Some(severity) = option_text(severity) {
        conditions.push(format!(
            "max_cvss_severity = {}",
            sql_string_literal(&severity.to_ascii_uppercase())
        ));
    }
    if let Some(version) = option_text(version) {
        conditions.push(format!(
            "cvss_versions LIKE {}",
            sql_string_literal(&format!("%|{version}|%"))
        ));
    }
    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };
    format!(
        r#"
        SELECT cve_id, state, published_at, updated_at, title, description_en
        FROM cve_cvss_search
        {where_clause}
        ORDER BY published_at DESC, cve_id ASC
        LIMIT {limit} OFFSET {offset}
        "#
    )
}

fn product_cvss_summary_index_sql(
    vendor: Option<&str>,
    product: Option<&str>,
    min_score: Option<f64>,
    max_score: Option<f64>,
    severity: Option<&str>,
    version: Option<&str>,
    state_scope: CveStateScope,
    limit: u64,
    offset: u64,
) -> String {
    let mut conditions = Vec::new();
    if !state_scope.includes_rejected() {
        conditions.push("state = 0".to_owned());
    }
    if let Some(vendor) = option_text(vendor) {
        conditions.push(format!(
            "vendor_text LIKE {}",
            sql_string_literal(&like_pattern(vendor))
        ));
    }
    if let Some(product) = option_text(product) {
        conditions.push(format!(
            "product_text LIKE {}",
            sql_string_literal(&like_pattern(product))
        ));
    }
    if let Some(min_score) = min_score {
        conditions.push(format!("max_cvss_score >= {min_score}"));
    }
    if let Some(max_score) = max_score {
        conditions.push(format!("max_cvss_score <= {max_score}"));
    }
    if let Some(severity) = option_text(severity) {
        conditions.push(format!(
            "max_cvss_severity = {}",
            sql_string_literal(&severity.to_ascii_uppercase())
        ));
    }
    if let Some(version) = option_text(version) {
        conditions.push(format!(
            "cvss_versions LIKE {}",
            sql_string_literal(&format!("%|{version}|%"))
        ));
    }
    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };
    format!(
        r#"
        SELECT cve_id, state, published_at, updated_at, title, description_en
        FROM cve_cvss_search
        {where_clause}
        ORDER BY published_at DESC, cve_id ASC
        LIMIT {limit} OFFSET {offset}
        "#
    )
}

fn reference_summary_index_sql(
    query: &str,
    state_scope: CveStateScope,
    limit: u64,
    offset: u64,
) -> String {
    let mut conditions = Vec::new();
    if !state_scope.includes_rejected() {
        conditions.push("state = 0".to_owned());
    }
    if let Some(query) = option_text(Some(query)) {
        conditions.push(format!(
            "reference_text LIKE {}",
            sql_string_literal(&like_pattern(query))
        ));
    }
    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };
    format!(
        r#"
        SELECT cve_id, state, published_at, updated_at, title, description_en
        FROM cve_summary_index
        {where_clause}
        ORDER BY published_at DESC, cve_id ASC
        LIMIT {limit} OFFSET {offset}
        "#
    )
}

fn date_range_summary_index_sql(
    published_from: Option<&str>,
    published_to: Option<&str>,
    updated_from: Option<&str>,
    updated_to: Option<&str>,
    state_scope: CveStateScope,
    limit: u64,
    offset: u64,
) -> String {
    let mut conditions = Vec::new();
    if !state_scope.includes_rejected() {
        conditions.push("state = 0".to_owned());
    }
    if let Some(value) = option_text(published_from) {
        conditions.push(format!("published_at >= {}", sql_string_literal(value)));
    }
    if let Some(value) = option_text(published_to) {
        conditions.push(format!("published_at <= {}", sql_string_literal(value)));
    }
    if let Some(value) = option_text(updated_from) {
        conditions.push(format!("updated_at >= {}", sql_string_literal(value)));
    }
    if let Some(value) = option_text(updated_to) {
        conditions.push(format!("updated_at <= {}", sql_string_literal(value)));
    }
    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };
    format!(
        r#"
        SELECT cve_id, state, published_at, updated_at, title, description_en
        FROM cve_summary_index
        {where_clause}
        ORDER BY published_at DESC, cve_id ASC
        LIMIT {limit} OFFSET {offset}
        "#
    )
}

fn fts_summary_sql(state_scope: CveStateScope) -> &'static str {
    if state_scope.includes_rejected() {
        r#"
    SELECT
        cve_summary_index.cve_id,
        cve_summary_index.state,
        cve_summary_index.published_at,
        cve_summary_index.updated_at,
        cve_summary_index.title,
        cve_summary_index.description_en
    FROM cve_summary_fts
    INNER JOIN cve_summary_index ON cve_summary_index.cve_id = cve_summary_fts.cve_id
    WHERE cve_summary_fts MATCH ?
    ORDER BY cve_summary_index.published_at DESC, cve_summary_index.cve_id ASC
    LIMIT ? OFFSET ?
    "#
    } else {
        r#"
    SELECT
        cve_summary_index.cve_id,
        cve_summary_index.state,
        cve_summary_index.published_at,
        cve_summary_index.updated_at,
        cve_summary_index.title,
        cve_summary_index.description_en
    FROM cve_summary_fts
    INNER JOIN cve_summary_index ON cve_summary_index.cve_id = cve_summary_fts.cve_id
    WHERE cve_summary_fts MATCH ? AND cve_summary_index.state = 0
    ORDER BY cve_summary_index.published_at DESC, cve_summary_index.cve_id ASC
    LIMIT ? OFFSET ?
    "#
    }
}

fn fts_ordered_summary_sql(state_scope: CveStateScope) -> &'static str {
    if state_scope.includes_rejected() {
        r#"
        WITH fts_matches AS MATERIALIZED (
            SELECT rowid AS cve_db_id
            FROM cve_summary_fts
            WHERE cve_summary_fts MATCH ?
        ),
        matches AS MATERIALIZED (
            SELECT summary.cve_db_id, summary.cve_id, summary.state, summary.published_at
            FROM cve_summary_index summary INDEXED BY idx_cve_summary_published
            WHERE summary.cve_db_id IN (SELECT cve_db_id FROM fts_matches)
            ORDER BY summary.published_at DESC, summary.cve_id ASC
            LIMIT ? OFFSET ?
        )
        SELECT matches.cve_id, matches.state, matches.published_at,
               summary.updated_at, summary.title, summary.description_en
        FROM matches
        CROSS JOIN cve_summary_index summary
        WHERE summary.cve_db_id = matches.cve_db_id
        ORDER BY matches.published_at DESC, matches.cve_id ASC
        "#
    } else {
        r#"
        WITH fts_matches AS MATERIALIZED (
            SELECT rowid AS cve_db_id
            FROM cve_summary_fts
            WHERE cve_summary_fts MATCH ?
        ),
        matches AS MATERIALIZED (
            SELECT summary.cve_db_id, summary.cve_id, summary.state, summary.published_at
            FROM cve_summary_index summary INDEXED BY idx_cve_summary_state_published
            WHERE summary.state = 0
              AND summary.cve_db_id IN (SELECT cve_db_id FROM fts_matches)
            ORDER BY summary.published_at DESC, summary.cve_id ASC
            LIMIT ? OFFSET ?
        )
        SELECT matches.cve_id, matches.state, matches.published_at,
               summary.updated_at, summary.title, summary.description_en
        FROM matches
        CROSS JOIN cve_summary_index summary
        WHERE summary.cve_db_id = matches.cve_db_id
        ORDER BY matches.published_at DESC, matches.cve_id ASC
        "#
    }
}

fn fts_count_sql(state_scope: CveStateScope) -> &'static str {
    if state_scope.includes_rejected() {
        "SELECT COUNT(*) AS count FROM cve_summary_fts WHERE cve_summary_fts MATCH ?"
    } else {
        r#"
        SELECT COUNT(*) AS count
        FROM cve_summary_fts
        INNER JOIN cve_summary_index ON cve_summary_index.cve_id = cve_summary_fts.cve_id
        WHERE cve_summary_fts MATCH ? AND cve_summary_index.state = 0
        "#
    }
}

fn osv_free_text_summary_sql(state_scope: CveStateScope) -> &'static str {
    if state_scope.includes_rejected() {
        r#"
        SELECT DISTINCT cve.cve_id, cve.state, cve.published_at, cve.updated_at, cve.title, cve.description_en
        FROM osv_text_fts
        INNER JOIN osv_cve_search s ON s.osv_id = osv_text_fts.osv_id
        INNER JOIN cve ON cve.cve_id = s.cve_id
        WHERE osv_text_fts MATCH ?
        ORDER BY cve.published_at DESC, cve.cve_id ASC
        LIMIT ? OFFSET ?
        "#
    } else {
        r#"
        SELECT DISTINCT cve.cve_id, cve.state, cve.published_at, cve.updated_at, cve.title, cve.description_en
        FROM osv_text_fts
        INNER JOIN osv_cve_search s ON s.osv_id = osv_text_fts.osv_id
        INNER JOIN cve ON cve.cve_id = s.cve_id
        WHERE osv_text_fts MATCH ? AND cve.state = 0
        ORDER BY cve.published_at DESC, cve.cve_id ASC
        LIMIT ? OFFSET ?
        "#
    }
}

fn osv_token_summary_sql(state_scope: CveStateScope) -> &'static str {
    if state_scope.includes_rejected() {
        r#"
        WITH matches AS (
            SELECT cve_id, MAX(published_at) AS published_at
            FROM osv_token_cve_search
            WHERE token >= ? AND token < ?
            GROUP BY cve_id
            ORDER BY published_at DESC, cve_id ASC
            LIMIT ? OFFSET ?
        )
        SELECT cve.cve_id, cve.state, cve.published_at, cve.updated_at, cve.title, cve.description_en
        FROM matches
        INNER JOIN cve ON cve.cve_id = matches.cve_id
        ORDER BY cve.published_at DESC, cve.cve_id ASC
        "#
    } else {
        r#"
        WITH matches AS (
            SELECT cve_id, MAX(published_at) AS published_at
            FROM osv_token_cve_search
            WHERE token >= ? AND token < ? AND state = 0
            GROUP BY cve_id
            ORDER BY published_at DESC, cve_id ASC
            LIMIT ? OFFSET ?
        )
        SELECT cve.cve_id, cve.state, cve.published_at, cve.updated_at, cve.title, cve.description_en
        FROM matches
        INNER JOIN cve ON cve.cve_id = matches.cve_id
        ORDER BY cve.published_at DESC, cve.cve_id ASC
        "#
    }
}

fn osv_alias_summary_sql(state_scope: CveStateScope) -> &'static str {
    if state_scope.includes_rejected() {
        r#"
        WITH bounds(alias, upper) AS (
            VALUES (?, ?)
        ),
        matches AS (
            SELECT s.cve_id
            FROM bounds
            CROSS JOIN osv_cve_search s
            WHERE s.osv_id >= bounds.alias AND s.osv_id < bounds.upper
            UNION
            SELECT s.cve_id
            FROM bounds
            CROSS JOIN osv_aliases a
            CROSS JOIN osv_cve_search s
            WHERE a.alias_id >= bounds.alias AND a.alias_id < bounds.upper
              AND s.osv_id = a.osv_id
        )
        SELECT cve.cve_id, cve.state, cve.published_at, cve.updated_at, cve.title, cve.description_en
        FROM matches
        CROSS JOIN cve
        WHERE cve.cve_id = matches.cve_id
        ORDER BY cve.published_at DESC, cve.cve_id ASC
        LIMIT ? OFFSET ?
        "#
    } else {
        r#"
        WITH bounds(alias, upper) AS (
            VALUES (?, ?)
        ),
        matches AS (
            SELECT s.cve_id
            FROM bounds
            CROSS JOIN osv_cve_search s
            WHERE s.osv_id >= bounds.alias AND s.osv_id < bounds.upper
            UNION
            SELECT s.cve_id
            FROM bounds
            CROSS JOIN osv_aliases a
            CROSS JOIN osv_cve_search s
            WHERE a.alias_id >= bounds.alias AND a.alias_id < bounds.upper
              AND s.osv_id = a.osv_id
        )
        SELECT cve.cve_id, cve.state, cve.published_at, cve.updated_at, cve.title, cve.description_en
        FROM matches
        CROSS JOIN cve
        WHERE cve.cve_id = matches.cve_id AND cve.state = 0
        ORDER BY cve.published_at DESC, cve.cve_id ASC
        LIMIT ? OFFSET ?
        "#
    }
}

fn fts_or_osv_count_sql(state_scope: CveStateScope) -> &'static str {
    if state_scope.includes_rejected() {
        r#"
        WITH fts_cves AS (
            SELECT cve_id
            FROM cve_summary_fts
            WHERE cve_summary_fts MATCH ?
        ),
        matching_osv AS (
            SELECT DISTINCT osv_text_fts.osv_id
            FROM osv_text_fts
            INNER JOIN osv_cve_search s ON s.osv_id = osv_text_fts.osv_id
            WHERE osv_text_fts MATCH ?
        ),
        osv_cves AS (
            SELECT DISTINCT s.cve_id
            FROM matching_osv m
            INNER JOIN osv_cve_search s ON s.osv_id = m.osv_id
        ),
        alias_cves AS (
            SELECT DISTINCT s.cve_id
            FROM osv_cve_search s
            WHERE s.osv_id >= ? AND s.osv_id < ?
            UNION
            SELECT DISTINCT s.cve_id
            FROM osv_aliases a
            INNER JOIN osv_cve_search s ON s.osv_id = a.osv_id
            WHERE a.alias_id >= ? AND a.alias_id < ?
        )
        SELECT COUNT(*) AS count
        FROM (
            SELECT cve_id FROM fts_cves
            UNION
            SELECT cve_id FROM osv_cves
            UNION
            SELECT cve_id FROM alias_cves
        )
        "#
    } else {
        r#"
        WITH fts_cves AS (
            SELECT cve_summary_index.cve_id
            FROM cve_summary_fts
            INNER JOIN cve_summary_index ON cve_summary_index.cve_id = cve_summary_fts.cve_id
            WHERE cve_summary_fts MATCH ? AND cve_summary_index.state = 0
        ),
        matching_osv AS (
            SELECT DISTINCT osv_text_fts.osv_id
            FROM osv_text_fts
            INNER JOIN osv_cve_search s ON s.osv_id = osv_text_fts.osv_id
            WHERE osv_text_fts MATCH ?
        ),
        osv_cves AS (
            SELECT DISTINCT s.cve_id
            FROM matching_osv m
            INNER JOIN osv_cve_search s ON s.osv_id = m.osv_id
        ),
        alias_cves AS (
            SELECT DISTINCT s.cve_id
            FROM osv_cve_search s
            WHERE s.osv_id >= ? AND s.osv_id < ?
            UNION
            SELECT DISTINCT s.cve_id
            FROM osv_aliases a
            INNER JOIN osv_cve_search s ON s.osv_id = a.osv_id
            WHERE a.alias_id >= ? AND a.alias_id < ?
        )
        SELECT COUNT(*) AS count
        FROM (
            SELECT cve_id FROM fts_cves
            UNION
            SELECT cve_id FROM osv_cves
            UNION
            SELECT cve_id FROM alias_cves
        ) combined
        INNER JOIN cve ON cve.cve_id = combined.cve_id
        WHERE cve.state = 0
        "#
    }
}

fn fts_or_osv_token_count_sql(state_scope: CveStateScope) -> &'static str {
    if state_scope.includes_rejected() {
        r#"
        WITH fts_cves AS (
            SELECT cve_id
            FROM cve_summary_fts
            WHERE cve_summary_fts MATCH ?
        ),
        osv_cves AS (
            SELECT cve_id
            FROM osv_token_cve_search
            WHERE token >= ? AND token < ?
        ),
        alias_cves AS (
            SELECT DISTINCT s.cve_id
            FROM osv_cve_search s
            WHERE s.osv_id >= ? AND s.osv_id < ?
            UNION
            SELECT DISTINCT s.cve_id
            FROM osv_aliases a
            INNER JOIN osv_cve_search s ON s.osv_id = a.osv_id
            WHERE a.alias_id >= ? AND a.alias_id < ?
        )
        SELECT COUNT(*) AS count
        FROM (
            SELECT cve_id FROM fts_cves
            UNION
            SELECT cve_id FROM osv_cves
            UNION
            SELECT cve_id FROM alias_cves
        )
        "#
    } else {
        r#"
        WITH fts_cves AS (
            SELECT cve_summary_index.cve_id
            FROM cve_summary_fts
            INNER JOIN cve_summary_index ON cve_summary_index.cve_id = cve_summary_fts.cve_id
            WHERE cve_summary_fts MATCH ? AND cve_summary_index.state = 0
        ),
        osv_cves AS (
            SELECT cve_id
            FROM osv_token_cve_search
            WHERE token >= ? AND token < ? AND state = 0
        ),
        alias_cves AS (
            SELECT DISTINCT s.cve_id
            FROM osv_cve_search s
            INNER JOIN cve ON cve.cve_id = s.cve_id
            WHERE s.osv_id >= ? AND s.osv_id < ? AND cve.state = 0
            UNION
            SELECT DISTINCT s.cve_id
            FROM osv_aliases a
            INNER JOIN osv_cve_search s ON s.osv_id = a.osv_id
            INNER JOIN cve ON cve.cve_id = s.cve_id
            WHERE a.alias_id >= ? AND a.alias_id < ? AND cve.state = 0
        )
        SELECT COUNT(*) AS count
        FROM (
            SELECT cve_id FROM fts_cves
            UNION
            SELECT cve_id FROM osv_cves
            UNION
            SELECT cve_id FROM alias_cves
        )
        "#
    }
}

fn affected_fts_summary_sql(state_scope: CveStateScope) -> &'static str {
    if state_scope.includes_rejected() {
        r#"
        SELECT DISTINCT
            cve_summary_index.cve_id,
            cve_summary_index.state,
            cve_summary_index.published_at,
            cve_summary_index.updated_at,
            cve_summary_index.title,
            cve_summary_index.description_en
        FROM cve_affected_summary_fts
        INNER JOIN cve_summary_index ON cve_summary_index.cve_id = cve_affected_summary_fts.cve_id
        WHERE cve_affected_summary_fts MATCH ?
        ORDER BY cve_summary_index.published_at DESC, cve_summary_index.cve_id ASC
        LIMIT ? OFFSET ?
        "#
    } else {
        r#"
        SELECT DISTINCT
            cve_summary_index.cve_id,
            cve_summary_index.state,
            cve_summary_index.published_at,
            cve_summary_index.updated_at,
            cve_summary_index.title,
            cve_summary_index.description_en
        FROM cve_affected_summary_fts
        INNER JOIN cve_summary_index ON cve_summary_index.cve_id = cve_affected_summary_fts.cve_id
        WHERE cve_affected_summary_fts MATCH ? AND cve_summary_index.state = 0
        ORDER BY cve_summary_index.published_at DESC, cve_summary_index.cve_id ASC
        LIMIT ? OFFSET ?
        "#
    }
}

fn affected_fts_ordered_rowid_summary_sql(state_scope: CveStateScope) -> &'static str {
    if state_scope.includes_rejected() {
        r#"
        WITH fts_matches AS MATERIALIZED (
            SELECT rowid AS cve_db_id
            FROM cve_affected_summary_fts
            WHERE cve_affected_summary_fts MATCH ?
        ),
        matches AS MATERIALIZED (
            SELECT summary.cve_db_id, summary.cve_id, summary.state, summary.published_at
            FROM cve_summary_index summary INDEXED BY idx_cve_summary_published
            WHERE summary.cve_db_id IN (SELECT cve_db_id FROM fts_matches)
            ORDER BY summary.published_at DESC, summary.cve_id ASC
            LIMIT ? OFFSET ?
        )
        SELECT matches.cve_id, matches.state, matches.published_at,
               summary.updated_at, summary.title, summary.description_en
        FROM matches
        CROSS JOIN cve_summary_index summary
        WHERE summary.cve_db_id = matches.cve_db_id
        ORDER BY matches.published_at DESC, matches.cve_id ASC
        "#
    } else {
        r#"
        WITH fts_matches AS MATERIALIZED (
            SELECT rowid AS cve_db_id
            FROM cve_affected_summary_fts
            WHERE cve_affected_summary_fts MATCH ?
        ),
        matches AS MATERIALIZED (
            SELECT summary.cve_db_id, summary.cve_id, summary.state, summary.published_at
            FROM cve_summary_index summary INDEXED BY idx_cve_summary_state_published
            WHERE summary.state = 0
              AND summary.cve_db_id IN (SELECT cve_db_id FROM fts_matches)
            ORDER BY summary.published_at DESC, summary.cve_id ASC
            LIMIT ? OFFSET ?
        )
        SELECT matches.cve_id, matches.state, matches.published_at,
               summary.updated_at, summary.title, summary.description_en
        FROM matches
        CROSS JOIN cve_summary_index summary
        WHERE summary.cve_db_id = matches.cve_db_id
        ORDER BY matches.published_at DESC, matches.cve_id ASC
        "#
    }
}

fn affected_fts_count_sql(state_scope: CveStateScope) -> &'static str {
    if state_scope.includes_rejected() {
        "SELECT COUNT(DISTINCT cve_id) AS count FROM cve_affected_summary_fts WHERE cve_affected_summary_fts MATCH ?"
    } else {
        r#"
        SELECT COUNT(DISTINCT cve_affected_summary_fts.cve_id) AS count
        FROM cve_affected_summary_fts
        INNER JOIN cve_summary_index ON cve_summary_index.cve_id = cve_affected_summary_fts.cve_id
        WHERE cve_affected_summary_fts MATCH ? AND cve_summary_index.state = 0
        "#
    }
}

fn affected_exact_summary_sql(
    vendor: Option<&str>,
    product: Option<&str>,
    vendor_exact: Option<&str>,
    product_exact: Option<&str>,
    published_since: Option<&str>,
    published_to: Option<&str>,
    updated_since: Option<&str>,
    state_scope: CveStateScope,
    sort_order: CveSummarySortOrder,
    limit: u64,
    offset: u64,
) -> String {
    let where_clause = affected_exact_where_clause(
        vendor,
        product,
        vendor_exact,
        product_exact,
        published_since,
        published_to,
        updated_since,
        state_scope,
    );
    let order_by = affected_exact_order_by(sort_order);
    format!(
        r#"
        SELECT DISTINCT
            cve_summary_index.cve_id,
            cve_summary_index.state,
            cve_summary_index.published_at,
            cve_summary_index.updated_at,
            cve_summary_index.title,
            cve_summary_index.description_en
        FROM cve_affected
        INNER JOIN cve_summary_index ON cve_summary_index.cve_db_id = cve_affected.cve_db_id
        {where_clause}
        ORDER BY {order_by}
        LIMIT {limit} OFFSET {offset}
        "#
    )
}

fn affected_exact_count_sql(
    vendor: Option<&str>,
    product: Option<&str>,
    vendor_exact: Option<&str>,
    product_exact: Option<&str>,
    state_scope: CveStateScope,
) -> String {
    let where_clause = affected_exact_where_clause(
        vendor,
        product,
        vendor_exact,
        product_exact,
        None,
        None,
        None,
        state_scope,
    );
    format!(
        r#"
        SELECT COUNT(DISTINCT cve_affected.cve_db_id) AS count
        FROM cve_affected
        INNER JOIN cve_summary_index ON cve_summary_index.cve_db_id = cve_affected.cve_db_id
        {where_clause}
        "#
    )
}

fn affected_exact_where_clause(
    vendor: Option<&str>,
    product: Option<&str>,
    vendor_exact: Option<&str>,
    product_exact: Option<&str>,
    published_since: Option<&str>,
    published_to: Option<&str>,
    updated_since: Option<&str>,
    state_scope: CveStateScope,
) -> String {
    let mut conditions = Vec::new();
    if !state_scope.includes_rejected() {
        conditions.push("cve_summary_index.state = 0".to_owned());
    }
    if let Some(vendor) = option_text(vendor) {
        conditions.push(format!(
            "cve_affected.vendor LIKE {}",
            sql_string_literal(&like_pattern(vendor))
        ));
    }
    if let Some(product) = option_text(product) {
        conditions.push(format!(
            "cve_affected.product LIKE {}",
            sql_string_literal(&like_pattern(product))
        ));
    }
    if let Some(vendor_exact) = option_text(vendor_exact) {
        conditions.push(format!(
            "cve_affected.vendor = {}",
            sql_string_literal(vendor_exact)
        ));
    }
    if let Some(product_exact) = option_text(product_exact) {
        conditions.push(format!(
            "cve_affected.product = {}",
            sql_string_literal(product_exact)
        ));
    }
    if let Some(published_since) = option_text(published_since) {
        conditions.push(format!(
            "cve_summary_index.published_at >= {}",
            sql_string_literal(published_since)
        ));
    }
    if let Some(published_to) = option_text(published_to) {
        conditions.push(format!(
            "cve_summary_index.published_at <= {}",
            sql_string_literal(published_to)
        ));
    }
    if let Some(updated_since) = option_text(updated_since) {
        conditions.push(format!(
            "cve_summary_index.updated_at >= {}",
            sql_string_literal(updated_since)
        ));
    }

    if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    }
}

fn affected_exact_order_by(sort_order: CveSummarySortOrder) -> &'static str {
    match sort_order {
        CveSummarySortOrder::PublishedAsc | CveSummarySortOrder::RelationRankAsc => {
            "cve_summary_index.published_at ASC, cve_summary_index.cve_id ASC"
        }
        CveSummarySortOrder::UpdatedAsc => {
            "cve_summary_index.updated_at ASC, cve_summary_index.cve_id ASC"
        }
        CveSummarySortOrder::UpdatedDesc => {
            "cve_summary_index.updated_at DESC, cve_summary_index.cve_id ASC"
        }
        CveSummarySortOrder::CveIdAsc => "cve_summary_index.cve_id ASC",
        CveSummarySortOrder::CveIdDesc => "cve_summary_index.cve_id DESC",
        CveSummarySortOrder::ScoreAsc => {
            "cve_summary_index.max_cvss_score ASC, cve_summary_index.published_at DESC, cve_summary_index.cve_id ASC"
        }
        CveSummarySortOrder::PublishedDesc
        | CveSummarySortOrder::RelationRankDesc
        | CveSummarySortOrder::ScoreDesc => {
            "cve_summary_index.published_at DESC, cve_summary_index.cve_id ASC"
        }
    }
}

fn advanced_summary_sql(options: &CveAdvancedSearch, limit: u64, offset: u64) -> String {
    let where_clause = advanced_where_clause(options);
    let order_by = match options.sort_order {
        CveSummarySortOrder::PublishedAsc => "cve.published_at ASC, cve.cve_id ASC",
        CveSummarySortOrder::PublishedDesc => "cve.published_at DESC, cve.cve_id ASC",
        CveSummarySortOrder::UpdatedAsc => "cve.updated_at ASC, cve.cve_id ASC",
        CveSummarySortOrder::UpdatedDesc => "cve.updated_at DESC, cve.cve_id ASC",
        CveSummarySortOrder::CveIdAsc => "cve.cve_id ASC",
        CveSummarySortOrder::CveIdDesc => "cve.cve_id DESC",
        CveSummarySortOrder::RelationRankAsc => "cve.published_at ASC, cve.cve_id ASC",
        CveSummarySortOrder::RelationRankDesc => "cve.published_at DESC, cve.cve_id ASC",
        CveSummarySortOrder::ScoreAsc => {
            "COALESCE((SELECT MAX(base_score) FROM cve_cvss WHERE cve_cvss.cve_db_id = cve.id), -1) ASC, cve.published_at DESC, cve.cve_id ASC"
        }
        CveSummarySortOrder::ScoreDesc => {
            "COALESCE((SELECT MAX(base_score) FROM cve_cvss WHERE cve_cvss.cve_db_id = cve.id), -1) DESC, cve.published_at DESC, cve.cve_id ASC"
        }
    };

    format!(
        r#"
        SELECT
            cve.cve_id,
            cve.state,
            cve.published_at,
            cve.updated_at,
            cve.title,
            cve.description_en
        FROM cve
        {where_clause}
        ORDER BY {order_by}
        LIMIT {limit} OFFSET {offset}
        "#
    )
}

fn advanced_count_sql(options: &CveAdvancedSearch) -> String {
    let where_clause = advanced_where_clause(options);
    format!(
        r#"
        SELECT COUNT(*) AS count
        FROM cve
        {where_clause}
        "#
    )
}

fn apply_affected_filters(
    mut query: sea_orm::Select<cve::Entity>,
    vendor: Option<&str>,
    product: Option<&str>,
    vendor_exact: Option<&str>,
    product_exact: Option<&str>,
) -> sea_orm::Select<cve::Entity> {
    if let Some(vendor) = option_text(vendor) {
        query = query.filter(cve_affected::Column::Vendor.like(like_pattern(vendor)));
    }
    if let Some(product) = option_text(product) {
        query = query.filter(cve_affected::Column::Product.like(like_pattern(product)));
    }
    if let Some(vendor_exact) = option_text(vendor_exact) {
        query = query.filter(cve_affected::Column::Vendor.eq(vendor_exact.to_owned()));
    }
    if let Some(product_exact) = option_text(product_exact) {
        query = query.filter(cve_affected::Column::Product.eq(product_exact.to_owned()));
    }
    query
}

fn advanced_where_clause(options: &CveAdvancedSearch) -> String {
    let mut conditions = Vec::new();

    if !options.state_scope.includes_rejected() {
        conditions.push("cve.state = 0".to_owned());
    }
    if let Some(query) = option_text(options.query.as_deref()) {
        advanced_query_conditions(options.query_mode, query, &mut conditions);
    }
    if let Some(published_from) = option_text(options.published_from.as_deref()) {
        conditions.push(format!(
            "cve.published_at >= {}",
            sql_string_literal(published_from)
        ));
    }
    if let Some(published_to) = option_text(options.published_to.as_deref()) {
        conditions.push(format!(
            "cve.published_at <= {}",
            sql_string_literal(published_to)
        ));
    }
    if let Some(cwe) = option_text(options.cwe.as_deref())
        && let Some(cwe_id) = cwe_number(cwe)
    {
        conditions.push(format!(
            "EXISTS (SELECT 1 FROM cve_cwe INDEXED BY idx_cve_cwe_cwe_id_cve_db_id WHERE cve_cwe.cwe_id = {cwe_id} AND cve_cwe.cve_db_id = cve.id)"
        ));
    }
    let vendor = option_text(options.vendor.as_deref());
    let product = option_text(options.product.as_deref());
    if let Some(query) = affected_fts_query(vendor, product) {
        conditions.push(format!(
            "cve.cve_id IN (SELECT cve_id FROM cve_affected_summary_fts WHERE cve_affected_summary_fts MATCH {})",
            sql_string_literal(&query)
        ));
    } else {
        if let Some(vendor) = vendor {
            conditions.push(format!(
                "EXISTS (SELECT 1 FROM cve_affected WHERE cve_affected.cve_db_id = cve.id AND cve_affected.vendor LIKE {})",
                sql_string_literal(&like_pattern(vendor))
            ));
        }
        if let Some(product) = product {
            conditions.push(format!(
                "EXISTS (SELECT 1 FROM cve_affected WHERE cve_affected.cve_db_id = cve.id AND cve_affected.product LIKE {})",
                sql_string_literal(&like_pattern(product))
            ));
        }
    }
    if let Some(vendor_exact) = option_text(options.vendor_exact.as_deref()) {
        conditions.push(format!(
            "EXISTS (SELECT 1 FROM cve_affected WHERE cve_affected.cve_db_id = cve.id AND cve_affected.vendor = {})",
            sql_string_literal(vendor_exact)
        ));
    }
    if let Some(product_exact) = option_text(options.product_exact.as_deref()) {
        conditions.push(format!(
            "EXISTS (SELECT 1 FROM cve_affected WHERE cve_affected.cve_db_id = cve.id AND cve_affected.product = {})",
            sql_string_literal(product_exact)
        ));
    }

    if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    }
}

fn advanced_query_conditions(
    mode: Option<CveAdvancedQueryMode>,
    query: &str,
    conditions: &mut Vec<String>,
) {
    match mode.unwrap_or(CveAdvancedQueryMode::FreeText) {
        CveAdvancedQueryMode::FreeText => {
            if let Some(query) = fts_query(query) {
                conditions.push(format!(
                    "cve.cve_id IN (SELECT cve_id FROM cve_summary_fts WHERE cve_summary_fts MATCH {})",
                    sql_string_literal(&query)
                ));
            } else {
                let pattern = sql_string_literal(&like_pattern(query));
                conditions.push(format!(
                    "(cve.cve_id LIKE {pattern} OR cve.title LIKE {pattern} OR cve.description_en LIKE {pattern})"
                ));
            }
        }
        CveAdvancedQueryMode::Product => {
            if let Some(query) = affected_fts_query(None, Some(query)) {
                conditions.push(format!(
                    "cve.cve_id IN (SELECT cve_id FROM cve_affected_summary_fts WHERE cve_affected_summary_fts MATCH {})",
                    sql_string_literal(&query)
                ));
            } else {
                conditions.push(format!(
                    "EXISTS (SELECT 1 FROM cve_affected WHERE cve_affected.cve_db_id = cve.id AND cve_affected.product LIKE {})",
                    sql_string_literal(&like_pattern(query))
                ));
            }
        }
        CveAdvancedQueryMode::Vendor => {
            if let Some(query) = affected_fts_query(Some(query), None) {
                conditions.push(format!(
                    "cve.cve_id IN (SELECT cve_id FROM cve_affected_summary_fts WHERE cve_affected_summary_fts MATCH {})",
                    sql_string_literal(&query)
                ));
            } else {
                conditions.push(format!(
                    "EXISTS (SELECT 1 FROM cve_affected WHERE cve_affected.cve_db_id = cve.id AND cve_affected.vendor LIKE {})",
                    sql_string_literal(&like_pattern(query))
                ));
            }
        }
        CveAdvancedQueryMode::Cwe => {
            if let Some(cwe_id) = cwe_number(query) {
                conditions.push(format!(
                    "EXISTS (SELECT 1 FROM cve_cwe INDEXED BY idx_cve_cwe_cwe_id_cve_db_id WHERE cve_cwe.cwe_id = {cwe_id} AND cve_cwe.cve_db_id = cve.id)"
                ));
            }
        }
        CveAdvancedQueryMode::Cve => {
            if let Some(upper_bound) = ascii_prefix_upper_bound(query) {
                let lower_bound = sql_string_literal(query);
                let upper_bound = sql_string_literal(&upper_bound);
                conditions.push(format!(
                    "(cve.cve_id >= {lower_bound} AND cve.cve_id < {upper_bound})"
                ));
            }
        }
    }
}

fn apply_advanced_query_filter(
    query: sea_orm::Select<cve::Entity>,
    mode: Option<CveAdvancedQueryMode>,
    search_query: &str,
) -> sea_orm::Select<cve::Entity> {
    match mode.unwrap_or(CveAdvancedQueryMode::FreeText) {
        CveAdvancedQueryMode::FreeText => {
            let pattern = like_pattern(search_query);
            query.filter(
                cve::Column::CveId
                    .like(pattern.clone())
                    .or(cve::Column::Title.like(pattern.clone()))
                    .or(cve::Column::DescriptionEn.like(pattern)),
            )
        }
        CveAdvancedQueryMode::Product => query.filter(Expr::cust(format!(
            "EXISTS (SELECT 1 FROM cve_affected WHERE cve_affected.cve_db_id = cve.id AND cve_affected.product LIKE {})",
            sql_string_literal(&like_pattern(search_query))
        ))),
        CveAdvancedQueryMode::Vendor => query.filter(Expr::cust(format!(
            "EXISTS (SELECT 1 FROM cve_affected WHERE cve_affected.cve_db_id = cve.id AND cve_affected.vendor LIKE {})",
            sql_string_literal(&like_pattern(search_query))
        ))),
        CveAdvancedQueryMode::Cwe => {
            if let Some(cwe_id) = cwe_number(search_query) {
                query.filter(Expr::cust(format!(
                    "EXISTS (SELECT 1 FROM cve_cwe INDEXED BY idx_cve_cwe_cwe_id_cve_db_id WHERE cve_cwe.cwe_id = {cwe_id} AND cve_cwe.cve_db_id = cve.id)"
                )))
            } else {
                query
            }
        }
        CveAdvancedQueryMode::Cve => {
            if let Some(upper_bound) = ascii_prefix_upper_bound(search_query) {
                query.filter(
                    cve::Column::CveId
                        .gte(search_query.to_owned())
                        .and(cve::Column::CveId.lt(upper_bound)),
                )
            } else {
                query
            }
        }
    }
}

fn cwe_summary_index_sql(
    cwe_ids: &[i32],
    state_scope: CveStateScope,
    limit: u64,
    offset: u64,
) -> String {
    let distinct = if cwe_ids.len() > 1 { "DISTINCT " } else { "" };
    let state_filter = state_sql_filter(state_scope, "cve_cwe_search");
    format!(
        r#"
        SELECT {distinct}
            cve_id,
            state,
            published_at,
            updated_at,
            title,
            description_en
        FROM cve_cwe_search
        WHERE cwe_id IN ({}){state_filter}
        ORDER BY published_at DESC, cve_id ASC
        LIMIT {} OFFSET {}
        "#,
        cwe_id_list(cwe_ids),
        limit,
        offset
    )
}

fn cwe_model_sql(cwe_ids: &[i32], state_scope: CveStateScope, limit: u64, offset: u64) -> String {
    let distinct = if cwe_ids.len() > 1 { "DISTINCT " } else { "" };
    let state_filter = state_sql_filter(state_scope, "cve");
    format!(
        r#"
        SELECT {distinct}
            cve.id,
            cve.cve_id,
            cve.state,
            cve.published_at,
            cve.updated_at,
            cve.serial,
            cve.title,
            cve.description_en,
            cve.reference_text,
            cve.raw_json
        FROM cve_cwe INDEXED BY idx_cve_cwe_cwe_id_cve_db_id
        INNER JOIN cve ON cve.id = cve_cwe.cve_db_id
        WHERE cve_cwe.cwe_id IN ({}){state_filter}
        ORDER BY cve.published_at DESC, cve.cve_id ASC
        LIMIT {} OFFSET {}
        "#,
        cwe_id_list(cwe_ids),
        limit,
        offset
    )
}

fn cwe_count_summary_index_sql(cwe_ids: &[i32], state_scope: CveStateScope) -> String {
    if state_scope.includes_rejected() {
        format!(
            "SELECT COUNT(DISTINCT cve_id) AS count FROM cve_cwe_search WHERE cwe_id IN ({})",
            cwe_id_list(cwe_ids)
        )
    } else {
        format!(
            r#"
            SELECT COUNT(DISTINCT cve_id) AS count
            FROM cve_cwe_search
            WHERE cwe_id IN ({}) AND state = 0
            "#,
            cwe_id_list(cwe_ids)
        )
    }
}

fn state_sql_filter(state_scope: CveStateScope, table_alias: &str) -> String {
    if state_scope.includes_rejected() {
        String::new()
    } else {
        format!(" AND {table_alias}.state = 0")
    }
}

fn cwe_id_list(cwe_ids: &[i32]) -> String {
    cwe_ids
        .iter()
        .map(i32::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn dedupe_summaries_by_cve_id(mut cves: Vec<CveSummary>) -> Vec<CveSummary> {
    let mut seen = HashSet::new();
    cves.retain(|cve| seen.insert(cve.cve_id.clone()));
    cves
}

fn append_unique_summaries(target: &mut Vec<CveSummary>, cves: Vec<CveSummary>) {
    let mut seen = target
        .iter()
        .map(|cve| cve.cve_id.clone())
        .collect::<HashSet<_>>();
    target.extend(
        cves.into_iter()
            .filter(|cve| seen.insert(cve.cve_id.clone())),
    );
}

fn fts_query(query: &str) -> Option<String> {
    let tokens = fts_tokens(query)
        .into_iter()
        .map(|token| format!("{token}*"))
        .collect::<Vec<_>>();
    if tokens.is_empty() {
        None
    } else {
        Some(tokens.join(" AND "))
    }
}

fn single_fts_token(query: &str) -> Option<String> {
    let tokens = fts_tokens(query);
    (tokens.len() == 1).then(|| tokens[0].clone())
}

fn fts_tokens(query: &str) -> Vec<String> {
    query
        .split(|ch: char| !ch.is_alphanumeric())
        .filter(|token| token.len() >= 2)
        .map(fts_token)
        .collect::<Vec<_>>()
}

fn token_prefix_upper_bound(token: &str) -> String {
    let mut upper = token.to_owned();
    upper.push(char::MAX);
    upper
}

fn is_identifier_like_query(query: &str) -> bool {
    let query = query.trim();
    query.len() >= 4
        && query.contains('-')
        && query
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
}

fn affected_fts_query(vendor: Option<&str>, product: Option<&str>) -> Option<String> {
    let mut clauses = Vec::new();
    if let Some(vendor) = vendor.and_then(|value| fts_column_query("vendor_text", value)) {
        clauses.push(vendor);
    }
    if let Some(product) = product.and_then(|value| fts_column_query("product_text", value)) {
        clauses.push(product);
    }
    if clauses.is_empty() {
        None
    } else {
        Some(clauses.join(" AND "))
    }
}

fn fts_column_query(column: &str, value: &str) -> Option<String> {
    let tokens = value
        .split(|ch: char| !ch.is_alphanumeric())
        .filter(|token| token.len() >= 2)
        .map(|token| format!("{column}:{}*", fts_token(token)))
        .collect::<Vec<_>>();
    if tokens.is_empty() {
        None
    } else {
        Some(tokens.join(" AND "))
    }
}

fn fts_token(token: &str) -> String {
    token
        .chars()
        .filter(|ch| ch.is_alphanumeric())
        .collect::<String>()
}

fn should_search_affected_text(query: &str) -> bool {
    let query = query.trim();
    !(is_cve_id_prefix_query(query)
        || is_cwe_id_query(query)
        || is_dateish_query(query)
        || query.len() < 2)
}

fn is_cve_id_prefix_query(query: &str) -> bool {
    query
        .get(..4)
        .map(|prefix| prefix.eq_ignore_ascii_case("CVE-"))
        .unwrap_or(false)
}

fn is_cwe_id_query(query: &str) -> bool {
    query
        .get(..4)
        .map(|prefix| prefix.eq_ignore_ascii_case("CWE-"))
        .unwrap_or(false)
}

fn is_dateish_query(query: &str) -> bool {
    query.len() >= 4
        && query
            .chars()
            .all(|ch| ch.is_ascii_digit() || matches!(ch, '-' | ':' | 'T' | 't' | 'Z' | 'z'))
}

fn ascii_prefix_upper_bound(prefix: &str) -> Option<String> {
    let mut bytes = prefix.as_bytes().to_vec();
    while let Some(last) = bytes.pop() {
        if last < 0x7f {
            bytes.push(last + 1);
            return String::from_utf8(bytes).ok();
        }
    }
    None
}

fn option_text(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

#[inline]
fn like_pattern(value: &str) -> String {
    format!("%{value}%")
}

struct RawRecordInput<'a> {
    source: &'a str,
    source_record_id: &'a str,
    source_path: Option<&'a str>,
    provider_published_at: Option<&'a str>,
    provider_modified_at: Option<&'a str>,
    score_date: Option<&'a str>,
    fetched_at: &'a str,
    content_hash: &'a str,
    raw_content: &'a str,
    content_type: &'a str,
}

struct ParsedOsvRawRecord {
    source_path: Option<String>,
    raw_json: String,
    parsed: OsvImportAdvisory,
    osv_id: String,
    content_hash: String,
}

#[derive(Clone, Debug, Deserialize)]
struct OsvImportAdvisory {
    #[serde(default)]
    schema_version: Option<String>,
    id: String,
    #[serde(default)]
    modified: Option<String>,
    #[serde(default)]
    published: Option<String>,
    #[serde(default)]
    withdrawn: Option<String>,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    details: Option<String>,
    #[serde(default)]
    affected: Vec<OsvImportAffected>,
    #[serde(default)]
    references: Vec<OsvImportReference>,
}

impl OsvImportAdvisory {
    fn parse_json(bytes: &[u8]) -> Result<Self, simd_json::Error> {
        let mut bytes = bytes.to_vec();
        simd_json::from_slice(&mut bytes)
    }

    fn validate_schema_shape(&self) -> Result<(), String> {
        if self.id.trim().is_empty() {
            return Err("OSV record is missing required field `id`".to_owned());
        }
        match self.modified.as_deref().map(str::trim) {
            Some(modified) if !modified.is_empty() => {}
            _ => return Err("OSV record is missing required field `modified`".to_owned()),
        }
        for (affected_index, affected) in self.affected.iter().enumerate() {
            for (range_index, range) in affected.ranges.iter().enumerate() {
                for (event_index, event) in range.events.iter().enumerate() {
                    event.validate_oneof().map_err(|reason| {
                        format!(
                            "OSV affected[{affected_index}].ranges[{range_index}].events[{event_index}] is invalid: {reason}"
                        )
                    })?;
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize)]
struct OsvImportAffected {
    #[serde(default)]
    package: Option<OsvImportPackage>,
    #[serde(default)]
    ranges: Vec<OsvImportRange>,
    #[serde(default)]
    versions: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct OsvImportPackage {
    #[serde(default)]
    ecosystem: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    purl: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct OsvImportRange {
    #[serde(rename = "type", default)]
    range_type: Option<String>,
    #[serde(default)]
    events: Vec<OsvImportRangeEvent>,
}

#[derive(Clone, Debug, Deserialize)]
struct OsvImportRangeEvent {
    #[serde(default)]
    introduced: Option<String>,
    #[serde(default)]
    fixed: Option<String>,
    #[serde(default)]
    last_affected: Option<String>,
    #[serde(default)]
    limit: Option<String>,
}

impl OsvImportRangeEvent {
    fn event_pairs(&self) -> Vec<(&'static str, &str)> {
        let mut pairs = Vec::new();
        if let Some(value) = self.introduced.as_deref() {
            pairs.push(("introduced", value));
        }
        if let Some(value) = self.fixed.as_deref() {
            pairs.push(("fixed", value));
        }
        if let Some(value) = self.last_affected.as_deref() {
            pairs.push(("last_affected", value));
        }
        if let Some(value) = self.limit.as_deref() {
            pairs.push(("limit", value));
        }
        pairs
    }

    fn validate_oneof(&self) -> Result<(), String> {
        let actual = self.event_pairs().len();
        if actual == 1 {
            Ok(())
        } else {
            Err(format!(
                "expected exactly one of introduced, fixed, last_affected, or limit; found {actual}"
            ))
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
struct OsvImportReference {
    #[serde(rename = "type", default)]
    reference_type: Option<String>,
    url: String,
}

fn parse_osv_raw_record(
    record: OsvRawRecord,
    content_hash: String,
) -> Result<ParsedOsvRawRecord, DbErr> {
    let parsed = OsvImportAdvisory::parse_json(record.raw_json.as_bytes())
        .map_err(|err| DbErr::Custom(format!("failed to parse OSV record: {err}")))?;
    parsed
        .validate_schema_shape()
        .map_err(|err| DbErr::Custom(format!("invalid OSV record {}: {err}", parsed.id)))?;
    let Some(osv_id) = option_text(Some(parsed.id.as_str())).map(ToOwned::to_owned) else {
        return Err(DbErr::Custom("OSV record has an empty id".to_owned()));
    };
    Ok(ParsedOsvRawRecord {
        source_path: record.source_path,
        raw_json: record.raw_json,
        parsed,
        osv_id,
        content_hash,
    })
}

#[derive(Clone, Debug, FromQueryResult)]
struct PackageOsvRow {
    id: i64,
    osv_id: String,
    ecosystem: Option<String>,
    package_name: Option<String>,
    purl: Option<String>,
}

#[derive(Clone, Debug)]
struct PackageMatch {
    package_row: PackageOsvRow,
    fixed_versions: Vec<String>,
    affected: AffectedStatus,
    resolution: IdentifierResolution,
}

#[derive(Clone, Debug, FromQueryResult)]
struct IdentifierNodeRow {
    identifier: String,
}

#[derive(Clone, Debug, FromQueryResult)]
struct RangeEventRow {
    affected_package_id: i64,
    range_id: i64,
    range_type: Option<String>,
    event_type: String,
    value: String,
    event_order: i64,
}

type OsvAffectedPackageInput = (usize, Option<String>, Option<String>, Option<String>);

async fn execute_values<C>(db: &C, sql: &str, values: Vec<SeaValue>) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    db.execute(Statement::from_sql_and_values(
        DbBackend::Sqlite,
        sql,
        values,
    ))
    .await?;
    Ok(())
}

async fn execute_many_rows<C>(
    db: &C,
    insert_sql: &str,
    row_width: usize,
    mut rows: Vec<Vec<SeaValue>>,
    suffix_sql: &str,
) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    if rows.is_empty() {
        return Ok(());
    }
    let max_rows = (900 / row_width).max(1);
    while !rows.is_empty() {
        let take = rows.len().min(max_rows);
        let chunk = rows.drain(..take);
        let placeholders = std::iter::repeat_n(
            format!(
                "({})",
                std::iter::repeat_n("?", row_width)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            take,
        )
        .collect::<Vec<_>>()
        .join(", ");
        let mut values = Vec::with_capacity(take * row_width);
        for mut row in chunk {
            debug_assert_eq!(row.len(), row_width);
            values.append(&mut row);
        }
        db.execute(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            format!("{insert_sql} VALUES {placeholders} {suffix_sql}"),
            values,
        ))
        .await?;
    }
    Ok(())
}

fn text_value(value: Option<String>) -> SeaValue {
    SeaValue::from(value)
}

async fn upsert_raw_record<C>(db: &C, input: RawRecordInput<'_>) -> Result<i64, DbErr>
where
    C: ConnectionTrait,
{
    let (stored_raw_content, raw_json) = raw_record_content_values(&input)?;
    let row = db
        .query_one(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            r#"
        INSERT INTO source_raw_records (
            source, source_record_id, source_path, provider_published_at,
            provider_modified_at, score_date, fetched_at, content_hash,
            raw_content, raw_json, raw_csv, content_type
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(source, source_record_id) DO UPDATE SET
            source_path = excluded.source_path,
            provider_published_at = excluded.provider_published_at,
            provider_modified_at = excluded.provider_modified_at,
            score_date = excluded.score_date,
            fetched_at = excluded.fetched_at,
            content_hash = excluded.content_hash,
            raw_content = excluded.raw_content,
            raw_json = excluded.raw_json,
            raw_csv = excluded.raw_csv,
            content_type = excluded.content_type
        RETURNING id
        "#,
            vec![
                SeaValue::from(input.source.to_owned()),
                SeaValue::from(input.source_record_id.to_owned()),
                SeaValue::from(input.source_path.map(ToOwned::to_owned)),
                SeaValue::from(input.provider_published_at.map(ToOwned::to_owned)),
                SeaValue::from(input.provider_modified_at.map(ToOwned::to_owned)),
                SeaValue::from(input.score_date.map(ToOwned::to_owned)),
                SeaValue::from(input.fetched_at.to_owned()),
                SeaValue::from(input.content_hash.to_owned()),
                SeaValue::from(stored_raw_content),
                SeaValue::from(raw_json),
                SeaValue::from(
                    (input.content_type == "text/csv").then(|| input.raw_content.to_owned()),
                ),
                SeaValue::from(input.content_type.to_owned()),
            ],
        ))
        .await?
        .ok_or_else(|| DbErr::Custom("raw record upsert did not return a row".to_owned()))?;
    row.try_get::<i64>("", "id")
}

async fn insert_raw_record<C>(db: &C, input: RawRecordInput<'_>) -> Result<i64, DbErr>
where
    C: ConnectionTrait,
{
    let (stored_raw_content, raw_json) = raw_record_content_values(&input)?;
    let row = db
        .query_one(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            r#"
        INSERT INTO source_raw_records (
            source, source_record_id, source_path, provider_published_at,
            provider_modified_at, score_date, fetched_at, content_hash,
            raw_content, raw_json, raw_csv, content_type
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        RETURNING id
        "#,
            vec![
                SeaValue::from(input.source.to_owned()),
                SeaValue::from(input.source_record_id.to_owned()),
                SeaValue::from(input.source_path.map(ToOwned::to_owned)),
                SeaValue::from(input.provider_published_at.map(ToOwned::to_owned)),
                SeaValue::from(input.provider_modified_at.map(ToOwned::to_owned)),
                SeaValue::from(input.score_date.map(ToOwned::to_owned)),
                SeaValue::from(input.fetched_at.to_owned()),
                SeaValue::from(input.content_hash.to_owned()),
                SeaValue::from(stored_raw_content),
                SeaValue::from(raw_json),
                SeaValue::from(
                    (input.content_type == "text/csv").then(|| input.raw_content.to_owned()),
                ),
                SeaValue::from(input.content_type.to_owned()),
            ],
        ))
        .await?
        .ok_or_else(|| DbErr::Custom("raw record insert did not return a row".to_owned()))?;
    row.try_get::<i64>("", "id")
}

fn raw_record_content_values(
    input: &RawRecordInput<'_>,
) -> Result<(String, Option<String>), DbErr> {
    if input.content_type != "application/json" {
        return Ok((input.raw_content.to_owned(), None));
    }
    let compact = compact_json_str(input.raw_content).map_err(|err| {
        DbErr::Custom(format!(
            "failed to store raw JSON for {} {}: {err}",
            input.source, input.source_record_id
        ))
    })?;
    Ok((compact.clone(), Some(compact)))
}

async fn insert_osv_normalized<C>(
    db: &C,
    parsed: &OsvImportAdvisory,
    raw_record_id: i64,
) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    write_osv_normalized(db, parsed, raw_record_id, false).await
}

async fn replace_osv_normalized<C>(
    db: &C,
    parsed: &OsvImportAdvisory,
    raw_record_id: i64,
) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    write_osv_normalized(db, parsed, raw_record_id, true).await
}

async fn write_osv_normalized<C>(
    db: &C,
    parsed: &OsvImportAdvisory,
    raw_record_id: i64,
    replace_existing: bool,
) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    let osv_id = normalize_identifier(&parsed.id);
    if replace_existing {
        for sql in [
            "DELETE FROM vulnerability_identifier_edges WHERE source = 'OSV aliases' AND (from_identifier = ? OR to_identifier = ?)",
            "DELETE FROM osv_references WHERE osv_id = ?",
            "DELETE FROM osv_aliases WHERE osv_id = ?",
            "DELETE FROM osv_cve_search WHERE osv_id = ?",
        ] {
            let values = if sql.contains("from_identifier") {
                vec![
                    SeaValue::from(osv_id.clone()),
                    SeaValue::from(osv_id.clone()),
                ]
            } else {
                vec![SeaValue::from(osv_id.clone())]
            };
            execute_values(db, sql, values).await?;
        }
        for sql in [
            "DELETE FROM osv_range_events WHERE range_id IN (SELECT r.id FROM osv_ranges r INNER JOIN osv_affected_packages p ON p.id = r.affected_package_id WHERE p.osv_id = ?)",
            "DELETE FROM osv_ranges WHERE affected_package_id IN (SELECT id FROM osv_affected_packages WHERE osv_id = ?)",
            "DELETE FROM osv_versions WHERE affected_package_id IN (SELECT id FROM osv_affected_packages WHERE osv_id = ?)",
            "DELETE FROM osv_affected_packages WHERE osv_id = ?",
        ] {
            execute_values(db, sql, vec![SeaValue::from(osv_id.clone())]).await?;
        }
    }
    execute_values(
        db,
        r#"
        INSERT INTO osv_advisories (
            osv_id, schema_version, published_at, modified_at, withdrawn_at,
            summary, details, raw_record_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(osv_id) DO UPDATE SET
            schema_version = excluded.schema_version,
            published_at = excluded.published_at,
            modified_at = excluded.modified_at,
            withdrawn_at = excluded.withdrawn_at,
            summary = excluded.summary,
            details = excluded.details,
            raw_record_id = excluded.raw_record_id
        "#,
        vec![
            SeaValue::from(osv_id.clone()),
            text_value(parsed.schema_version.clone()),
            text_value(parsed.published.clone()),
            text_value(parsed.modified.clone()),
            text_value(parsed.withdrawn.clone()),
            text_value(parsed.summary.clone()),
            text_value(parsed.details.clone()),
            SeaValue::from(raw_record_id),
        ],
    )
    .await?;
    let now = Utc::now().to_rfc3339();
    upsert_identifier_with_type(db, &osv_id, "osv", "OSV", &now).await?;
    let aliases = parsed
        .aliases
        .iter()
        .map(|alias| normalize_identifier(alias))
        .collect::<Vec<_>>();
    execute_many_rows(
        db,
        "INSERT OR IGNORE INTO osv_aliases (osv_id, alias_id)",
        2,
        aliases
            .iter()
            .map(|alias_id| {
                vec![
                    SeaValue::from(osv_id.clone()),
                    SeaValue::from(alias_id.clone()),
                ]
            })
            .collect(),
        "",
    )
    .await?;
    let cve_ids = std::iter::once(osv_id.as_str())
        .chain(aliases.iter().map(String::as_str))
        .filter(|identifier| identifier.starts_with("CVE-"))
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    execute_many_rows(
        db,
        "INSERT OR IGNORE INTO osv_cve_search (osv_id, cve_id)",
        2,
        cve_ids
            .iter()
            .map(|cve_id| {
                vec![
                    SeaValue::from(osv_id.clone()),
                    SeaValue::from(cve_id.clone()),
                ]
            })
            .collect(),
        "",
    )
    .await?;
    upsert_identifiers(db, &aliases, "OSV", &now).await?;
    execute_many_rows(
        db,
        r#"
        INSERT OR IGNORE INTO vulnerability_identifier_edges (
            from_identifier, to_identifier, relation_type, source, confidence, evidence_json, created_at
        )
        "#,
        7,
        aliases
            .iter()
            .flat_map(|alias_id| {
                [
                    vec![
                        SeaValue::from(osv_id.clone()),
                        SeaValue::from(alias_id.clone()),
                        SeaValue::from("alias".to_owned()),
                        SeaValue::from("OSV aliases".to_owned()),
                        SeaValue::from("high".to_owned()),
                        SeaValue::from(
                            serde_json::json!({"osv_id": osv_id, "alias": alias_id}).to_string(),
                        ),
                        SeaValue::from(now.clone()),
                    ],
                    vec![
                        SeaValue::from(alias_id.clone()),
                        SeaValue::from(osv_id.clone()),
                        SeaValue::from("alias".to_owned()),
                        SeaValue::from("OSV aliases".to_owned()),
                        SeaValue::from("high".to_owned()),
                        SeaValue::from(
                            serde_json::json!({"osv_id": osv_id, "alias": alias_id}).to_string(),
                        ),
                        SeaValue::from(now.clone()),
                    ],
                ]
            })
            .collect(),
        "",
    )
    .await?;
    let affected_package_ids = insert_osv_affected_packages(
        db,
        &osv_id,
        parsed
            .affected
            .iter()
            .enumerate()
            .map(|(affected_order, affected)| {
                let package = affected.package.as_ref();
                (
                    affected_order,
                    package.and_then(|package| package.ecosystem.clone()),
                    package.and_then(|package| package.name.clone()),
                    package.and_then(|package| package.purl.clone()),
                )
            })
            .collect(),
    )
    .await?;
    let range_ids = insert_osv_ranges(
        db,
        parsed
            .affected
            .iter()
            .enumerate()
            .flat_map(|(affected_order, affected)| {
                let package_id = affected_package_ids[&affected_order];
                affected
                    .ranges
                    .iter()
                    .enumerate()
                    .map(move |(range_order, range)| {
                        (
                            affected_order,
                            range_order,
                            package_id,
                            range.range_type.clone(),
                        )
                    })
            })
            .collect(),
    )
    .await?;
    let mut event_rows = Vec::new();
    let mut version_rows = Vec::new();
    for (affected_order, affected) in parsed.affected.iter().enumerate() {
        let package_id = affected_package_ids[&affected_order];
        for (range_order, range) in affected.ranges.iter().enumerate() {
            let range_id = range_ids[&(affected_order, range_order)];
            for (event_order, event) in range.events.iter().enumerate() {
                for (event_type, value) in event.event_pairs() {
                    event_rows.push(vec![
                        SeaValue::from(range_id),
                        SeaValue::from(event_type.to_owned()),
                        SeaValue::from(value.to_owned()),
                        SeaValue::from(event_order as i64),
                    ]);
                }
            }
        }
        for version in &affected.versions {
            version_rows.push(vec![
                SeaValue::from(package_id),
                SeaValue::from(version.clone()),
            ]);
        }
    }
    execute_many_rows(
        db,
        "INSERT INTO osv_range_events (range_id, event_type, value, event_order)",
        4,
        event_rows,
        "",
    )
    .await?;
    execute_many_rows(
        db,
        "INSERT OR IGNORE INTO osv_versions (affected_package_id, version)",
        2,
        version_rows,
        "",
    )
    .await?;
    execute_many_rows(
        db,
        "INSERT OR IGNORE INTO osv_references (osv_id, reference_type, url)",
        3,
        parsed
            .references
            .iter()
            .map(|reference| {
                vec![
                    SeaValue::from(osv_id.clone()),
                    text_value(reference.reference_type.clone()),
                    SeaValue::from(reference.url.clone()),
                ]
            })
            .collect(),
        "",
    )
    .await?;
    Ok(())
}

async fn insert_osv_affected_packages<C>(
    db: &C,
    osv_id: &str,
    mut rows: Vec<OsvAffectedPackageInput>,
) -> Result<HashMap<usize, i64>, DbErr>
where
    C: ConnectionTrait,
{
    let mut ids = HashMap::with_capacity(rows.len());
    let max_rows = 900 / 5;
    while !rows.is_empty() {
        let take = rows.len().min(max_rows);
        let chunk = rows.drain(..take);
        let placeholders = std::iter::repeat_n("(?, ?, ?, ?, ?)", take)
            .collect::<Vec<_>>()
            .join(", ");
        let mut values = Vec::with_capacity(take * 5);
        for (affected_order, ecosystem, package_name, purl) in chunk {
            values.push(SeaValue::from(osv_id.to_owned()));
            values.push(SeaValue::from(affected_order as i64));
            values.push(SeaValue::from(ecosystem));
            values.push(SeaValue::from(package_name));
            values.push(SeaValue::from(purl));
        }
        let returned = db
            .query_all(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                format!(
                    r#"
                INSERT INTO osv_affected_packages (
                    osv_id, affected_order, ecosystem, package_name, purl
                ) VALUES {placeholders}
                RETURNING id, affected_order
                "#
                ),
                values,
            ))
            .await?;
        for row in returned {
            ids.insert(
                row.try_get::<i64>("", "affected_order")? as usize,
                row.try_get::<i64>("", "id")?,
            );
        }
    }
    Ok(ids)
}

async fn insert_osv_ranges<C>(
    db: &C,
    mut rows: Vec<(usize, usize, i64, Option<String>)>,
) -> Result<HashMap<(usize, usize), i64>, DbErr>
where
    C: ConnectionTrait,
{
    let mut ids = HashMap::with_capacity(rows.len());
    let max_rows = 900 / 4;
    while !rows.is_empty() {
        let take = rows.len().min(max_rows);
        let chunk = rows.drain(..take);
        let placeholders = std::iter::repeat_n("(?, ?, ?, ?)", take)
            .collect::<Vec<_>>()
            .join(", ");
        let mut values = Vec::with_capacity(take * 4);
        for (affected_order, range_order, affected_package_id, range_type) in chunk {
            values.push(SeaValue::from(affected_package_id));
            values.push(SeaValue::from(affected_order as i64));
            values.push(SeaValue::from(range_order as i64));
            values.push(SeaValue::from(range_type));
        }
        let returned = db
            .query_all(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                format!(
                    r#"
                INSERT INTO osv_ranges (
                    affected_package_id, affected_order, range_order, range_type
                ) VALUES {placeholders}
                RETURNING id, affected_order, range_order
                "#
                ),
                values,
            ))
            .await?;
        for row in returned {
            ids.insert(
                (
                    row.try_get::<i64>("", "affected_order")? as usize,
                    row.try_get::<i64>("", "range_order")? as usize,
                ),
                row.try_get::<i64>("", "id")?,
            );
        }
    }
    Ok(ids)
}

async fn mark_source_attempt<C>(
    db: &C,
    source: &str,
    content_hash: Option<&str>,
) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    let now = Utc::now().to_rfc3339();
    execute_values(
        db,
        r#"
        INSERT INTO source_sync_state (source, last_attempt_at, status, content_hash)
        VALUES (?, ?, 'running', ?)
        ON CONFLICT(source) DO UPDATE SET
            last_attempt_at = excluded.last_attempt_at,
            status = 'running',
            error_message = NULL,
            content_hash = excluded.content_hash
        "#,
        vec![
            SeaValue::from(source.to_owned()),
            SeaValue::from(now),
            SeaValue::from(content_hash.map(ToOwned::to_owned)),
        ],
    )
    .await
}

async fn mark_source_success<C>(
    db: &C,
    source: &str,
    content_hash: Option<&str>,
    last_cursor: Option<&str>,
    record_count: Option<i64>,
    schema_version: Option<&str>,
) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    let now = Utc::now().to_rfc3339();
    execute_values(
        db,
        r#"
        INSERT INTO source_sync_state (
            source, last_attempt_at, last_success_at, status, error_message,
            last_cursor, content_hash, schema_version, record_count
        ) VALUES (?, ?, ?, 'success', NULL, ?, ?, ?, ?)
        ON CONFLICT(source) DO UPDATE SET
            last_attempt_at = excluded.last_attempt_at,
            last_success_at = excluded.last_success_at,
            status = 'success',
            error_message = NULL,
            last_cursor = excluded.last_cursor,
            content_hash = excluded.content_hash,
            schema_version = excluded.schema_version,
            record_count = excluded.record_count
        "#,
        vec![
            SeaValue::from(source.to_owned()),
            SeaValue::from(now.clone()),
            SeaValue::from(now),
            SeaValue::from(last_cursor.map(ToOwned::to_owned)),
            SeaValue::from(content_hash.map(ToOwned::to_owned)),
            SeaValue::from(schema_version.map(ToOwned::to_owned)),
            SeaValue::from(record_count.unwrap_or_default()),
        ],
    )
    .await
}

async fn refresh_identifier_nodes_for_source<C>(db: &C, source: &str) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    let now = Utc::now().to_rfc3339();
    match source {
        "CVE" => {
            execute_values(
                db,
                r#"
                INSERT INTO vulnerability_identifiers (
                    identifier, identifier_type, source, first_seen_at, last_seen_at
                )
                SELECT DISTINCT cve_id, 'cve', 'CVE', ?, ?
                FROM cve
                WHERE true
                ON CONFLICT(identifier) DO UPDATE SET
                    identifier_type = excluded.identifier_type,
                    last_seen_at = excluded.last_seen_at
                "#,
                vec![SeaValue::from(now.clone()), SeaValue::from(now.clone())],
            )
            .await?;
        }
        "OSV" => {
            execute_values(
                db,
                r#"
                INSERT INTO vulnerability_identifiers (
                    identifier, identifier_type, source, first_seen_at, last_seen_at
                )
                SELECT DISTINCT osv_id, 'osv', 'OSV', ?, ?
                FROM osv_advisories
                WHERE true
                ON CONFLICT(identifier) DO UPDATE SET
                    identifier_type = excluded.identifier_type,
                    last_seen_at = excluded.last_seen_at
                "#,
                vec![SeaValue::from(now.clone()), SeaValue::from(now.clone())],
            )
            .await?;
            execute_values(
                db,
                r#"
                INSERT INTO vulnerability_identifiers (
                    identifier, identifier_type, source, first_seen_at, last_seen_at
                )
                SELECT DISTINCT
                    alias_id,
                    CASE
                        WHEN alias_id LIKE 'CVE-%' THEN 'cve'
                        WHEN alias_id LIKE 'GHSA-%' THEN 'ghsa'
                        WHEN alias_id LIKE 'RUSTSEC-%' THEN 'rustsec'
                        WHEN alias_id LIKE 'PYSEC-%' THEN 'pysec'
                        WHEN alias_id LIKE 'GO-%' THEN 'go'
                        WHEN alias_id LIKE 'OSV-%' THEN 'osv'
                        ELSE 'other'
                    END,
                    'OSV',
                    ?,
                    ?
                FROM osv_aliases
                WHERE true
                ON CONFLICT(identifier) DO UPDATE SET
                    identifier_type = excluded.identifier_type,
                    last_seen_at = excluded.last_seen_at
                "#,
                vec![SeaValue::from(now.clone()), SeaValue::from(now.clone())],
            )
            .await?;
        }
        "KEV" => {
            execute_values(
                db,
                r#"
                INSERT INTO vulnerability_identifiers (
                    identifier, identifier_type, source, first_seen_at, last_seen_at
                )
                SELECT DISTINCT cve_id, 'cve', 'KEV', ?, ?
                FROM kev_entries
                WHERE true
                ON CONFLICT(identifier) DO UPDATE SET
                    identifier_type = excluded.identifier_type,
                    last_seen_at = excluded.last_seen_at
                "#,
                vec![SeaValue::from(now.clone()), SeaValue::from(now.clone())],
            )
            .await?;
        }
        "EPSS" => {
            execute_values(
                db,
                r#"
                INSERT INTO vulnerability_identifiers (
                    identifier, identifier_type, source, first_seen_at, last_seen_at
                )
                SELECT DISTINCT cve_id, 'cve', 'EPSS', ?, ?
                FROM epss_current
                WHERE true
                ON CONFLICT(identifier) DO UPDATE SET
                    identifier_type = excluded.identifier_type,
                    last_seen_at = excluded.last_seen_at
                "#,
                vec![SeaValue::from(now.clone()), SeaValue::from(now.clone())],
            )
            .await?;
        }
        _ => {}
    }
    Ok(())
}

async fn refresh_osv_alias_edges<C>(db: &C) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    let now = Utc::now().to_rfc3339();
    for sql in [
        r#"
        INSERT OR IGNORE INTO vulnerability_identifier_edges (
            from_identifier, to_identifier, relation_type, source, confidence, evidence_json, created_at
        )
        SELECT DISTINCT
            osv_id,
            alias_id,
            'alias',
            'OSV aliases',
            'high',
            json_object('osv_id', osv_id, 'alias', alias_id),
            ?
        FROM osv_aliases
        "#,
        r#"
        INSERT OR IGNORE INTO vulnerability_identifier_edges (
            from_identifier, to_identifier, relation_type, source, confidence, evidence_json, created_at
        )
        SELECT DISTINCT
            alias_id,
            osv_id,
            'alias',
            'OSV aliases',
            'high',
            json_object('osv_id', osv_id, 'alias', alias_id),
            ?
        FROM osv_aliases
        "#,
    ] {
        execute_values(db, sql, vec![SeaValue::from(now.clone())]).await?;
    }
    Ok(())
}

async fn upsert_identifier<C>(db: &C, id: &str, source: &str, now: &str) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    let id = normalize_identifier(id);
    let identifier_type = identifier_type(&id).to_owned();
    upsert_identifier_with_type(db, &id, &identifier_type, source, now).await
}

async fn upsert_identifiers<C>(db: &C, ids: &[String], source: &str, now: &str) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    execute_many_rows(
        db,
        r#"
        INSERT INTO vulnerability_identifiers (
            identifier, identifier_type, source, first_seen_at, last_seen_at
        )
        "#,
        5,
        ids.iter()
            .map(|id| {
                let id = normalize_identifier(id);
                vec![
                    SeaValue::from(id.clone()),
                    SeaValue::from(identifier_type(&id).to_owned()),
                    SeaValue::from(source.to_owned()),
                    SeaValue::from(now.to_owned()),
                    SeaValue::from(now.to_owned()),
                ]
            })
            .collect(),
        r#"
        ON CONFLICT(identifier) DO UPDATE SET
            identifier_type = excluded.identifier_type,
            last_seen_at = excluded.last_seen_at
        "#,
    )
    .await
}

async fn upsert_identifier_with_type<C>(
    db: &C,
    id: &str,
    identifier_type: &str,
    source: &str,
    now: &str,
) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    let id = normalize_identifier(id);
    execute_values(
        db,
        r#"
        INSERT INTO vulnerability_identifiers (
            identifier, identifier_type, source, first_seen_at, last_seen_at
        ) VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(identifier) DO UPDATE SET
            identifier_type = excluded.identifier_type,
            last_seen_at = excluded.last_seen_at
        "#,
        vec![
            SeaValue::from(id.clone()),
            SeaValue::from(identifier_type.to_owned()),
            SeaValue::from(source.to_owned()),
            SeaValue::from(now.to_owned()),
            SeaValue::from(now.to_owned()),
        ],
    )
    .await
}

async fn load_osv_summaries<C>(db: &C, ids: &[String]) -> Result<Vec<OsvSummary>, DbErr>
where
    C: ConnectionTrait,
{
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    OsvSummary::find_by_statement(Statement::from_string(
        DbBackend::Sqlite,
        format!(
            "SELECT osv_id, schema_version, published_at, modified_at, withdrawn_at, summary, details FROM osv_advisories WHERE osv_id IN ({}) ORDER BY osv_id",
            sql_string_list(ids)
        ),
    ))
    .all(db)
    .await
}

#[derive(Debug, FromQueryResult)]
struct IdentifierValueRow {
    value: String,
}

#[derive(Debug, FromQueryResult)]
struct CveAffectedOverviewRow {
    cve_db_id: i32,
    vendor: Option<String>,
    product: Option<String>,
    package_name: Option<String>,
    collection_url: Option<String>,
    default_status: Option<String>,
}

async fn load_osv_ids_for_cve<C>(db: &C, cve_id: &str) -> Result<Vec<String>, DbErr>
where
    C: ConnectionTrait,
{
    IdentifierValueRow::find_by_statement(Statement::from_sql_and_values(
        DbBackend::Sqlite,
        r#"
        SELECT DISTINCT osv_id AS value
        FROM osv_cve_search
        WHERE cve_id = ?
        ORDER BY osv_id
        "#,
        vec![SeaValue::from(normalize_identifier(cve_id))],
    ))
    .all(db)
    .await
    .map(|rows| rows.into_iter().map(|row| row.value).collect())
}

async fn load_aliases_for_cve<C>(db: &C, cve_id: &str) -> Result<Vec<String>, DbErr>
where
    C: ConnectionTrait,
{
    IdentifierValueRow::find_by_statement(Statement::from_sql_and_values(
        DbBackend::Sqlite,
        r#"
        SELECT DISTINCT a.alias_id AS value
        FROM osv_cve_search s
        INNER JOIN osv_aliases a ON a.osv_id = s.osv_id
        WHERE s.cve_id = ? AND a.alias_id NOT LIKE 'CVE-%'
        ORDER BY a.alias_id
        "#,
        vec![SeaValue::from(normalize_identifier(cve_id))],
    ))
    .all(db)
    .await
    .map(|rows| rows.into_iter().map(|row| row.value).collect())
}

async fn load_affected_packages<C>(
    db: &C,
    ids: &[String],
) -> Result<Vec<AffectedPackageSummary>, DbErr>
where
    C: ConnectionTrait,
{
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    AffectedPackageSummary::find_by_statement(Statement::from_string(
        DbBackend::Sqlite,
        format!(
            r#"
            SELECT p.osv_id, p.ecosystem, p.package_name, p.purl,
                   COALESCE(GROUP_CONCAT(e.value), '') AS fixed_versions
            FROM osv_affected_packages p
            LEFT JOIN osv_ranges r ON r.affected_package_id = p.id
            LEFT JOIN osv_range_events e ON e.range_id = r.id AND e.event_type = 'fixed'
            WHERE p.osv_id IN ({})
            GROUP BY p.id
            ORDER BY p.osv_id, p.ecosystem, p.package_name
            "#,
            sql_string_list(ids)
        ),
    ))
    .all(db)
    .await
}

async fn load_kev<C>(db: &C, cve_id: &str) -> Result<Option<KevInfo>, DbErr>
where
    C: ConnectionTrait,
{
    KevInfo::find_by_statement(Statement::from_sql_and_values(
        DbBackend::Sqlite,
        "SELECT cve_id, vendor_project, product, vulnerability_name, date_added, short_description, required_action, due_date, known_ransomware_campaign_use, notes, fetched_at FROM kev_entries WHERE cve_id = ?",
        vec![SeaValue::from(normalize_identifier(cve_id))],
    ))
    .one(db)
    .await
}

async fn load_kev_many<C>(db: &C, cve_ids: &[String]) -> Result<Vec<KevInfo>, DbErr>
where
    C: ConnectionTrait,
{
    if cve_ids.is_empty() {
        return Ok(Vec::new());
    }
    KevInfo::find_by_statement(Statement::from_string(
        DbBackend::Sqlite,
        format!(
            r#"
            SELECT cve_id, vendor_project, product, vulnerability_name, date_added,
                   short_description, required_action, due_date,
                   known_ransomware_campaign_use, notes, fetched_at
            FROM kev_entries
            WHERE cve_id IN ({})
            "#,
            sql_string_list(cve_ids)
        ),
    ))
    .all(db)
    .await
}

async fn load_epss<C>(db: &C, cve_id: &str) -> Result<Option<EpssInfo>, DbErr>
where
    C: ConnectionTrait,
{
    EpssInfo::find_by_statement(Statement::from_sql_and_values(
        DbBackend::Sqlite,
        "SELECT cve_id, epss, percentile, score_date, model_version, fetched_at FROM epss_current WHERE cve_id = ?",
        vec![SeaValue::from(normalize_identifier(cve_id))],
    ))
    .one(db)
    .await
}

async fn load_epss_many<C>(db: &C, cve_ids: &[String]) -> Result<Vec<EpssInfo>, DbErr>
where
    C: ConnectionTrait,
{
    if cve_ids.is_empty() {
        return Ok(Vec::new());
    }
    EpssInfo::find_by_statement(Statement::from_string(
        DbBackend::Sqlite,
        format!(
            r#"
            SELECT cve_id, epss, percentile, score_date, model_version, fetched_at
            FROM epss_current
            WHERE cve_id IN ({})
            "#,
            sql_string_list(cve_ids)
        ),
    ))
    .all(db)
    .await
}

async fn load_existing_osv_ids<C>(db: &C, ids: &[String]) -> Result<Vec<String>, DbErr>
where
    C: ConnectionTrait,
{
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    IdentifierNodeRow::find_by_statement(Statement::from_string(
        DbBackend::Sqlite,
        format!(
            "SELECT osv_id AS identifier FROM osv_advisories WHERE osv_id IN ({})",
            sql_string_list(ids)
        ),
    ))
    .all(db)
    .await
    .map(|rows| rows.into_iter().map(|row| row.identifier).collect())
}

fn resolved_identifier_type(id: &str, osv_ids: &HashSet<String>) -> String {
    if identifier_type(id) == "cve" {
        "cve".to_owned()
    } else if osv_ids.contains(id) {
        "osv".to_owned()
    } else {
        identifier_type(id).to_owned()
    }
}

fn split_concat_values(value: &str) -> Vec<String> {
    value
        .split(',')
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

async fn load_osv_ranges_many<C>(
    db: &C,
    package_ids: &[i64],
) -> Result<HashMap<i64, Vec<RangeEventRow>>, DbErr>
where
    C: ConnectionTrait,
{
    if package_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let package_ids = package_ids
        .iter()
        .map(i64::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let rows = RangeEventRow::find_by_statement(Statement::from_string(
        DbBackend::Sqlite,
        format!(
            r#"
        SELECT r.affected_package_id, r.id AS range_id, r.range_type,
               e.event_type, e.value, e.event_order
        FROM osv_ranges r
        INNER JOIN osv_range_events e ON e.range_id = r.id
        WHERE r.affected_package_id IN ({package_ids})
        ORDER BY r.affected_package_id, r.id, e.event_order
        "#
        ),
    ))
    .all(db)
    .await?;
    let mut by_package = HashMap::new();
    for row in rows {
        by_package
            .entry(row.affected_package_id)
            .or_insert_with(Vec::new)
            .push(row);
    }
    Ok(by_package)
}

fn fixed_versions_from_ranges(ranges: &[RangeEventRow]) -> Vec<String> {
    let mut values = ranges
        .iter()
        .filter(|row| row.event_type == "fixed")
        .map(|row| row.value.clone())
        .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    values
}

fn match_version(
    ecosystem: &str,
    installed: &str,
    ranges: &[RangeEventRow],
) -> Option<AffectedStatus> {
    if !ecosystem.eq_ignore_ascii_case("crates.io") {
        return Some(AffectedStatus {
            status: "unsupported_version_scheme".to_owned(),
            confidence: "low".to_owned(),
        });
    }
    let installed = semver::Version::parse(installed).ok()?;
    if ranges.is_empty() {
        return Some(AffectedStatus {
            status: "unknown".to_owned(),
            confidence: "low".to_owned(),
        });
    }
    let mut affected = false;
    let mut by_range: HashMap<i64, Vec<&RangeEventRow>> = HashMap::new();
    for row in ranges {
        if row
            .range_type
            .as_deref()
            .is_some_and(|range_type| !range_type.eq_ignore_ascii_case("SEMVER"))
        {
            return Some(AffectedStatus {
                status: "unsupported_version_scheme".to_owned(),
                confidence: "low".to_owned(),
            });
        }
        by_range.entry(row.range_id).or_default().push(row);
    }
    for events in by_range.values_mut() {
        events.sort_by_key(|row| row.event_order);
        let mut introduced = semver::Version::new(0, 0, 0);
        let mut fixed = None;
        for event in events.iter() {
            match event.event_type.as_str() {
                "introduced" => {
                    if event.value != "0"
                        && let Ok(version) = semver::Version::parse(&event.value)
                    {
                        introduced = version;
                    }
                }
                "fixed" => {
                    if let Ok(version) = semver::Version::parse(&event.value) {
                        fixed = Some(version);
                    }
                }
                _ => {}
            }
        }
        if installed >= introduced && fixed.as_ref().is_none_or(|fixed| installed < *fixed) {
            affected = true;
        }
    }
    Some(AffectedStatus {
        status: if affected { "affected" } else { "not_affected" }.to_owned(),
        confidence: "high".to_owned(),
    })
}

fn priority_signals(
    kev: Option<&KevInfo>,
    epss: Option<&EpssInfo>,
    has_fixed_version: bool,
    affected: &AffectedStatus,
) -> PrioritySignals {
    let mut reasons = Vec::new();
    let known_exploited = kev.is_some();
    if known_exploited {
        reasons.push("CVE is listed in CISA KEV".to_owned());
    }
    if epss.is_some_and(|epss| epss.percentile >= 0.95) {
        reasons.push("EPSS percentile is >= 0.95".to_owned());
    }
    if affected.status == "affected" {
        reasons.push("Installed version is within OSV affected range".to_owned());
    }
    if has_fixed_version {
        reasons.push("Fixed version is available".to_owned());
    }
    let suggested_priority = if known_exploited {
        "urgent"
    } else if epss.is_some_and(|epss| epss.percentile >= 0.95) {
        "high"
    } else if affected.status != "affected" || affected.confidence == "low" {
        "unknown"
    } else if has_fixed_version {
        "medium"
    } else {
        "low"
    };
    PrioritySignals {
        known_exploited,
        epss_percentile: epss.map(|epss| epss.percentile),
        has_fixed_version,
        affected_confidence: affected.confidence.clone(),
        suggested_priority: suggested_priority.to_owned(),
        reasons,
    }
}

#[cfg(test)]
mod tests;
