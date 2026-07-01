pub mod entity;
pub mod migration;

use chrono::Utc;
use entity::{
    app_metadata, cve, cve_affected, cve_cvss, cve_cwe, cve_zip_file, cwe, read_json_file,
};
use md5::{Digest, Md5};
use migration::Migrator;
use std::collections::{HashMap, HashSet};

use qanvuli_models::{
    CveStatusData, RawCveRecord, RawCveStatusRecord, cna_affected_raw_values, cna_cvss_raw_values,
    cna_cwe_raw_values,
    cve::base::cve_metadata::CveState,
    cve::published::cna_description::CnaDescription,
    cwe::{WeaknessCatalog, enumeration::RelatedNature},
    parse_value_with_raw,
};
use sea_orm::sea_query::{Expr, OnConflict};
use sea_orm::{
    ColumnTrait, Condition, ConnectionTrait, Database, DatabaseConnection, DatabaseTransaction,
    DbBackend, DbErr, EntityTrait, FromQueryResult, PaginatorTrait, QueryFilter, QueryOrder,
    QuerySelect, Set, Statement, TransactionTrait, Value as SeaValue,
};
use sea_orm_migration::prelude::MigratorTrait;
use serde::{Serialize, Serializer};
use serde_json::Value;
use simd_json::{BorrowedValue, prelude::*};

const CVE_CHUNK_SIZE: usize = 2000;
const CVSS_CHUNK_SIZE: usize = CVE_CHUNK_SIZE * 2;
const AFFECTED_CHUNK_SIZE: usize = CVE_CHUNK_SIZE * 2;
const CWE_CHUNK_SIZE: usize = CVE_CHUNK_SIZE * 6;
const CWE_MASTER_CHUNK_SIZE: usize = CVE_CHUNK_SIZE * 2;
const READ_JSON_FILE_CHUNK_SIZE: usize = 8_000;
const CVE_ASSET_METADATA_PREFIX: &str = "cve_asset:";
const PUBLISHED_STATE: i32 = 0;
const REJECTED_STATE: i32 = 1;

pub struct CveActiveModels {
    pub cve_id: String,
    pub cve: cve::ActiveModel,
    pub cvss_rows: Vec<cve_cvss::ActiveModel>,
    pub affected_rows: Vec<cve_affected::ActiveModel>,
    pub cwe_master_rows: Vec<cwe::ActiveModel>,
    pub cwe_rows: Vec<cve_cwe::ActiveModel>,
}

pub struct ReadJsonFileRecord {
    pub filename: String,
    pub md5hash: String,
}

#[derive(Clone, Debug)]
pub struct CveZipFileRecord {
    pub zip_filename: String,
    pub zip_datetime: String,
    pub zip_type: i32,
}

impl ReadJsonFileRecord {
    pub fn from_content(filename: impl Into<String>, content: &[u8]) -> Self {
        Self {
            filename: filename.into(),
            md5hash: md5_hex(content),
        }
    }
}

#[derive(Clone, Debug, FromQueryResult, Serialize)]
pub struct CveSummary {
    pub cve_id: String,
    #[serde(serialize_with = "serialize_cve_state")]
    pub state: i32,
    pub published_at: String,
    pub updated_at: String,
    pub title: String,
    pub description_en: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CveSummaryWithDetail {
    pub summary: CveSummary,
    pub detail: CveDetail,
}

#[derive(Clone, Debug, FromQueryResult)]
struct CveIdMapping {
    id: i32,
}

#[derive(Clone, Debug, FromQueryResult)]
struct CveDbIdByCveId {
    id: i32,
    cve_id: String,
}

#[derive(Clone, Debug, FromQueryResult, Serialize)]
pub struct CveDatabaseStatus {
    pub cve_count: i64,
    pub published_count: i64,
    pub rejected_count: i64,
    pub cwe_count: i64,
    pub affected_count: i64,
    pub cvss_count: i64,
    pub latest_cve_updated_at: Option<String>,
    pub latest_zip_datetime: Option<String>,
    pub latest_zip_filename: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CveReference {
    pub url: Option<String>,
    pub name: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct CveDetail {
    pub cwes: Vec<CveCweDetail>,
    pub cvss: Vec<CveCvssDetail>,
    pub affected: Vec<CveAffectedDetail>,
}

#[derive(Clone, Debug, FromQueryResult, Serialize)]
pub struct CveCweDetail {
    pub id: i32,
    pub description: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CweEntry {
    pub id: i32,
    pub description: Option<String>,
    pub status: Option<String>,
    pub parent_id: Option<i32>,
    pub parent_count: usize,
    pub sibling_count: usize,
    pub child_count: usize,
}

#[derive(Clone, Debug, FromQueryResult)]
struct CweEntryRow {
    id: i32,
    description: Option<String>,
    status: Option<String>,
    parent_id: Option<i32>,
}

#[derive(Clone, Debug, FromQueryResult, Serialize)]
pub struct CveCvssDetail {
    pub version: String,
    pub base_score: Option<f64>,
    pub base_severity: Option<String>,
    pub vector_string: Option<String>,
    pub source: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CveAffectedDetail {
    pub vendor: Option<String>,
    pub product: Option<String>,
    pub package_name: Option<String>,
    pub collection_url: Option<String>,
    pub default_status: Option<String>,
    pub versions: Vec<CveAffectedVersionDetail>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct CveAffectedVersionDetail {
    pub version: Option<String>,
    pub status: Option<String>,
    pub version_type: Option<String>,
    pub less_than: Option<String>,
    pub less_than_or_equal: Option<String>,
}

#[derive(Clone, Debug, FromQueryResult)]
struct CveCweDetailRow {
    cve_db_id: i32,
    id: i32,
    description: Option<String>,
}

#[derive(Clone, Debug, FromQueryResult)]
struct CveCvssDetailRow {
    cve_db_id: i32,
    version: String,
    base_score: Option<f64>,
    base_severity: Option<String>,
    vector_string: Option<String>,
    source: Option<String>,
}

#[derive(Clone, Debug, FromQueryResult)]
struct CveAffectedDetailRow {
    cve_db_id: i32,
    vendor: Option<String>,
    product: Option<String>,
    package_name: Option<String>,
    collection_url: Option<String>,
    default_status: Option<String>,
    raw_json: String,
}

#[derive(Clone, Debug, Default)]
pub struct CveAdvancedSearch {
    pub query: Option<String>,
    pub query_mode: Option<CveAdvancedQueryMode>,
    pub published_from: Option<String>,
    pub published_to: Option<String>,
    pub cwe: Option<String>,
    pub product: Option<String>,
    pub product_exact: Option<String>,
    pub vendor: Option<String>,
    pub vendor_exact: Option<String>,
    pub state_scope: CveStateScope,
    pub sort_order: CveSummarySortOrder,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CveAdvancedQueryMode {
    FreeText,
    Product,
    Vendor,
    Cwe,
    Cve,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CveStateScope {
    #[default]
    PublishedOnly,
    IncludeRejected,
}

impl CveStateScope {
    fn includes_rejected(self) -> bool {
        matches!(self, Self::IncludeRejected)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CveSummarySortOrder {
    PublishedAsc,
    #[default]
    PublishedDesc,
    CveIdAsc,
    CveIdDesc,
    RelationRankAsc,
    RelationRankDesc,
    ScoreAsc,
    ScoreDesc,
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

    pub fn from_raw_json_string(raw_json: String) -> Result<Self, DbErr> {
        let mut bytes = raw_json.as_bytes().to_vec();
        let value: BorrowedValue<'_> =
            simd_json::to_borrowed_value(&mut bytes).map_err(json_parse_db_err)?;
        let cve_id = borrowed_cve_id(&value).unwrap_or_default().to_owned();
        let cvss_rows = borrowed_cvss_active_models(&value)?;
        let affected_rows = borrowed_affected_active_models(&value)?;
        let cwe_rows = borrowed_cwe_active_models(&value);

        Ok(Self {
            cve_id: cve_id.clone(),
            cve: borrowed_cve_active_model(raw_json, &value, &cve_id),
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

fn md5_hex(bytes: &[u8]) -> String {
    let mut hasher = Md5::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
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

pub fn cve_state_label(state: i32) -> &'static str {
    match state {
        PUBLISHED_STATE => "PUBLISHED",
        REJECTED_STATE => "REJECTED",
        _ => "UNKNOWN",
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

#[derive(Clone)]
pub struct CveDatabase {
    db: DatabaseConnection,
}

pub struct CveBulkReplaceSession {
    txn: DatabaseTransaction,
}

impl CveDatabase {
    pub async fn connect(database_url: &str) -> Result<Self, DbErr> {
        let db = connect_database(database_url).await?;
        Ok(Self { db })
    }

    pub async fn new_async(database_url: &str) -> Result<Self, DbErr> {
        Self::connect(database_url).await
    }

    pub fn connection(&self) -> &DatabaseConnection {
        &self.db
    }

    pub fn into_connection(self) -> DatabaseConnection {
        self.db
    }

    pub async fn close(self) -> Result<(), DbErr> {
        self.db.close().await
    }

    pub async fn initialize_schema(&self) -> Result<(), DbErr> {
        Migrator::up(&self.db, None).await
    }

    pub async fn rebuild_schema(&self) -> Result<(), DbErr> {
        Migrator::down(&self.db, None).await?;
        self.initialize_schema().await
    }

    pub async fn upsert_cve(&self, model: cve::ActiveModel) -> Result<(), DbErr> {
        upsert_cve_on(&self.db, model).await
    }

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

    pub async fn upsert_cve_records(
        &self,
        records: Vec<RawCveRecord<CveStatusData>>,
    ) -> Result<usize, DbErr> {
        self.upsert_cve_models(records.into_iter().map(CveActiveModels::from).collect())
            .await
    }

    pub async fn upsert_cve_raw_json_strings(&self, values: Vec<String>) -> Result<usize, DbErr> {
        self.upsert_cve_models(
            values
                .into_iter()
                .map(CveActiveModels::from_raw_json_string)
                .collect::<Result<Vec<_>, _>>()?,
        )
        .await
    }

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

    pub async fn prepare_bulk_replace_all(&self) -> Result<(), DbErr> {
        prepare_bulk_replace_all_on(&self.db).await
    }

    pub async fn begin_bulk_replace_all(&self) -> Result<CveBulkReplaceSession, DbErr> {
        prepare_bulk_replace_all_on(&self.db).await?;
        let txn = self.db.begin().await?;
        Ok(CveBulkReplaceSession { txn })
    }

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

    pub async fn finish_bulk_replace_all(&self) -> Result<(), DbErr> {
        finish_bulk_replace_all_on(&self.db).await
    }

    pub async fn compact_storage(&self) -> Result<(), DbErr> {
        compact_storage_on(&self.db).await
    }

    pub async fn clear_cve_tables(&self) -> Result<(), DbErr> {
        let txn = self.db.begin().await?;
        clear_cve_tables_on(&txn).await?;
        txn.commit().await
    }

    pub async fn upsert_cwe_catalog(&self, catalog: &WeaknessCatalog) -> Result<usize, DbErr> {
        let txn = self.db.begin().await?;
        let count = upsert_cwe_catalog_on(&txn, catalog).await?;
        txn.commit().await?;
        Ok(count)
    }

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

    pub async fn insert_cve_models(&self, models: Vec<CveActiveModels>) -> Result<usize, DbErr> {
        if models.is_empty() {
            return Ok(0);
        }

        let txn = self.db.begin().await?;
        let inserted = insert_cve_models_on(&txn, models, true).await?;
        txn.commit().await?;
        Ok(inserted)
    }

    pub async fn insert_cve_records_bulk(
        &self,
        records: Vec<RawCveRecord<CveStatusData>>,
    ) -> Result<usize, DbErr> {
        self.insert_cve_models_bulk(records.into_iter().map(CveActiveModels::from).collect())
            .await
    }

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

    pub async fn get_all(&self) -> Result<Vec<cve::Model>, DbErr> {
        cve::Entity::find()
            .order_by_desc(cve::Column::PublishedAt)
            .order_by_asc(cve::Column::CveId)
            .all(&self.db)
            .await
    }

    pub async fn find_cve_by_id(&self, cve_id: &str) -> Result<Option<cve::Model>, DbErr> {
        cve::Entity::find()
            .filter(cve::Column::CveId.eq(cve_id))
            .one(&self.db)
            .await
    }

    pub async fn find_cve_raw_json_by_id(&self, cve_id: &str) -> Result<Option<Value>, DbErr> {
        self.find_cve_by_id(cve_id)
            .await
            .and_then(|row| row.map(|row| raw_json_value(&row.raw_json)).transpose())
    }

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

    pub async fn count_cve_summaries_by_cwe(&self, cwe_ids: &[String]) -> Result<u64, DbErr> {
        self.count_cve_summaries_by_cwe_with_state_scope(cwe_ids, CveStateScope::PublishedOnly)
            .await
    }

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
            return CveSummary::find_by_statement(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                affected_fts_summary_sql(state_scope),
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

    pub async fn count_cve_summaries_by_cve_id_prefix(&self, prefix: &str) -> Result<u64, DbErr> {
        self.count_cve_summaries_by_cve_id_prefix_with_state_scope(
            prefix,
            CveStateScope::PublishedOnly,
        )
        .await
    }

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

    pub async fn count_cve_summaries_by_date_prefix(&self, prefix: &str) -> Result<u64, DbErr> {
        self.count_cve_summaries_by_date_prefix_with_state_scope(
            prefix,
            CveStateScope::PublishedOnly,
        )
        .await
    }

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
            return self
                .search_cve_summaries_by_fts_text_with_state_scope(
                    &fts_query,
                    state_scope,
                    limit,
                    offset,
                )
                .await;
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

    pub async fn count_cve_summaries_free_text(&self, query: &str) -> Result<u64, DbErr> {
        self.count_cve_summaries_free_text_with_state_scope(query, CveStateScope::PublishedOnly)
            .await
    }

    pub async fn count_cve_summaries_free_text_with_state_scope(
        &self,
        query: &str,
        state_scope: CveStateScope,
    ) -> Result<u64, DbErr> {
        let query = query.trim();
        if query.is_empty() {
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
            self.count_cve_summaries_by_fts_text_with_state_scope(&fts_query, state_scope)
                .await
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

    pub async fn search_cve_summaries_by_fts_text_with_state_scope(
        &self,
        query: &str,
        state_scope: CveStateScope,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, DbErr> {
        CveSummary::find_by_statement(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            fts_summary_sql(state_scope),
            vec![
                SeaValue::from(query.to_owned()),
                SeaValue::from(limit as i64),
                SeaValue::from(offset as i64),
            ],
        ))
        .all(&self.db)
        .await
    }

    pub async fn count_cve_summaries_by_fts_text(&self, query: &str) -> Result<u64, DbErr> {
        self.count_cve_summaries_by_fts_text_with_state_scope(query, CveStateScope::PublishedOnly)
            .await
    }

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

    pub async fn mark_json_file_read(&self, filename: &str, md5hash: &str) -> Result<(), DbErr> {
        self.mark_json_files_read(vec![ReadJsonFileRecord {
            filename: filename.to_owned(),
            md5hash: md5hash.to_owned(),
        }])
        .await?;

        Ok(())
    }

    pub async fn mark_json_files_read(
        &self,
        files: Vec<ReadJsonFileRecord>,
    ) -> Result<usize, DbErr> {
        mark_json_files_read_on(&self.db, files, true).await
    }

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

    pub async fn latest_cve_zip_datetime(&self) -> Result<Option<String>, DbErr> {
        cve_zip_file::Entity::find()
            .order_by_desc(cve_zip_file::Column::ZipDatetime)
            .order_by_desc(cve_zip_file::Column::Id)
            .one(&self.db)
            .await
            .map(|row| row.map(|row| row.zip_datetime))
    }

    pub async fn latest_cve_updated_at(&self) -> Result<Option<String>, DbErr> {
        cve::Entity::find()
            .select_only()
            .column_as(cve::Column::UpdatedAt.max(), "updated_at")
            .into_tuple::<Option<String>>()
            .one(&self.db)
            .await
            .map(|value| value.flatten().filter(|value| !value.is_empty()))
    }

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

fn serialize_cve_state<S>(state: &i32, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(cve_state_label(*state))
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
    rebuild_cve_summary_indexes(db).await?;
    db.execute_unprepared("ANALYZE").await?;
    db.execute_unprepared("PRAGMA optimize").await?;
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
        r#"
        INSERT INTO cve_summary_fts (cve_id, title, description_en, affected_text, reference_text)
        SELECT cve_id, title, COALESCE(description_en, ''), affected_text, reference_text
        FROM cve_summary_index
        {where_clause}
        "#
    ))
    .await?;
    db.execute_unprepared(&format!(
        r#"
        INSERT INTO cve_affected_summary_fts (cve_id, vendor_text, product_text, affected_text)
        SELECT cve_id, vendor_text, product_text, affected_text
        FROM cve_summary_index
        {where_clause}
        "#
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
        .map(|ids| format!("WHERE cve_id IN ({ids})"))
        .unwrap_or_default();
    db.execute_unprepared(&format!(
        r#"
        INSERT OR REPLACE INTO cve_cvss_search (
            cve_id, state, published_at, updated_at, title, description_en,
            max_cvss_score, max_cvss_severity, cvss_versions
        )
        SELECT
            cve_id, state, published_at, updated_at, title, description_en,
            max_cvss_score, max_cvss_severity,
            COALESCE((
                SELECT '|' || REPLACE(GROUP_CONCAT(DISTINCT version), ',', '|') || '|'
                FROM cve_cvss
                WHERE cve_cvss.cve_db_id = cve_summary_index.cve_db_id
            ), '')
        FROM cve_summary_index
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
    if let Some(vendor) = option_text(options.vendor.as_deref()) {
        conditions.push(format!(
            "EXISTS (SELECT 1 FROM cve_affected WHERE cve_affected.cve_db_id = cve.id AND cve_affected.vendor LIKE {})",
            sql_string_literal(&like_pattern(vendor))
        ));
    }
    if let Some(product) = option_text(options.product.as_deref()) {
        conditions.push(format!(
            "EXISTS (SELECT 1 FROM cve_affected WHERE cve_affected.cve_db_id = cve.id AND cve_affected.product LIKE {})",
            sql_string_literal(&like_pattern(product))
        ));
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
            let pattern = sql_string_literal(&like_pattern(query));
            conditions.push(format!(
                "(cve.cve_id LIKE {pattern} OR cve.title LIKE {pattern} OR cve.description_en LIKE {pattern})"
            ));
        }
        CveAdvancedQueryMode::Product => {
            conditions.push(format!(
                "EXISTS (SELECT 1 FROM cve_affected WHERE cve_affected.cve_db_id = cve.id AND cve_affected.product LIKE {})",
                sql_string_literal(&like_pattern(query))
            ));
        }
        CveAdvancedQueryMode::Vendor => {
            conditions.push(format!(
                "EXISTS (SELECT 1 FROM cve_affected WHERE cve_affected.cve_db_id = cve.id AND cve_affected.vendor LIKE {})",
                sql_string_literal(&like_pattern(query))
            ));
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
    let tokens = query
        .split(|ch: char| !ch.is_alphanumeric())
        .filter(|token| token.len() >= 2)
        .map(|token| format!("{}*", fts_token(token)))
        .collect::<Vec<_>>();
    if tokens.is_empty() {
        None
    } else {
        Some(tokens.join(" AND "))
    }
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

fn sql_string_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn option_text(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

#[inline]
fn like_pattern(value: &str) -> String {
    format!("%{value}%")
}

#[cfg(test)]
mod tests {
    use super::*;
    use qanvuli_models::parse_json_with_raw;
    use sea_orm::{PaginatorTrait, Set};
    use serde_json::json;

    const CVE_JSON: &str = r#"{
        "dataType": "CVE_RECORD",
        "dataVersion": "5.1.0",
        "cveMetadata": {
            "cveId": "CVE-2024-0001",
            "assignerOrgId": "00000000-0000-4000-8000-000000000000",
            "state": "PUBLISHED",
            "serial": 2,
            "datePublished": "2024-01-01T00:00:00Z",
            "dateUpdated": "2024-01-02T00:00:00Z"
        },
        "containers": {
            "cna": {
                "providerMetadata": {
                    "orgId": "00000000-0000-4000-8000-000000000000"
                },
                "title": "Example CVE",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "Example vulnerability."
                    }
                ],
                "affected": [
                    {
                        "vendor": "Example Vendor",
                        "product": "Example Product",
                        "defaultStatus": "affected"
                    }
                ],
                "metrics": [
                    {
                        "format": "CVSS",
                        "cvssV3_1": {
                            "version": "3.1",
                            "baseScore": 9.8,
                            "baseSeverity": "CRITICAL",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                        }
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "lang": "en",
                                "cweId": "CWE-79",
                                "description": "Cross-site Scripting"
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "https://example.com/advisory"
                    }
                ]
            }
        },
        "x_extraField": {
            "kept": true
        }
    }"#;

    #[test]
    fn raw_cve_record_converts_to_cve_active_model() {
        let raw_record = parse_json_with_raw(CVE_JSON).unwrap();
        let expected_raw_json = raw_record.raw_json().clone();
        let active_model = cve::ActiveModel::from(raw_record);

        assert_eq!(active_model.cve_id.unwrap(), "CVE-2024-0001");
        assert_eq!(active_model.state.unwrap(), PUBLISHED_STATE);
        assert_eq!(
            active_model.published_at.unwrap(),
            "2024-01-01T00:00:00+00:00"
        );
        assert_eq!(
            active_model.updated_at.unwrap(),
            "2024-01-02T00:00:00+00:00"
        );
        assert_eq!(active_model.serial.unwrap(), 2);
        assert_eq!(active_model.title.unwrap(), "Example CVE");
        assert_eq!(
            active_model.description_en.unwrap().as_deref(),
            Some("Example vulnerability.")
        );
        assert!(
            active_model
                .reference_text
                .unwrap()
                .contains("https://example.com/advisory")
        );
        assert_eq!(
            active_model.raw_json.unwrap(),
            expected_raw_json.to_string()
        );
    }

    #[test]
    fn raw_cve_record_converts_to_all_active_models() {
        let raw_record = parse_json_with_raw(CVE_JSON).unwrap();
        let models = CveActiveModels::from(raw_record);

        assert_eq!(models.cve_id, "CVE-2024-0001");
        assert_eq!(models.cvss_rows.len(), 1);
        assert_eq!(models.affected_rows.len(), 1);
        assert_eq!(models.cwe_rows.len(), 1);

        let cvss = models.cvss_rows.into_iter().next().unwrap();
        assert_eq!(cvss.cve_db_id.unwrap(), 0);
        assert_eq!(cvss.version.unwrap(), "3.1");
        assert_eq!(cvss.base_score.unwrap(), Some(9.8));
        assert_eq!(cvss.base_severity.unwrap().as_deref(), Some("CRITICAL"));
        assert_eq!(
            cvss.vector_string.unwrap().as_deref(),
            Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        );
        assert_eq!(
            raw_json_value(&cvss.raw_json.unwrap()).unwrap()["version"],
            "3.1"
        );

        let affected = models.affected_rows.into_iter().next().unwrap();
        assert_eq!(affected.cve_db_id.unwrap(), 0);
        assert_eq!(affected.vendor.unwrap().as_deref(), Some("Example Vendor"));
        assert_eq!(
            affected.product.unwrap().as_deref(),
            Some("Example Product")
        );
        assert_eq!(
            affected.default_status.unwrap().as_deref(),
            Some("affected")
        );
        assert!(affected.version_text.unwrap().is_empty());
        assert_eq!(
            raw_json_value(&affected.raw_json.unwrap()).unwrap()["vendor"],
            "Example Vendor"
        );

        let cwe = models.cwe_rows.into_iter().next().unwrap();
        assert_eq!(cwe.cve_db_id.unwrap(), 0);
        assert_eq!(cwe.cwe_id.unwrap(), 79);
        assert!(models.cwe_master_rows.is_empty());
    }

    #[test]
    fn dedupe_summaries_keeps_one_row_per_cve_id() {
        let cves = vec![
            test_summary("CVE-2024-1000", "first"),
            test_summary("CVE-2024-1000", "duplicate"),
            test_summary("CVE-2024-1001", "second"),
        ];

        let cves = dedupe_summaries_by_cve_id(cves);

        assert_eq!(cves.len(), 2);
        assert_eq!(cves[0].cve_id, "CVE-2024-1000");
        assert_eq!(cves[0].title, "first");
        assert_eq!(cves[1].cve_id, "CVE-2024-1001");
    }

    #[test]
    fn affected_text_search_skips_short_cve_and_date_queries() {
        assert!(!should_search_affected_text("a"));
        assert!(!should_search_affected_text("CVE-2024-1000"));
        assert!(!should_search_affected_text("CWE-79"));
        assert!(!should_search_affected_text("2026-06-08"));
        assert!(should_search_affected_text("Cardinarity"));
    }

    #[test]
    fn cve_id_prefix_query_accepts_cve_prefix_case_insensitively() {
        assert!(is_cve_id_prefix_query("CVE-2026"));
        assert!(is_cve_id_prefix_query("cve-2026"));
        assert!(!is_cve_id_prefix_query("CWE-79"));
        assert!(!is_cve_id_prefix_query("2026"));
    }

    #[test]
    fn cwe_id_query_accepts_cwe_prefix_case_insensitively() {
        assert!(is_cwe_id_query("CWE-79"));
        assert!(is_cwe_id_query("cwe-79"));
        assert!(!is_cwe_id_query("CVE-2026"));
        assert!(!is_cwe_id_query("79"));
    }

    fn test_summary(cve_id: &str, title: &str) -> CveSummary {
        CveSummary {
            cve_id: cve_id.to_owned(),
            state: PUBLISHED_STATE,
            published_at: "2024-02-01T00:00:00+00:00".to_owned(),
            updated_at: "2024-02-02T00:00:00+00:00".to_owned(),
            title: title.to_owned(),
            description_en: None,
        }
    }

    #[test]
    fn in_memory_sqlite_writes_and_reads_simple_cve() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();

        runtime.block_on(async {
            let db = connect_database("sqlite::memory:").await.unwrap();
            let cve_db = CveDatabase { db: db.clone() };
            cve_db.initialize_schema().await.unwrap();
            insert_test_cwe(&db).await;

            cve_db
                .upsert_cve(cve::ActiveModel {
                    id: Default::default(),
                    cve_id: Set("CVE-2026-0001".to_owned()),
                    state: Set(PUBLISHED_STATE),
                    published_at: Set("2026-01-01T00:00:00Z".to_owned()),
                    updated_at: Set("2026-01-02T00:00:00Z".to_owned()),
                    serial: Set(1),
                    title: Set("example".to_owned()),
                    description_en: Set(Some("description".to_owned())),
                    reference_text: Set(String::new()),
                    raw_json: Set(json!({"id": "CVE-2026-0001"}).to_string()),
                })
                .await
                .unwrap();

            cve_db
                .replace_cve_children(
                    "CVE-2026-0001",
                    vec![cve_cvss::ActiveModel {
                        cve_db_id: Set(0),
                        version: Set("3.1".to_owned()),
                        base_score: Set(Some(9.8)),
                        base_severity: Set(Some("CRITICAL".to_owned())),
                        vector_string: Set(Some("CVSS:3.1/...".to_owned())),
                        source: Set(Some("cna".to_owned())),
                        raw_json: Set(json!({"version": "3.1"}).to_string()),
                        ..Default::default()
                    }],
                    vec![cve_affected::ActiveModel {
                        cve_db_id: Set(0),
                        vendor: Set(Some("Example Vendor".to_owned())),
                        product: Set(Some("Example Product".to_owned())),
                        version_text: Set(String::new()),
                        raw_json: Set(json!({"vendor": "Example Vendor"}).to_string()),
                        ..Default::default()
                    }],
                    vec![cve_cwe::ActiveModel {
                        cve_db_id: Set(0),
                        cwe_id: Set(79),
                    }],
                )
                .await
                .unwrap();

            let found = cve_db
                .find_cve_by_id("CVE-2026-0001")
                .await
                .unwrap()
                .unwrap();
            assert_eq!(found.cve_id, "CVE-2026-0001");
            assert_eq!(found.state, PUBLISHED_STATE);
            assert_eq!(found.published_at, "2026-01-01T00:00:00Z");
            assert_eq!(found.updated_at, "2026-01-02T00:00:00Z");
            assert_eq!(found.serial, 1);
            assert_eq!(found.title, "example");
            assert_eq!(found.description_en.as_deref(), Some("description"));
            assert_eq!(
                raw_json_value(&found.raw_json).unwrap(),
                json!({"id": "CVE-2026-0001"})
            );

            let by_cwe = cve_db
                .search_cves_by_cwe(&["CWE-79".to_owned()], 10, 0)
                .await
                .unwrap();
            assert_eq!(by_cwe.len(), 1);

            let by_product = cve_db
                .search_cves_by_vendor_product(Some("Vendor"), Some("Product"), 10, 0)
                .await
                .unwrap();
            assert_eq!(by_product.len(), 1);

            let affected_count = cve_affected::Entity::find().count(&db).await.unwrap();
            assert_eq!(affected_count, 1);
        });
    }

    #[test]
    fn cve_summary_search_defaults_to_published_only() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();

        runtime.block_on(async {
            let db = CveDatabase::connect("sqlite::memory:").await.unwrap();
            db.initialize_schema().await.unwrap();

            for (cve_id, state, state_label) in [
                ("CVE-2026-1000", PUBLISHED_STATE, "PUBLISHED"),
                ("CVE-2026-1001", REJECTED_STATE, "REJECTED"),
            ] {
                db.upsert_cve(cve::ActiveModel {
                    id: Default::default(),
                    cve_id: Set(cve_id.to_owned()),
                    state: Set(state),
                    published_at: Set("2026-01-01T00:00:00Z".to_owned()),
                    updated_at: Set("2026-01-02T00:00:00Z".to_owned()),
                    serial: Set(1),
                    title: Set(format!("{state_label} example")),
                    description_en: Set(Some("description".to_owned())),
                    reference_text: Set(String::new()),
                    raw_json: Set(json!({"id": cve_id, "state": state_label}).to_string()),
                })
                .await
                .unwrap();
            }
            rebuild_cve_summary_indexes(db.connection()).await.unwrap();

            let default = db
                .search_cve_summaries_by_cve_id_prefix("CVE-2026-100", 10, 0)
                .await
                .unwrap();
            assert_eq!(default.len(), 1);
            assert_eq!(default[0].state, PUBLISHED_STATE);

            let including_rejected = db
                .search_cve_summaries_by_cve_id_prefix_with_state_scope(
                    "CVE-2026-100",
                    CveStateScope::IncludeRejected,
                    10,
                    0,
                )
                .await
                .unwrap();
            assert_eq!(including_rejected.len(), 2);

            let default_count = db
                .count_cve_summaries_by_cve_id_prefix("CVE-2026-100")
                .await
                .unwrap();
            assert_eq!(default_count, 1);

            let including_rejected_count = db
                .count_cve_summaries_by_cve_id_prefix_with_state_scope(
                    "CVE-2026-100",
                    CveStateScope::IncludeRejected,
                )
                .await
                .unwrap();
            assert_eq!(including_rejected_count, 2);
        });
    }

    #[test]
    fn upsert_cve_models_writes_parent_and_children() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();

        runtime.block_on(async {
            let db = connect_database("sqlite::memory:").await.unwrap();
            let cve_db = CveDatabase { db: db.clone() };
            cve_db.initialize_schema().await.unwrap();
            insert_test_cwe(&db).await;

            let models = CveActiveModels::from(parse_json_with_raw(CVE_JSON).unwrap());
            let inserted = cve_db.upsert_cve_models(vec![models]).await.unwrap();
            assert_eq!(inserted, 1);

            let found = cve_db
                .find_cve_by_id("CVE-2024-0001")
                .await
                .unwrap()
                .unwrap();
            assert_eq!(found.cve_id, "CVE-2024-0001");

            let by_cwe = cve_db
                .search_cves_by_cwe(&["CWE-79".to_owned()], 10, 0)
                .await
                .unwrap();
            assert_eq!(by_cwe.len(), 1);

            let by_product = cve_db
                .search_cves_by_vendor_product(Some("Example Vendor"), Some("Product"), 10, 0)
                .await
                .unwrap();
            assert_eq!(by_product.len(), 1);

            let by_product_summary = cve_db
                .search_cve_summaries_by_vendor_product_with_state_scope(
                    Some("Example Vendor"),
                    Some("Product"),
                    CveStateScope::PublishedOnly,
                    10,
                    0,
                )
                .await
                .unwrap();
            assert_eq!(by_product_summary.len(), 1);

            let by_product_count = cve_db
                .count_cve_summaries_by_vendor_product_with_state_scope(
                    Some("Example Vendor"),
                    Some("Product"),
                    CveStateScope::PublishedOnly,
                )
                .await
                .unwrap();
            assert_eq!(by_product_count, 1);

            let by_exact_product = cve_db
                .search_cve_summaries_by_vendor_product_exact_with_state_scope(
                    None,
                    None,
                    None,
                    Some("Example Product"),
                    CveStateScope::PublishedOnly,
                    10,
                    0,
                )
                .await
                .unwrap();
            assert_eq!(by_exact_product.len(), 1);

            let by_partial_as_exact = cve_db
                .search_cve_summaries_by_vendor_product_exact_with_state_scope(
                    None,
                    None,
                    None,
                    Some("Product"),
                    CveStateScope::PublishedOnly,
                    10,
                    0,
                )
                .await
                .unwrap();
            assert!(by_partial_as_exact.is_empty());

            cve_db
                .replace_cve_children(
                    "CVE-2024-0001",
                    Vec::new(),
                    Vec::new(),
                    vec![cve_cwe::ActiveModel {
                        cve_db_id: Set(0),
                        cwe_id: Set(79),
                    }],
                )
                .await
                .unwrap();

            let cwe = cwe::Entity::find_by_id(79).one(&db).await.unwrap().unwrap();
            assert_eq!(cwe.description.as_deref(), Some("Cross-site Scripting"));
        });
    }

    async fn insert_test_cwe(db: &DatabaseConnection) {
        cwe::Entity::insert(cwe::ActiveModel {
            id: Set(79),
            description: Set(Some("Cross-site Scripting".to_owned())),
            status: Set(Some("Stable".to_owned())),
            parent_id: Set(None),
        })
        .exec(db)
        .await
        .unwrap();
    }

    #[test]
    fn mark_json_file_read_upserts_processed_file() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();

        runtime.block_on(async {
            let db = CveDatabase::connect("sqlite::memory:").await.unwrap();
            db.initialize_schema().await.unwrap();

            db.mark_json_file_read("cves/CVE-2024-0001.json", "0123456789abcdef")
                .await
                .unwrap();
            db.mark_json_file_read("cves/CVE-2024-0001.json", "0123456789abcdef")
                .await
                .unwrap();

            let found = db
                .find_read_json_file("cves/CVE-2024-0001.json", "0123456789abcdef")
                .await
                .unwrap()
                .unwrap();
            assert_eq!(found.filename, "cves/CVE-2024-0001.json");
            assert_eq!(found.md5hash, "0123456789abcdef");
            assert!(!found.created_at.is_empty());
            assert!(!found.updated_at.is_empty());

            let count = read_json_file::Entity::find()
                .count(db.connection())
                .await
                .unwrap();
            assert_eq!(count, 1);
        });
    }

    #[test]
    fn mark_json_files_read_splits_large_batches_under_sqlite_variable_limit() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();

        runtime.block_on(async {
            let db = CveDatabase::connect("sqlite::memory:").await.unwrap();
            db.initialize_schema().await.unwrap();

            let files = (0..20_000)
                .map(|index| ReadJsonFileRecord {
                    filename: format!("cves/CVE-2024-{index:04}.json"),
                    md5hash: format!("{index:032x}"),
                })
                .collect::<Vec<_>>();

            let marked = db.mark_json_files_read(files).await.unwrap();
            assert_eq!(marked, 20_000);

            let count = read_json_file::Entity::find()
                .count(db.connection())
                .await
                .unwrap();
            assert_eq!(count, 20_000);
        });
    }
}
