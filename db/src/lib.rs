pub mod entity;
pub mod migration;

use entity::{cve, cve_affected, cve_cvss, cve_cwe};
use migration::Migrator;
use std::collections::HashSet;

use qanvuli_models::{
    CveStatusData, RawCveRecord, cna_affected_raw_values, cna_cvss_raw_values, cna_cwe_raw_values,
    cve::base::cve_metadata::CveState, cve::published::cna_description::CnaDescription,
};
use sea_orm::sea_query::OnConflict;
use sea_orm::{
    ColumnTrait, ConnectionTrait, Database, DatabaseConnection, DbBackend, DbErr, EntityTrait,
    QueryFilter, QueryOrder, QuerySelect, Set, Statement, TransactionTrait,
};
use sea_orm_migration::prelude::MigratorTrait;
use serde_json::Value;

pub struct CveActiveModels {
    pub cve_id: String,
    pub cve: cve::ActiveModel,
    pub cvss_rows: Vec<cve_cvss::ActiveModel>,
    pub affected_rows: Vec<cve_affected::ActiveModel>,
    pub cwe_rows: Vec<cve_cwe::ActiveModel>,
}

impl From<RawCveRecord<CveStatusData>> for CveActiveModels {
    fn from(value: RawCveRecord<CveStatusData>) -> Self {
        let raw_json = value.raw_json().clone();
        let cve_id = raw_json
            .pointer("/cveMetadata/cveId")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();

        Self {
            cve_id: cve_id.clone(),
            cve: cve::ActiveModel::from(value),
            cvss_rows: cvss_active_models(&cve_id, &raw_json),
            affected_rows: affected_active_models(&cve_id, &raw_json),
            cwe_rows: cwe_active_models(&cve_id, &raw_json),
        }
    }
}

impl From<RawCveRecord<CveStatusData>> for cve::ActiveModel {
    fn from(value: RawCveRecord<CveStatusData>) -> Self {
        let (content, raw_json) = value.into_parts();

        match content {
            CveStatusData::Published(cve) => {
                let metadata = cve.cve_metadata;
                let cna = cve.containers.cna;
                let cve_id = metadata.cve_id;
                let title = cna.title.unwrap_or_else(|| cve_id.clone());

                Self {
                    cve_id: Set(cve_id),
                    state: Set(cve_state_to_string(&metadata.state)),
                    published_at: Set(metadata
                        .date_published
                        .map_or_else(String::new, |d| d.to_rfc3339())),
                    updated_at: Set(metadata
                        .date_updated
                        .map_or_else(String::new, |d| d.to_rfc3339())),
                    serial: Set(metadata.serial.unwrap_or_default() as i32),
                    title: Set(title),
                    description_en: Set(description_en(&cna.descriptions)),
                    raw_json: Set(raw_json),
                }
            }
            CveStatusData::Rejected(cve) => {
                let metadata = cve.cve_metadata;
                let cna = cve.containers.cna;
                let cve_id = metadata.cve_id;

                Self {
                    cve_id: Set(cve_id.clone()),
                    state: Set(cve_state_to_string(&metadata.state)),
                    published_at: Set(metadata
                        .date_published
                        .map_or_else(String::new, |d| d.to_rfc3339())),
                    updated_at: Set(metadata
                        .date_updated
                        .map_or_else(String::new, |d| d.to_rfc3339())),
                    serial: Set(metadata.serial.unwrap_or_default() as i32),
                    title: Set(cve_id),
                    description_en: Set(description_en(&cna.rejected_reasons)),
                    raw_json: Set(raw_json),
                }
            }
        }
    }
}

fn cvss_active_models(cve_id: &str, raw_json: &Value) -> Vec<cve_cvss::ActiveModel> {
    cna_cvss_raw_values(raw_json)
        .into_iter()
        .map(|cvss| cve_cvss::ActiveModel {
            cve_id: Set(cve_id.to_owned()),
            version: Set(json_string(&cvss.raw_json, "version").unwrap_or(cvss.cvss_key)),
            base_score: Set(cvss.raw_json.get("baseScore").and_then(Value::as_f64)),
            base_severity: Set(json_string(&cvss.raw_json, "baseSeverity")),
            vector_string: Set(json_string(&cvss.raw_json, "vectorString")),
            source: Set(Some("cna".to_owned())),
            raw_json: Set(cvss.raw_json),
            ..Default::default()
        })
        .collect()
}

fn affected_active_models(cve_id: &str, raw_json: &Value) -> Vec<cve_affected::ActiveModel> {
    cna_affected_raw_values(raw_json)
        .into_iter()
        .map(|affected| cve_affected::ActiveModel {
            cve_id: Set(cve_id.to_owned()),
            vendor: Set(json_string(&affected, "vendor")),
            product: Set(json_string_or_json(&affected, "product")),
            package_name: Set(json_string(&affected, "packageName")),
            collection_url: Set(json_string(&affected, "collectionURL")),
            default_status: Set(json_string(&affected, "defaultStatus")),
            raw_json: Set(affected),
            ..Default::default()
        })
        .collect()
}

fn cwe_active_models(cve_id: &str, raw_json: &Value) -> Vec<cve_cwe::ActiveModel> {
    let mut seen = HashSet::new();

    cna_cwe_raw_values(raw_json)
        .into_iter()
        .filter_map(|cwe| {
            let cwe_id = json_string(&cwe, "cweId")?;
            if !seen.insert(cwe_id.clone()) {
                return None;
            }

            Some(cve_cwe::ActiveModel {
                cve_id: Set(cve_id.to_owned()),
                cwe_id: Set(cwe_id),
                description: Set(json_string(&cwe, "description")),
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

fn json_string_or_json(value: &Value, key: &str) -> Option<String> {
    value.get(key).map(|value| {
        value
            .as_str()
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| value.to_string())
    })
}

fn cve_state_to_string(state: &CveState) -> String {
    match state {
        CveState::Reserved => "RESERVED",
        CveState::Published => "PUBLISHED",
        CveState::Rejected => "REJECTED",
    }
    .to_owned()
}

fn description_en(descriptions: &[CnaDescription]) -> Option<String> {
    descriptions
        .iter()
        .find(|description| description.lang == "en")
        .or_else(|| descriptions.first())
        .map(|description| description.value.clone())
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
    Ok(db)
}

pub async fn initialize_schema(db: &DatabaseConnection) -> Result<(), DbErr> {
    Migrator::up(db, None).await
}

pub async fn rebuild_schema(db: &DatabaseConnection) -> Result<(), DbErr> {
    Migrator::down(db, None).await?;
    initialize_schema(db).await
}

pub async fn upsert_cve(db: &DatabaseConnection, model: cve::ActiveModel) -> Result<(), DbErr> {
    upsert_cve_on(db, model).await
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

pub async fn upsert_cve_models(
    db: &DatabaseConnection,
    models: Vec<CveActiveModels>,
) -> Result<usize, DbErr> {
    if models.is_empty() {
        return Ok(0);
    }

    let txn = db.begin().await?;
    let mut cve_ids = Vec::with_capacity(models.len());
    let mut cve_rows = Vec::with_capacity(models.len());
    let mut cvss_rows = Vec::new();
    let mut affected_rows = Vec::new();
    let mut cwe_rows = Vec::new();

    for models in models {
        cve_ids.push(models.cve_id.clone());
        cve_rows.push(models.cve);
        cvss_rows.extend(models.cvss_rows);
        affected_rows.extend(models.affected_rows);
        cwe_rows.extend(models.cwe_rows);
    }

    let inserted = cve_rows.len();

    for chunk in cve_rows.chunks(50) {
        cve::Entity::insert_many(chunk.iter().cloned())
            .on_conflict(cve_upsert_conflict())
            .exec(&txn)
            .await?;
    }

    cve_cvss::Entity::delete_many()
        .filter(cve_cvss::Column::CveId.is_in(cve_ids.iter().cloned()))
        .exec(&txn)
        .await?;
    cve_affected::Entity::delete_many()
        .filter(cve_affected::Column::CveId.is_in(cve_ids.iter().cloned()))
        .exec(&txn)
        .await?;
    cve_cwe::Entity::delete_many()
        .filter(cve_cwe::Column::CveId.is_in(cve_ids))
        .exec(&txn)
        .await?;

    for chunk in cvss_rows.chunks(100) {
        cve_cvss::Entity::insert_many(chunk.iter().cloned())
            .exec(&txn)
            .await?;
    }
    for chunk in affected_rows.chunks(100) {
        cve_affected::Entity::insert_many(chunk.iter().cloned())
            .exec(&txn)
            .await?;
    }
    for chunk in cwe_rows.chunks(300) {
        cve_cwe::Entity::insert_many(chunk.iter().cloned())
            .exec(&txn)
            .await?;
    }

    txn.commit().await?;
    Ok(inserted)
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
            cve::Column::RawJson,
        ])
        .to_owned()
}

pub async fn replace_cve_children(
    db: &DatabaseConnection,
    cve_id: &str,
    cvss_rows: Vec<cve_cvss::ActiveModel>,
    affected_rows: Vec<cve_affected::ActiveModel>,
    cwe_rows: Vec<cve_cwe::ActiveModel>,
) -> Result<(), DbErr> {
    let txn = db.begin().await?;

    cve_cvss::Entity::delete_many()
        .filter(cve_cvss::Column::CveId.eq(cve_id))
        .exec(&txn)
        .await?;
    cve_affected::Entity::delete_many()
        .filter(cve_affected::Column::CveId.eq(cve_id))
        .exec(&txn)
        .await?;
    cve_cwe::Entity::delete_many()
        .filter(cve_cwe::Column::CveId.eq(cve_id))
        .exec(&txn)
        .await?;

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

    txn.commit().await
}

pub async fn get_all(db: &DatabaseConnection) -> Result<Vec<cve::Model>, DbErr> {
    cve::Entity::find()
        .order_by_desc(cve::Column::PublishedAt)
        .order_by_asc(cve::Column::CveId)
        .all(db)
        .await
}

pub async fn find_cve_by_id(
    db: &DatabaseConnection,
    cve_id: &str,
) -> Result<Option<cve::Model>, DbErr> {
    cve::Entity::find_by_id(cve_id.to_owned()).one(db).await
}

pub async fn search_cves_by_cwe(
    db: &DatabaseConnection,
    cwe_ids: &[String],
    limit: u64,
    offset: u64,
) -> Result<Vec<cve::Model>, DbErr> {
    if cwe_ids.is_empty() {
        return Ok(Vec::new());
    }

    cve::Entity::find()
        .inner_join(cve_cwe::Entity)
        .filter(cve_cwe::Column::CweId.is_in(cwe_ids.iter().cloned()))
        .distinct()
        .order_by_desc(cve::Column::PublishedAt)
        .order_by_asc(cve::Column::CveId)
        .limit(limit)
        .offset(offset)
        .all(db)
        .await
}

pub async fn search_cves_by_vendor_product(
    db: &DatabaseConnection,
    vendor: Option<&str>,
    product: Option<&str>,
    limit: u64,
    offset: u64,
) -> Result<Vec<cve::Model>, DbErr> {
    let mut query = cve::Entity::find().inner_join(cve_affected::Entity);

    if let Some(vendor) = vendor {
        query = query.filter(cve_affected::Column::Vendor.like(like_pattern(vendor)));
    }
    if let Some(product) = product {
        query = query.filter(cve_affected::Column::Product.like(like_pattern(product)));
    }

    query
        .distinct()
        .order_by_desc(cve::Column::PublishedAt)
        .order_by_asc(cve::Column::CveId)
        .limit(limit)
        .offset(offset)
        .all(db)
        .await
}

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
        assert_eq!(active_model.state.unwrap(), "PUBLISHED");
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
        assert_eq!(active_model.raw_json.unwrap(), expected_raw_json);
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
        assert_eq!(cvss.cve_id.unwrap(), "CVE-2024-0001");
        assert_eq!(cvss.version.unwrap(), "3.1");
        assert_eq!(cvss.base_score.unwrap(), Some(9.8));
        assert_eq!(cvss.base_severity.unwrap().as_deref(), Some("CRITICAL"));
        assert_eq!(
            cvss.vector_string.unwrap().as_deref(),
            Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        );
        assert_eq!(cvss.raw_json.unwrap()["version"], "3.1");

        let affected = models.affected_rows.into_iter().next().unwrap();
        assert_eq!(affected.cve_id.unwrap(), "CVE-2024-0001");
        assert_eq!(affected.vendor.unwrap().as_deref(), Some("Example Vendor"));
        assert_eq!(
            affected.product.unwrap().as_deref(),
            Some("Example Product")
        );
        assert_eq!(
            affected.default_status.unwrap().as_deref(),
            Some("affected")
        );
        assert_eq!(affected.raw_json.unwrap()["vendor"], "Example Vendor");

        let cwe = models.cwe_rows.into_iter().next().unwrap();
        assert_eq!(cwe.cve_id.unwrap(), "CVE-2024-0001");
        assert_eq!(cwe.cwe_id.unwrap(), "CWE-79");
        assert_eq!(
            cwe.description.unwrap().as_deref(),
            Some("Cross-site Scripting")
        );
    }

    #[test]
    fn in_memory_sqlite_writes_and_reads_simple_cve() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();

        runtime.block_on(async {
            let db = connect_database("sqlite::memory:").await.unwrap();
            initialize_schema(&db).await.unwrap();

            upsert_cve(
                &db,
                cve::ActiveModel {
                    cve_id: Set("CVE-2026-0001".to_owned()),
                    state: Set("PUBLISHED".to_owned()),
                    published_at: Set("2026-01-01T00:00:00Z".to_owned()),
                    updated_at: Set("2026-01-02T00:00:00Z".to_owned()),
                    serial: Set(1),
                    title: Set("example".to_owned()),
                    description_en: Set(Some("description".to_owned())),
                    raw_json: Set(json!({"id": "CVE-2026-0001"})),
                },
            )
            .await
            .unwrap();

            replace_cve_children(
                &db,
                "CVE-2026-0001",
                vec![cve_cvss::ActiveModel {
                    cve_id: Set("CVE-2026-0001".to_owned()),
                    version: Set("3.1".to_owned()),
                    base_score: Set(Some(9.8)),
                    base_severity: Set(Some("CRITICAL".to_owned())),
                    vector_string: Set(Some("CVSS:3.1/...".to_owned())),
                    source: Set(Some("cna".to_owned())),
                    raw_json: Set(json!({"version": "3.1"})),
                    ..Default::default()
                }],
                vec![cve_affected::ActiveModel {
                    cve_id: Set("CVE-2026-0001".to_owned()),
                    vendor: Set(Some("Example Vendor".to_owned())),
                    product: Set(Some("Example Product".to_owned())),
                    raw_json: Set(json!({"vendor": "Example Vendor"})),
                    ..Default::default()
                }],
                vec![cve_cwe::ActiveModel {
                    cve_id: Set("CVE-2026-0001".to_owned()),
                    cwe_id: Set("CWE-79".to_owned()),
                    description: Set(Some("Cross-site Scripting".to_owned())),
                }],
            )
            .await
            .unwrap();

            let found = find_cve_by_id(&db, "CVE-2026-0001").await.unwrap().unwrap();
            assert_eq!(found.cve_id, "CVE-2026-0001");
            assert_eq!(found.state, "PUBLISHED");
            assert_eq!(found.published_at, "2026-01-01T00:00:00Z");
            assert_eq!(found.updated_at, "2026-01-02T00:00:00Z");
            assert_eq!(found.serial, 1);
            assert_eq!(found.title, "example");
            assert_eq!(found.description_en.as_deref(), Some("description"));
            assert_eq!(found.raw_json, json!({"id": "CVE-2026-0001"}));

            let by_cwe = search_cves_by_cwe(&db, &["CWE-79".to_owned()], 10, 0)
                .await
                .unwrap();
            assert_eq!(by_cwe.len(), 1);

            let by_product =
                search_cves_by_vendor_product(&db, Some("Vendor"), Some("Product"), 10, 0)
                    .await
                    .unwrap();
            assert_eq!(by_product.len(), 1);

            let affected_count = cve_affected::Entity::find().count(&db).await.unwrap();
            assert_eq!(affected_count, 1);
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
            initialize_schema(&db).await.unwrap();

            let models = CveActiveModels::from(parse_json_with_raw(CVE_JSON).unwrap());
            let inserted = upsert_cve_models(&db, vec![models]).await.unwrap();
            assert_eq!(inserted, 1);

            let found = find_cve_by_id(&db, "CVE-2024-0001").await.unwrap().unwrap();
            assert_eq!(found.cve_id, "CVE-2024-0001");

            let by_cwe = search_cves_by_cwe(&db, &["CWE-79".to_owned()], 10, 0)
                .await
                .unwrap();
            assert_eq!(by_cwe.len(), 1);

            let by_product =
                search_cves_by_vendor_product(&db, Some("Example Vendor"), Some("Product"), 10, 0)
                    .await
                    .unwrap();
            assert_eq!(by_product.len(), 1);
        });
    }
}
