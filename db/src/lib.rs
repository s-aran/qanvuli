pub mod entity;
pub mod migration;

use chrono::Utc;
use entity::{cve, cve_affected, cve_cvss, cve_cwe, cwe, read_json_file};
use md5::{Digest, Md5};
use migration::Migrator;
use std::collections::HashSet;

use qanvuli_models::{
    CveStatusData, RawCveRecord, cna_affected_raw_values, cna_cvss_raw_values, cna_cwe_raw_values,
    cve::base::cve_metadata::CveState, cve::published::cna_description::CnaDescription,
};
use sea_orm::sea_query::OnConflict;
use sea_orm::{
    ColumnTrait, Condition, ConnectionTrait, Database, DatabaseConnection, DatabaseTransaction,
    DbBackend, DbErr, EntityTrait, FromQueryResult, PaginatorTrait, QueryFilter, QueryOrder,
    QuerySelect, Set, Statement, TransactionTrait, Value as SeaValue,
};
use sea_orm_migration::prelude::MigratorTrait;
use serde::Serialize;
use serde_json::Value;

const CVE_CHUNK_SIZE: usize = 2000;
const CVSS_CHUNK_SIZE: usize = CVE_CHUNK_SIZE * 2;
const AFFECTED_CHUNK_SIZE: usize = CVE_CHUNK_SIZE * 2;
const CWE_CHUNK_SIZE: usize = CVE_CHUNK_SIZE * 6;
const CWE_MASTER_CHUNK_SIZE: usize = CVE_CHUNK_SIZE * 2;
const READ_JSON_FILE_CHUNK_SIZE: usize = 1000;

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
    pub state: String,
    pub published_at: String,
    pub updated_at: String,
    pub title: String,
    pub description_en: Option<String>,
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

#[derive(Clone, Debug, FromQueryResult, Serialize)]
pub struct CveCvssDetail {
    pub version: String,
    pub base_score: Option<f64>,
    pub base_severity: Option<String>,
    pub vector_string: Option<String>,
    pub source: Option<String>,
}

#[derive(Clone, Debug, FromQueryResult, Serialize)]
pub struct CveAffectedDetail {
    pub vendor: Option<String>,
    pub product: Option<String>,
    pub package_name: Option<String>,
    pub collection_url: Option<String>,
    pub default_status: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct CveAdvancedSearch {
    pub published_from: Option<String>,
    pub published_to: Option<String>,
    pub cwe: Option<String>,
    pub product: Option<String>,
    pub vendor: Option<String>,
    pub sort_order: CveSummarySortOrder,
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
            cwe_master_rows: cwe_master_active_models(&raw_json),
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
            let cwe_id = cwe_number(json_string(&cwe, "cweId")?.as_str())?;
            if !seen.insert(cwe_id) {
                return None;
            }

            Some(cve_cwe::ActiveModel {
                cve_id: Set(cve_id.to_owned()),
                cwe_id: Set(cwe_id),
            })
        })
        .collect()
}

fn cwe_master_active_models(raw_json: &Value) -> Vec<cwe::ActiveModel> {
    let mut seen = HashSet::new();

    cna_cwe_raw_values(raw_json)
        .into_iter()
        .filter_map(|cwe| {
            let cwe_id = cwe_number(json_string(&cwe, "cweId")?.as_str())?;
            if !seen.insert(cwe_id) {
                return None;
            }

            Some(cwe::ActiveModel {
                id: Set(cwe_id),
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

fn md5_hex(bytes: &[u8]) -> String {
    let mut hasher = Md5::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn json_string_or_json(value: &Value, key: &str) -> Option<String> {
    value.get(key).map(|value| {
        value
            .as_str()
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| value.to_string())
    })
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

#[derive(Clone)]
pub struct CveDatabase {
    db: DatabaseConnection,
}

impl CveDatabase {
    pub async fn connect(database_url: &str) -> Result<Self, DbErr> {
        Ok(Self {
            db: connect_database(database_url).await?,
        })
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

    pub async fn replace_all_cve_models(
        &self,
        models: Vec<CveActiveModels>,
    ) -> Result<usize, DbErr> {
        let txn = self.db.begin().await?;

        clear_cve_tables_on(&txn).await?;
        let inserted = insert_cve_models_on(&txn, models).await?;

        txn.commit().await?;
        Ok(inserted)
    }

    pub async fn clear_cve_tables(&self) -> Result<(), DbErr> {
        let txn = self.db.begin().await?;
        clear_cve_tables_on(&txn).await?;
        txn.commit().await
    }

    pub async fn insert_cve_models(&self, models: Vec<CveActiveModels>) -> Result<usize, DbErr> {
        if models.is_empty() {
            return Ok(0);
        }

        let txn = self.db.begin().await?;
        let inserted = insert_cve_models_on(&txn, models).await?;
        txn.commit().await?;
        Ok(inserted)
    }

    pub async fn replace_cve_children(
        &self,
        cve_id: &str,
        cvss_rows: Vec<cve_cvss::ActiveModel>,
        affected_rows: Vec<cve_affected::ActiveModel>,
        cwe_rows: Vec<cve_cwe::ActiveModel>,
    ) -> Result<(), DbErr> {
        let txn = self.db.begin().await?;

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

        let cwe_master_rows = cwe_rows
            .iter()
            .map(|row| cwe::ActiveModel {
                id: row.cwe_id.clone(),
                description: Set(None),
            })
            .collect::<Vec<_>>();

        if !cvss_rows.is_empty() {
            cve_cvss::Entity::insert_many(cvss_rows).exec(&txn).await?;
        }
        if !affected_rows.is_empty() {
            cve_affected::Entity::insert_many(affected_rows)
                .exec(&txn)
                .await?;
        }
        if !cwe_master_rows.is_empty() {
            upsert_cwe_rows(&txn, cwe_master_rows).await?;
        }
        if !cwe_rows.is_empty() {
            cve_cwe::Entity::insert_many(cwe_rows).exec(&txn).await?;
        }
        upsert_cve_search_fts_rows(&txn, &[cve_id.to_owned()]).await?;

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
        cve::Entity::find_by_id(cve_id.to_owned())
            .one(&self.db)
            .await
    }

    pub async fn find_cve_detail(&self, cve_id: &str) -> Result<CveDetail, DbErr> {
        let cwes = cve_cwe::Entity::find()
            .select_only()
            .column_as(cve_cwe::Column::CweId, "id")
            .column_as(cwe::Column::Description, "description")
            .inner_join(cwe::Entity)
            .filter(cve_cwe::Column::CveId.eq(cve_id))
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
            .filter(cve_cvss::Column::CveId.eq(cve_id))
            .order_by_desc(cve_cvss::Column::BaseScore)
            .order_by_asc(cve_cvss::Column::Version)
            .into_model::<CveCvssDetail>()
            .all(&self.db)
            .await?;

        let affected = cve_affected::Entity::find()
            .select_only()
            .columns([
                cve_affected::Column::Vendor,
                cve_affected::Column::Product,
                cve_affected::Column::PackageName,
                cve_affected::Column::CollectionUrl,
                cve_affected::Column::DefaultStatus,
            ])
            .filter(cve_affected::Column::CveId.eq(cve_id))
            .order_by_asc(cve_affected::Column::Vendor)
            .order_by_asc(cve_affected::Column::Product)
            .into_model::<CveAffectedDetail>()
            .all(&self.db)
            .await?;

        Ok(CveDetail {
            cwes,
            cvss,
            affected,
        })
    }

    pub async fn search_cves_by_cwe(
        &self,
        cwe_ids: &[String],
        limit: u64,
        offset: u64,
    ) -> Result<Vec<cve::Model>, DbErr> {
        let cwe_ids = cwe_numbers(cwe_ids);
        if cwe_ids.is_empty() {
            return Ok(Vec::new());
        }

        if matches!(self.db.get_database_backend(), DbBackend::Sqlite) {
            self.ensure_cwe_search_index().await?;
            return cve::Model::find_by_statement(Statement::from_string(
                DbBackend::Sqlite,
                cwe_model_sql(&cwe_ids, limit, offset),
            ))
            .all(&self.db)
            .await;
        }

        cve::Entity::find()
            .inner_join(cve_cwe::Entity)
            .filter(cve_cwe::Column::CweId.is_in(cwe_ids))
            .distinct()
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
        let cwe_ids = cwe_numbers(cwe_ids);
        if cwe_ids.is_empty() {
            return Ok(Vec::new());
        }

        if matches!(self.db.get_database_backend(), DbBackend::Sqlite) {
            self.ensure_cwe_search_index().await?;
            return CveSummary::find_by_statement(Statement::from_string(
                DbBackend::Sqlite,
                cwe_summary_sql(&cwe_ids, limit, offset),
            ))
            .all(&self.db)
            .await;
        }

        cve::Entity::find()
            .select_only()
            .columns(summary_columns())
            .inner_join(cve_cwe::Entity)
            .filter(cve_cwe::Column::CweId.is_in(cwe_ids))
            .distinct()
            .order_by_desc(cve::Column::PublishedAt)
            .order_by_asc(cve::Column::CveId)
            .limit(limit)
            .offset(offset)
            .into_model::<CveSummary>()
            .all(&self.db)
            .await
    }

    pub async fn count_cve_summaries_by_cwe(&self, cwe_ids: &[String]) -> Result<u64, DbErr> {
        let cwe_ids = cwe_numbers(cwe_ids);
        if cwe_ids.is_empty() {
            return Ok(0);
        }

        if matches!(self.db.get_database_backend(), DbBackend::Sqlite) {
            self.ensure_cwe_search_index().await?;
            return self
                .count_by_sql(format!(
                    "SELECT COUNT(DISTINCT cve_id) AS count FROM cve_cwe INDEXED BY idx_cve_cwe_cwe_id_cve_id WHERE cwe_id IN ({})",
                    cwe_id_list(&cwe_ids)
                ))
                .await;
        }

        cve::Entity::find()
            .inner_join(cve_cwe::Entity)
            .filter(cve_cwe::Column::CweId.is_in(cwe_ids))
            .distinct()
            .count(&self.db)
            .await
    }

    async fn ensure_cwe_search_index(&self) -> Result<(), DbErr> {
        if matches!(self.db.get_database_backend(), DbBackend::Sqlite) {
            self.db
                .execute_unprepared(
                    "CREATE INDEX IF NOT EXISTS idx_cve_cwe_cwe_id_cve_id ON cve_cwe (cwe_id, cve_id)",
                )
                .await?;
        }
        Ok(())
    }

    async fn ensure_cve_search_fts(&self) -> Result<(), DbErr> {
        if !matches!(self.db.get_database_backend(), DbBackend::Sqlite) {
            return Ok(());
        }

        create_cve_search_fts(&self.db).await?;
        let has_rows = self
            .db
            .query_one(Statement::from_string(
                DbBackend::Sqlite,
                "SELECT 1 FROM cve_search_fts LIMIT 1".to_owned(),
            ))
            .await?
            .is_some();
        if !has_rows {
            rebuild_cve_search_fts(&self.db).await?;
        }

        Ok(())
    }

    pub async fn search_cves_by_vendor_product(
        &self,
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
        let mut query = cve::Entity::find()
            .select_only()
            .columns(summary_columns())
            .inner_join(cve_affected::Entity);

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
            .into_model::<CveSummary>()
            .all(&self.db)
            .await
    }

    pub async fn count_cve_summaries_by_vendor_product(
        &self,
        vendor: Option<&str>,
        product: Option<&str>,
    ) -> Result<u64, DbErr> {
        let mut query = cve::Entity::find().inner_join(cve_affected::Entity);

        if let Some(vendor) = vendor {
            query = query.filter(cve_affected::Column::Vendor.like(like_pattern(vendor)));
        }
        if let Some(product) = product {
            query = query.filter(cve_affected::Column::Product.like(like_pattern(product)));
        }

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

        if let Some(vendor) = vendor {
            query = query.filter(cve_affected::Column::Vendor.like(like_pattern(vendor)));
        }
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
        let pattern = like_pattern(query);

        cve::Entity::find()
            .filter(
                cve::Column::CveId
                    .like(pattern.clone())
                    .or(cve::Column::Title.like(pattern.clone()))
                    .or(cve::Column::DescriptionEn.like(pattern)),
            )
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
        let query = query.trim();
        if is_cve_id_prefix_query(query) {
            return self
                .search_cve_summaries_by_cve_id_prefix(query, limit, offset)
                .await;
        }
        if is_cwe_id_query(query) {
            let Some(cwe_id) = cwe_number(query) else {
                return Ok(Vec::new());
            };
            return self
                .search_cve_summaries_by_cwe(&[cwe_id.to_string()], limit, offset)
                .await;
        }
        if is_dateish_query(query) {
            return self
                .search_cve_summaries_by_date_prefix(query, limit, offset)
                .await;
        }
        if matches!(self.db.get_database_backend(), DbBackend::Sqlite)
            && let Some(fts_query) = fts_query(query)
        {
            return self
                .search_cve_summaries_by_fts_text(&fts_query, limit, offset)
                .await;
        }

        let pattern = like_pattern(query);

        cve::Entity::find()
            .select_only()
            .columns(summary_columns())
            .filter(
                cve::Column::CveId
                    .like(pattern.clone())
                    .or(cve::Column::Title.like(pattern.clone()))
                    .or(cve::Column::DescriptionEn.like(pattern)),
            )
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
        let prefix = prefix.trim().to_ascii_uppercase();
        let Some(upper_bound) = ascii_prefix_upper_bound(&prefix) else {
            return Ok(Vec::new());
        };

        if !matches!(self.db.get_database_backend(), DbBackend::Sqlite) {
            return cve::Entity::find()
                .select_only()
                .columns(summary_columns())
                .filter(
                    cve::Column::CveId
                        .gte(prefix)
                        .and(cve::Column::CveId.lt(upper_bound)),
                )
                .order_by_asc(cve::Column::CveId)
                .limit(limit)
                .offset(offset)
                .into_model::<CveSummary>()
                .all(&self.db)
                .await;
        }

        CveSummary::find_by_statement(Statement::from_sql_and_values(
            self.db.get_database_backend(),
            cve_id_prefix_summary_sql(),
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
        let prefix = prefix.trim().to_ascii_uppercase();
        let Some(upper_bound) = ascii_prefix_upper_bound(&prefix) else {
            return Ok(0);
        };

        if !matches!(self.db.get_database_backend(), DbBackend::Sqlite) {
            return cve::Entity::find()
                .filter(
                    cve::Column::CveId
                        .gte(prefix)
                        .and(cve::Column::CveId.lt(upper_bound)),
                )
                .count(&self.db)
                .await;
        }

        self.count_by_statement(
            "SELECT COUNT(*) AS count FROM cve WHERE cve_id >= ? AND cve_id < ?",
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
            return cve::Entity::find()
                .select_only()
                .columns(summary_columns())
                .filter(condition)
                .distinct()
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
            date_prefix_summary_sql(),
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
            return cve::Entity::find()
                .filter(condition)
                .distinct()
                .count(&self.db)
                .await;
        }

        self.count_by_statement(
            r#"
            SELECT COUNT(DISTINCT cve_id) AS count
            FROM (
                SELECT cve_id FROM cve INDEXED BY idx_cve_published_at
                WHERE published_at >= ? AND published_at < ?
                UNION ALL
                SELECT cve_id FROM cve INDEXED BY idx_cve_updated_at
                WHERE updated_at >= ? AND updated_at < ?
            )
            "#,
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
        let query = query.trim();
        if query.is_empty() {
            return self
                .search_cve_summaries_by_date(None, None, limit, offset)
                .await;
        }

        let candidate_limit = limit.saturating_add(offset).max(limit);
        let cwe_id = cwe_number(query);
        let mut cves = Vec::new();

        if is_cve_id_prefix_query(query) {
            append_unique_summaries(
                &mut cves,
                self.search_cve_summaries_by_cve_id_prefix(query, candidate_limit, 0)
                    .await?,
            );
        } else if is_dateish_query(query) {
            append_unique_summaries(
                &mut cves,
                self.search_cve_summaries_by_date_prefix(query, candidate_limit, 0)
                    .await?,
            );
        } else if is_cwe_id_query(query) {
            let Some(cwe_id) = cwe_id else {
                return Ok(Vec::new());
            };
            append_unique_summaries(
                &mut cves,
                self.search_cve_summaries_by_cwe(&[cwe_id.to_string()], candidate_limit, 0)
                    .await?,
            );
        } else if let Some(cwe_id) = cwe_id {
            append_unique_summaries(
                &mut cves,
                self.search_cve_summaries_by_cwe(&[cwe_id.to_string()], candidate_limit, 0)
                    .await?,
            );
        } else if matches!(self.db.get_database_backend(), DbBackend::Sqlite)
            && let Some(fts_query) = fts_query(query)
        {
            return self
                .search_cve_summaries_by_fts_text(&fts_query, limit, offset)
                .await;
        } else {
            append_unique_summaries(
                &mut cves,
                self.search_cve_summaries_by_cve_free_text(query, candidate_limit, 0)
                    .await?,
            );
        }

        if cwe_id.is_none()
            && !matches!(self.db.get_database_backend(), DbBackend::Sqlite)
            && should_search_affected_text(query)
        {
            append_unique_summaries(
                &mut cves,
                self.search_cve_summaries_by_affected_text(query, candidate_limit, 0)
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
        let query = query.trim();
        if query.is_empty() {
            return cve::Entity::find().count(&self.db).await;
        }

        let cwe_id = cwe_number(query);
        if is_cve_id_prefix_query(query) {
            self.count_cve_summaries_by_cve_id_prefix(query).await
        } else if is_dateish_query(query) {
            self.count_cve_summaries_by_date_prefix(query).await
        } else if is_cwe_id_query(query) {
            let Some(cwe_id) = cwe_id else {
                return Ok(0);
            };
            self.count_cve_summaries_by_cwe(&[cwe_id.to_string()]).await
        } else if let Some(cwe_id) = cwe_id {
            self.count_cve_summaries_by_cwe(&[cwe_id.to_string()]).await
        } else if matches!(self.db.get_database_backend(), DbBackend::Sqlite)
            && let Some(fts_query) = fts_query(query)
        {
            self.count_cve_summaries_by_fts_text(&fts_query).await
        } else {
            let pattern = like_pattern(query);
            cve::Entity::find()
                .filter(
                    cve::Column::CveId
                        .like(pattern.clone())
                        .or(cve::Column::Title.like(pattern.clone()))
                        .or(cve::Column::DescriptionEn.like(pattern.clone()))
                        .or(cve::Column::PublishedAt.like(pattern.clone()))
                        .or(cve::Column::UpdatedAt.like(pattern)),
                )
                .count(&self.db)
                .await
        }
    }

    pub async fn search_cve_summaries_by_fts_text(
        &self,
        query: &str,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, DbErr> {
        self.ensure_cve_search_fts().await?;

        CveSummary::find_by_statement(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            fts_summary_sql(),
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
        self.ensure_cve_search_fts().await?;
        self.count_by_statement(
            "SELECT COUNT(*) AS count FROM cve_search_fts WHERE cve_search_fts MATCH ?",
            vec![SeaValue::from(query.to_owned())],
        )
        .await
    }

    async fn search_cve_summaries_by_cve_free_text(
        &self,
        query: &str,
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

        cve::Entity::find()
            .select_only()
            .columns(summary_columns())
            .filter(condition)
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
        limit: u64,
        offset: u64,
    ) -> Result<Vec<CveSummary>, DbErr> {
        let pattern = like_pattern(query);
        let condition = Condition::any()
            .add(cve_affected::Column::Vendor.like(pattern.clone()))
            .add(cve_affected::Column::Product.like(pattern.clone()))
            .add(cve_affected::Column::PackageName.like(pattern));

        let cves = cve::Entity::find()
            .select_only()
            .columns(summary_columns())
            .inner_join(cve_affected::Entity)
            .filter(condition)
            .distinct()
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
        let mut query = cve::Entity::find()
            .select_only()
            .columns(summary_columns())
            .inner_join(cve_cvss::Entity);

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
        let mut query = cve::Entity::find()
            .select_only()
            .columns(summary_columns())
            .inner_join(cve_affected::Entity)
            .inner_join(cve_cvss::Entity);

        if let Some(vendor) = vendor {
            query = query.filter(cve_affected::Column::Vendor.like(like_pattern(vendor)));
        }
        if let Some(product) = product {
            query = query.filter(cve_affected::Column::Product.like(like_pattern(product)));
        }
        if let Some(min_score) = min_score {
            query = query.filter(cve_cvss::Column::BaseScore.gte(min_score));
        }
        if let Some(severity) = severity {
            query = query.filter(cve_cvss::Column::BaseSeverity.eq(severity.to_ascii_uppercase()));
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
        let mut query = cve::Entity::find().select_only().columns(summary_columns());

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

        if matches!(self.db.get_database_backend(), DbBackend::Sqlite) {
            if options
                .cwe
                .as_deref()
                .is_some_and(|cwe| !cwe.trim().is_empty())
            {
                self.ensure_cwe_search_index().await?;
            }
            return CveSummary::find_by_statement(Statement::from_string(
                DbBackend::Sqlite,
                advanced_summary_sql(options, limit, offset),
            ))
            .all(&self.db)
            .await;
        }

        let mut query = cve::Entity::find().select_only().columns(summary_columns());

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
        {
            query = query.inner_join(cve_affected::Entity);
            if let Some(vendor) = option_text(options.vendor.as_deref()) {
                query = query.filter(cve_affected::Column::Vendor.like(like_pattern(vendor)));
            }
            if let Some(product) = option_text(options.product.as_deref()) {
                query = query.filter(cve_affected::Column::Product.like(like_pattern(product)));
            }
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

        if matches!(self.db.get_database_backend(), DbBackend::Sqlite) {
            if options
                .cwe
                .as_deref()
                .is_some_and(|cwe| !cwe.trim().is_empty())
            {
                self.ensure_cwe_search_index().await?;
            }
            return self.count_by_sql(advanced_count_sql(options)).await;
        }

        let mut query = cve::Entity::find();

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
        {
            query = query.inner_join(cve_affected::Entity);
            if let Some(vendor) = option_text(options.vendor.as_deref()) {
                query = query.filter(cve_affected::Column::Vendor.like(like_pattern(vendor)));
            }
            if let Some(product) = option_text(options.product.as_deref()) {
                query = query.filter(cve_affected::Column::Product.like(like_pattern(product)));
            }
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
        if files.is_empty() {
            return Ok(0);
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
                insert_read_json_file_rows(std::mem::take(&mut rows), &self.db).await?;
                rows = Vec::with_capacity(READ_JSON_FILE_CHUNK_SIZE);
            }
        }

        if !rows.is_empty() {
            insert_read_json_file_rows(rows, &self.db).await?;
        }

        Ok(count)
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
    let mut cvss_rows = Vec::new();
    let mut affected_rows = Vec::new();
    let mut cwe_master_rows = Vec::new();
    let mut cwe_rows = Vec::new();

    for models in models {
        cve_ids.push(models.cve_id.clone());
        cve_rows.push(models.cve);
        cvss_rows.extend(models.cvss_rows);
        affected_rows.extend(models.affected_rows);
        cwe_master_rows.extend(models.cwe_master_rows);
        cwe_rows.extend(models.cwe_rows);
    }

    let inserted = cve_rows.len();

    for chunk in cve_rows.chunks(CVE_CHUNK_SIZE) {
        cve::Entity::insert_many(chunk.iter().cloned())
            .on_conflict(cve_upsert_conflict())
            .exec(txn)
            .await?;
    }

    cve_cvss::Entity::delete_many()
        .filter(cve_cvss::Column::CveId.is_in(cve_ids.iter().cloned()))
        .exec(txn)
        .await?;
    cve_affected::Entity::delete_many()
        .filter(cve_affected::Column::CveId.is_in(cve_ids.iter().cloned()))
        .exec(txn)
        .await?;
    cve_cwe::Entity::delete_many()
        .filter(cve_cwe::Column::CveId.is_in(cve_ids.iter().cloned()))
        .exec(txn)
        .await?;

    for chunk in cvss_rows.chunks(CVSS_CHUNK_SIZE) {
        cve_cvss::Entity::insert_many(chunk.iter().cloned())
            .exec(txn)
            .await?;
    }
    for chunk in affected_rows.chunks(AFFECTED_CHUNK_SIZE) {
        cve_affected::Entity::insert_many(chunk.iter().cloned())
            .exec(txn)
            .await?;
    }
    for chunk in cwe_master_rows.chunks(CWE_MASTER_CHUNK_SIZE) {
        cwe::Entity::insert_many(chunk.iter().cloned())
            .on_conflict(cwe_upsert_conflict())
            .exec(txn)
            .await?;
    }
    for chunk in cwe_rows.chunks(CWE_CHUNK_SIZE) {
        cve_cwe::Entity::insert_many(chunk.iter().cloned())
            .exec(txn)
            .await?;
    }
    upsert_cve_search_fts_rows(txn, &cve_ids).await?;

    Ok(inserted)
}

async fn insert_cve_models_on(
    txn: &DatabaseTransaction,
    models: Vec<CveActiveModels>,
) -> Result<usize, DbErr> {
    let mut inserted = 0usize;
    let mut batch = Vec::with_capacity(CVE_CHUNK_SIZE);

    for models in models {
        batch.push(models);
        if batch.len() == CVE_CHUNK_SIZE {
            inserted += insert_cve_model_batch(txn, std::mem::take(&mut batch)).await?;
            batch = Vec::with_capacity(CVE_CHUNK_SIZE);
        }
    }

    if !batch.is_empty() {
        inserted += insert_cve_model_batch(txn, batch).await?;
    }

    Ok(inserted)
}

async fn insert_cve_model_batch(
    txn: &DatabaseTransaction,
    models: Vec<CveActiveModels>,
) -> Result<usize, DbErr> {
    let mut cve_rows = Vec::with_capacity(models.len());
    let mut cve_ids = Vec::with_capacity(models.len());
    let mut cvss_rows = Vec::new();
    let mut affected_rows = Vec::new();
    let mut cwe_master_rows = Vec::new();
    let mut cwe_rows = Vec::new();

    for models in models {
        cve_ids.push(models.cve_id);
        cve_rows.push(models.cve);
        cvss_rows.extend(models.cvss_rows);
        affected_rows.extend(models.affected_rows);
        cwe_master_rows.extend(models.cwe_master_rows);
        cwe_rows.extend(models.cwe_rows);
    }

    let inserted = cve_rows.len();

    insert_cve_rows(txn, cve_rows).await?;

    for chunk in cvss_rows.chunks(CVSS_CHUNK_SIZE) {
        insert_cvss_rows(txn, chunk.to_vec()).await?;
    }
    for chunk in affected_rows.chunks(AFFECTED_CHUNK_SIZE) {
        insert_affected_rows(txn, chunk.to_vec()).await?;
    }
    for chunk in cwe_master_rows.chunks(CWE_MASTER_CHUNK_SIZE) {
        upsert_cwe_rows(txn, chunk.to_vec()).await?;
    }
    for chunk in cwe_rows.chunks(CWE_CHUNK_SIZE) {
        insert_cwe_rows(txn, chunk.to_vec()).await?;
    }
    upsert_cve_search_fts_rows(txn, &cve_ids).await?;

    Ok(inserted)
}

async fn clear_cve_tables_on(txn: &DatabaseTransaction) -> Result<(), DbErr> {
    clear_cve_search_fts(txn).await?;
    cve_cwe::Entity::delete_many().exec(txn).await?;
    cwe::Entity::delete_many().exec(txn).await?;
    cve_affected::Entity::delete_many().exec(txn).await?;
    cve_cvss::Entity::delete_many().exec(txn).await?;
    cve::Entity::delete_many().exec(txn).await?;
    Ok(())
}

async fn insert_cve_rows(
    txn: &DatabaseTransaction,
    rows: Vec<cve::ActiveModel>,
) -> Result<(), DbErr> {
    cve::Entity::insert_many(rows).exec(txn).await?;
    Ok(())
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

async fn insert_cwe_rows(
    txn: &DatabaseTransaction,
    rows: Vec<cve_cwe::ActiveModel>,
) -> Result<(), DbErr> {
    cve_cwe::Entity::insert_many(rows).exec(txn).await?;
    Ok(())
}

async fn create_cve_search_fts<C>(db: &C) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    if !matches!(db.get_database_backend(), DbBackend::Sqlite) {
        return Ok(());
    }

    db.execute_unprepared(
        r#"
        CREATE VIRTUAL TABLE IF NOT EXISTS cve_search_fts USING fts5(
            cve_id UNINDEXED,
            title,
            description_en,
            affected,
            tokenize = 'unicode61'
        )
        "#,
    )
    .await?;
    Ok(())
}

async fn rebuild_cve_search_fts<C>(db: &C) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    if !matches!(db.get_database_backend(), DbBackend::Sqlite) {
        return Ok(());
    }

    create_cve_search_fts(db).await?;
    db.execute_unprepared("DELETE FROM cve_search_fts").await?;
    db.execute_unprepared(
        r#"
        INSERT INTO cve_search_fts (cve_id, title, description_en, affected)
        SELECT
            cve.cve_id,
            cve.title,
            COALESCE(cve.description_en, ''),
            COALESCE(
                GROUP_CONCAT(
                    COALESCE(cve_affected.vendor, '') || ' ' ||
                    COALESCE(cve_affected.product, '') || ' ' ||
                    COALESCE(cve_affected.package_name, ''),
                    ' '
                ),
                ''
            )
        FROM cve
        LEFT JOIN cve_affected ON cve_affected.cve_id = cve.cve_id
        GROUP BY cve.cve_id
        "#,
    )
    .await?;
    Ok(())
}

async fn clear_cve_search_fts<C>(db: &C) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    if !matches!(db.get_database_backend(), DbBackend::Sqlite) {
        return Ok(());
    }

    create_cve_search_fts(db).await?;
    db.execute_unprepared("DELETE FROM cve_search_fts").await?;
    Ok(())
}

async fn upsert_cve_search_fts_rows<C>(db: &C, cve_ids: &[String]) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    if cve_ids.is_empty() || !matches!(db.get_database_backend(), DbBackend::Sqlite) {
        return Ok(());
    }

    create_cve_search_fts(db).await?;
    let cve_ids = cve_ids
        .iter()
        .map(|cve_id| sql_string_literal(cve_id))
        .collect::<Vec<_>>()
        .join(",");
    db.execute_unprepared(&format!(
        "DELETE FROM cve_search_fts WHERE cve_id IN ({cve_ids})"
    ))
    .await?;
    db.execute_unprepared(&format!(
        r#"
        INSERT INTO cve_search_fts (cve_id, title, description_en, affected)
        SELECT
            cve.cve_id,
            cve.title,
            COALESCE(cve.description_en, ''),
            COALESCE(
                GROUP_CONCAT(
                    COALESCE(cve_affected.vendor, '') || ' ' ||
                    COALESCE(cve_affected.product, '') || ' ' ||
                    COALESCE(cve_affected.package_name, ''),
                    ' '
                ),
                ''
            )
        FROM cve
        LEFT JOIN cve_affected ON cve_affected.cve_id = cve.cve_id
        WHERE cve.cve_id IN ({cve_ids})
        GROUP BY cve.cve_id
        "#
    ))
    .await?;
    Ok(())
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

fn cwe_upsert_conflict() -> OnConflict {
    OnConflict::column(cwe::Column::Id)
        .update_column(cwe::Column::Description)
        .to_owned()
}

fn cwe_active_model_id(row: &cwe::ActiveModel) -> Option<i32> {
    match &row.id {
        sea_orm::ActiveValue::Set(id) => Some(*id),
        sea_orm::ActiveValue::Unchanged(id) => Some(*id),
        sea_orm::ActiveValue::NotSet => None,
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

async fn insert_read_json_file_rows(
    rows: Vec<read_json_file::ActiveModel>,
    db: &DatabaseConnection,
) -> Result<(), DbErr> {
    read_json_file::Entity::insert_many(rows)
        .on_conflict(read_json_file_upsert_conflict())
        .exec(db)
        .await?;

    Ok(())
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

pub async fn upsert_cve_models(
    db: &DatabaseConnection,
    models: Vec<CveActiveModels>,
) -> Result<usize, DbErr> {
    CveDatabase { db: db.clone() }
        .upsert_cve_models(models)
        .await
}

pub async fn replace_all_cve_models(
    db: &DatabaseConnection,
    models: Vec<CveActiveModels>,
) -> Result<usize, DbErr> {
    CveDatabase { db: db.clone() }
        .replace_all_cve_models(models)
        .await
}

pub async fn clear_cve_tables(db: &DatabaseConnection) -> Result<(), DbErr> {
    CveDatabase { db: db.clone() }.clear_cve_tables().await
}

pub async fn insert_cve_models(
    db: &DatabaseConnection,
    models: Vec<CveActiveModels>,
) -> Result<usize, DbErr> {
    CveDatabase { db: db.clone() }
        .insert_cve_models(models)
        .await
}

pub async fn replace_cve_children(
    db: &DatabaseConnection,
    cve_id: &str,
    cvss_rows: Vec<cve_cvss::ActiveModel>,
    affected_rows: Vec<cve_affected::ActiveModel>,
    cwe_rows: Vec<cve_cwe::ActiveModel>,
) -> Result<(), DbErr> {
    CveDatabase { db: db.clone() }
        .replace_cve_children(cve_id, cvss_rows, affected_rows, cwe_rows)
        .await
}

pub async fn get_all(db: &DatabaseConnection) -> Result<Vec<cve::Model>, DbErr> {
    CveDatabase { db: db.clone() }.get_all().await
}

pub async fn find_cve_by_id(
    db: &DatabaseConnection,
    cve_id: &str,
) -> Result<Option<cve::Model>, DbErr> {
    CveDatabase { db: db.clone() }.find_cve_by_id(cve_id).await
}

pub async fn search_cves_by_cwe(
    db: &DatabaseConnection,
    cwe_ids: &[String],
    limit: u64,
    offset: u64,
) -> Result<Vec<cve::Model>, DbErr> {
    CveDatabase { db: db.clone() }
        .search_cves_by_cwe(cwe_ids, limit, offset)
        .await
}

pub async fn search_cves_by_vendor_product(
    db: &DatabaseConnection,
    vendor: Option<&str>,
    product: Option<&str>,
    limit: u64,
    offset: u64,
) -> Result<Vec<cve::Model>, DbErr> {
    CveDatabase { db: db.clone() }
        .search_cves_by_vendor_product(vendor, product, limit, offset)
        .await
}

pub async fn search_cves_by_text(
    db: &DatabaseConnection,
    query: &str,
    limit: u64,
    offset: u64,
) -> Result<Vec<cve::Model>, DbErr> {
    CveDatabase { db: db.clone() }
        .search_cves_by_text(query, limit, offset)
        .await
}

pub async fn mark_json_file_read(
    db: &DatabaseConnection,
    filename: &str,
    md5hash: &str,
) -> Result<(), DbErr> {
    CveDatabase { db: db.clone() }
        .mark_json_file_read(filename, md5hash)
        .await
}

pub async fn mark_json_files_read(
    db: &DatabaseConnection,
    files: Vec<ReadJsonFileRecord>,
) -> Result<usize, DbErr> {
    CveDatabase { db: db.clone() }
        .mark_json_files_read(files)
        .await
}

pub async fn find_read_json_file(
    db: &DatabaseConnection,
    filename: &str,
    md5hash: &str,
) -> Result<Option<read_json_file::Model>, DbErr> {
    CveDatabase { db: db.clone() }
        .find_read_json_file(filename, md5hash)
        .await
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

fn cve_id_prefix_summary_sql() -> &'static str {
    r#"
    SELECT
        cve_id,
        state,
        published_at,
        updated_at,
        title,
        description_en
    FROM cve
    WHERE cve_id >= ? AND cve_id < ?
    ORDER BY cve_id ASC
    LIMIT ? OFFSET ?
    "#
}

fn date_prefix_summary_sql() -> &'static str {
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
}

fn fts_summary_sql() -> &'static str {
    r#"
    SELECT
        cve.cve_id,
        cve.state,
        cve.published_at,
        cve.updated_at,
        cve.title,
        cve.description_en
    FROM cve_search_fts
    INNER JOIN cve ON cve.cve_id = cve_search_fts.cve_id
    WHERE cve_search_fts MATCH ?
    ORDER BY bm25(cve_search_fts), cve.published_at DESC, cve.cve_id ASC
    LIMIT ? OFFSET ?
    "#
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
            "COALESCE((SELECT MAX(base_score) FROM cve_cvss WHERE cve_cvss.cve_id = cve.cve_id), -1) ASC, cve.published_at DESC, cve.cve_id ASC"
        }
        CveSummarySortOrder::ScoreDesc => {
            "COALESCE((SELECT MAX(base_score) FROM cve_cvss WHERE cve_cvss.cve_id = cve.cve_id), -1) DESC, cve.published_at DESC, cve.cve_id ASC"
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

fn advanced_where_clause(options: &CveAdvancedSearch) -> String {
    let mut conditions = Vec::new();

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
            "EXISTS (SELECT 1 FROM cve_cwe INDEXED BY idx_cve_cwe_cwe_id_cve_id WHERE cve_cwe.cwe_id = {cwe_id} AND cve_cwe.cve_id = cve.cve_id)"
        ));
    }
    if let Some(vendor) = option_text(options.vendor.as_deref()) {
        conditions.push(format!(
            "EXISTS (SELECT 1 FROM cve_affected WHERE cve_affected.cve_id = cve.cve_id AND cve_affected.vendor LIKE {})",
            sql_string_literal(&like_pattern(vendor))
        ));
    }
    if let Some(product) = option_text(options.product.as_deref()) {
        conditions.push(format!(
            "EXISTS (SELECT 1 FROM cve_affected WHERE cve_affected.cve_id = cve.cve_id AND cve_affected.product LIKE {})",
            sql_string_literal(&like_pattern(product))
        ));
    }

    if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    }
}

fn cwe_summary_sql(cwe_ids: &[i32], limit: u64, offset: u64) -> String {
    let distinct = if cwe_ids.len() > 1 { "DISTINCT " } else { "" };
    format!(
        r#"
        SELECT {distinct}
            cve.cve_id,
            cve.state,
            cve.published_at,
            cve.updated_at,
            cve.title,
            cve.description_en
        FROM cve_cwe INDEXED BY idx_cve_cwe_cwe_id_cve_id
        INNER JOIN cve ON cve.cve_id = cve_cwe.cve_id
        WHERE cve_cwe.cwe_id IN ({})
        ORDER BY cve.published_at DESC, cve.cve_id ASC
        LIMIT {} OFFSET {}
        "#,
        cwe_id_list(cwe_ids),
        limit,
        offset
    )
}

fn cwe_model_sql(cwe_ids: &[i32], limit: u64, offset: u64) -> String {
    let distinct = if cwe_ids.len() > 1 { "DISTINCT " } else { "" };
    format!(
        r#"
        SELECT {distinct}
            cve.cve_id,
            cve.state,
            cve.published_at,
            cve.updated_at,
            cve.serial,
            cve.title,
            cve.description_en,
            cve.raw_json
        FROM cve_cwe INDEXED BY idx_cve_cwe_cwe_id_cve_id
        INNER JOIN cve ON cve.cve_id = cve_cwe.cve_id
        WHERE cve_cwe.cwe_id IN ({})
        ORDER BY cve.published_at DESC, cve.cve_id ASC
        LIMIT {} OFFSET {}
        "#,
        cwe_id_list(cwe_ids),
        limit,
        offset
    )
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
        assert_eq!(cwe.cwe_id.unwrap(), 79);
        let cwe_master = models.cwe_master_rows.into_iter().next().unwrap();
        assert_eq!(cwe_master.id.unwrap(), 79);
        assert_eq!(
            cwe_master.description.unwrap().as_deref(),
            Some("Cross-site Scripting")
        );
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
            state: "PUBLISHED".to_owned(),
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
                    cwe_id: Set(79),
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

            replace_cve_children(
                &db,
                "CVE-2024-0001",
                Vec::new(),
                Vec::new(),
                vec![cve_cwe::ActiveModel {
                    cve_id: Set("CVE-2024-0001".to_owned()),
                    cwe_id: Set(79),
                }],
            )
            .await
            .unwrap();

            let cwe = cwe::Entity::find_by_id(79).one(&db).await.unwrap().unwrap();
            assert_eq!(cwe.description.as_deref(), Some("Cross-site Scripting"));
        });
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
}
