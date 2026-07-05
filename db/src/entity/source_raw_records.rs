//! Raw source records for enrichment feeds.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "source_raw_records")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    #[sea_orm(column_type = "Text")]
    pub source: String,
    #[sea_orm(column_type = "Text")]
    pub source_record_id: String,
    #[sea_orm(column_type = "Text", nullable)]
    pub source_path: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub provider_published_at: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub provider_modified_at: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub score_date: Option<String>,
    #[sea_orm(column_type = "Text")]
    pub fetched_at: String,
    #[sea_orm(column_type = "Text")]
    pub content_hash: String,
    #[sea_orm(column_type = "Text")]
    pub raw_content: String,
    #[sea_orm(column_type = "Text", nullable)]
    pub raw_json: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub raw_csv: Option<String>,
    #[sea_orm(column_type = "Text")]
    pub content_type: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
