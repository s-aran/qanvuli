//! Enrichment source synchronization state.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "source_sync_state")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, column_type = "Text")]
    pub source: String,
    #[sea_orm(column_type = "Text", nullable)]
    pub last_attempt_at: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub last_success_at: Option<String>,
    #[sea_orm(column_type = "Text")]
    pub status: String,
    #[sea_orm(column_type = "Text", nullable)]
    pub error_message: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub last_cursor: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub content_hash: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub schema_version: Option<String>,
    pub record_count: i32,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
