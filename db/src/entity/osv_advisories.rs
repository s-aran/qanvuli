//! Normalized OSV advisory records.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "osv_advisories")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, column_type = "Text")]
    pub osv_id: String,
    #[sea_orm(column_type = "Text", nullable)]
    pub schema_version: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub published_at: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub modified_at: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub withdrawn_at: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub summary: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub details: Option<String>,
    pub raw_record_id: i32,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
