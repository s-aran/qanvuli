//! OSV range event rows.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "osv_range_events")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub range_id: i32,
    #[sea_orm(column_type = "Text")]
    pub event_type: String,
    #[sea_orm(column_type = "Text")]
    pub value: String,
    pub event_order: i32,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
