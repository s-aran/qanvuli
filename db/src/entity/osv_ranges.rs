//! OSV affected package ranges.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "osv_ranges")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub affected_package_id: i32,
    pub affected_order: i32,
    pub range_order: i32,
    #[sea_orm(column_type = "Text", nullable)]
    pub range_type: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
