//! OSV affected package rows.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "osv_affected_packages")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    #[sea_orm(column_type = "Text")]
    pub osv_id: String,
    #[sea_orm(column_type = "Text", nullable)]
    pub ecosystem: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub package_name: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub purl: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
