//! FIRST EPSS current scores.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "epss_current")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, column_type = "Text")]
    pub cve_id: String,
    pub epss: f64,
    pub percentile: f64,
    #[sea_orm(column_type = "Text", nullable)]
    pub score_date: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub model_version: Option<String>,
    #[sea_orm(column_type = "Text")]
    pub fetched_at: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
