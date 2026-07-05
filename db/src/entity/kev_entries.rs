//! CISA KEV entries.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq)]
#[sea_orm(table_name = "kev_entries")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, column_type = "Text")]
    pub cve_id: String,
    #[sea_orm(column_type = "Text", nullable)]
    pub vendor_project: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub product: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub vulnerability_name: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub date_added: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub short_description: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub required_action: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub due_date: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub known_ransomware_campaign_use: Option<String>,
    #[sea_orm(column_type = "Text", nullable)]
    pub notes: Option<String>,
    #[sea_orm(column_type = "Text")]
    pub fetched_at: String,
    pub raw_record_id: i32,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
