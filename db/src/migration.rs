use crate::entity::{cve, cve_affected, cve_cvss, cve_cwe};
use sea_orm::Schema;
use sea_orm_migration::prelude::*;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![Box::new(M20260516CreateCveTables)]
    }
}

pub struct M20260516CreateCveTables;

impl MigrationName for M20260516CreateCveTables {
    fn name(&self) -> &str {
        "m20260516_create_cve_tables"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for M20260516CreateCveTables {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let schema = Schema::new(manager.get_database_backend());

        manager
            .create_table(
                schema
                    .create_table_from_entity(cve::Entity)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                schema
                    .create_table_from_entity(cve_cvss::Entity)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                schema
                    .create_table_from_entity(cve_affected::Entity)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;
        manager
            .create_table(
                schema
                    .create_table_from_entity(cve_cwe::Entity)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;

        for statement in index_statements() {
            manager.create_index(statement).await?;
        }

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for statement in [
            Table::drop().table(cve_cwe::Entity).if_exists().to_owned(),
            Table::drop()
                .table(cve_affected::Entity)
                .if_exists()
                .to_owned(),
            Table::drop().table(cve_cvss::Entity).if_exists().to_owned(),
            Table::drop().table(cve::Entity).if_exists().to_owned(),
        ] {
            manager.drop_table(statement).await?;
        }

        Ok(())
    }
}

fn index_statements() -> Vec<IndexCreateStatement> {
    vec![
        Index::create()
            .name("idx_cve_published_at")
            .table(cve::Entity)
            .col(cve::Column::PublishedAt)
            .if_not_exists()
            .to_owned(),
        Index::create()
            .name("idx_cve_updated_at")
            .table(cve::Entity)
            .col(cve::Column::UpdatedAt)
            .if_not_exists()
            .to_owned(),
        Index::create()
            .name("idx_cve_cvss_cve_id")
            .table(cve_cvss::Entity)
            .col(cve_cvss::Column::CveId)
            .if_not_exists()
            .to_owned(),
        Index::create()
            .name("idx_cve_cvss_version")
            .table(cve_cvss::Entity)
            .col(cve_cvss::Column::Version)
            .if_not_exists()
            .to_owned(),
        Index::create()
            .name("idx_cve_cvss_base_score")
            .table(cve_cvss::Entity)
            .col(cve_cvss::Column::BaseScore)
            .if_not_exists()
            .to_owned(),
        Index::create()
            .name("idx_cve_affected_cve_id")
            .table(cve_affected::Entity)
            .col(cve_affected::Column::CveId)
            .if_not_exists()
            .to_owned(),
        Index::create()
            .name("idx_cve_affected_vendor")
            .table(cve_affected::Entity)
            .col(cve_affected::Column::Vendor)
            .if_not_exists()
            .to_owned(),
        Index::create()
            .name("idx_cve_affected_product")
            .table(cve_affected::Entity)
            .col(cve_affected::Column::Product)
            .if_not_exists()
            .to_owned(),
        Index::create()
            .name("idx_cve_affected_package")
            .table(cve_affected::Entity)
            .col(cve_affected::Column::PackageName)
            .if_not_exists()
            .to_owned(),
        Index::create()
            .name("idx_cve_cwe_cve_id")
            .table(cve_cwe::Entity)
            .col(cve_cwe::Column::CveId)
            .if_not_exists()
            .to_owned(),
        Index::create()
            .name("idx_cve_cwe_cwe_id")
            .table(cve_cwe::Entity)
            .col(cve_cwe::Column::CweId)
            .if_not_exists()
            .to_owned(),
    ]
}
