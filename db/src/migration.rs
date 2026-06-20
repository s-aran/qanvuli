use crate::entity::{
    app_metadata, cve, cve_affected, cve_cvss, cve_cwe, cve_zip_file, cwe, read_json_file,
};
use sea_orm::{ConnectionTrait, Schema};
use sea_orm_migration::prelude::*;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![Box::new(M20260616CreateCurrentSchema)]
    }
}

pub struct M20260616CreateCurrentSchema;

impl MigrationName for M20260616CreateCurrentSchema {
    fn name(&self) -> &str {
        "m20260616_create_current_schema"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for M20260616CreateCurrentSchema {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        reject_legacy_pre_rekey_schema(manager).await?;

        let schema = Schema::new(manager.get_database_backend());
        for statement in [
            schema
                .create_table_from_entity(cve::Entity)
                .if_not_exists()
                .to_owned(),
            schema
                .create_table_from_entity(cwe::Entity)
                .if_not_exists()
                .to_owned(),
            schema
                .create_table_from_entity(cve_cvss::Entity)
                .if_not_exists()
                .to_owned(),
            schema
                .create_table_from_entity(cve_affected::Entity)
                .if_not_exists()
                .to_owned(),
            schema
                .create_table_from_entity(cve_cwe::Entity)
                .if_not_exists()
                .to_owned(),
            schema
                .create_table_from_entity(read_json_file::Entity)
                .if_not_exists()
                .to_owned(),
            schema
                .create_table_from_entity(app_metadata::Entity)
                .if_not_exists()
                .to_owned(),
            schema
                .create_table_from_entity(cve_zip_file::Entity)
                .if_not_exists()
                .to_owned(),
        ] {
            manager.create_table(statement).await?;
        }

        create_current_indexes(manager.get_connection()).await?;
        create_cve_search_fts(manager.get_connection()).await?;
        rebuild_cve_search_fts(manager.get_connection()).await?;
        create_cve_affected_fts(manager.get_connection()).await?;
        rebuild_cve_affected_fts(manager.get_connection()).await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE IF EXISTS cve_search_fts")
            .await?;
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE IF EXISTS cve_affected_fts")
            .await?;

        for statement in [
            Table::drop()
                .table(cve_zip_file::Entity)
                .if_exists()
                .to_owned(),
            Table::drop()
                .table(app_metadata::Entity)
                .if_exists()
                .to_owned(),
            Table::drop()
                .table(read_json_file::Entity)
                .if_exists()
                .to_owned(),
            Table::drop().table(cve_cwe::Entity).if_exists().to_owned(),
            Table::drop().table(cwe::Entity).if_exists().to_owned(),
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

async fn reject_legacy_pre_rekey_schema(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    if manager.has_table("cve").await? && !manager.has_column("cve", "id").await? {
        return Err(DbErr::Custom(
            "database uses the pre-rekey CVE schema; run init --rebuild or recreate the database"
                .to_owned(),
        ));
    }
    Ok(())
}

async fn create_current_indexes<C>(db: &C) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    for sql in [
        "CREATE INDEX IF NOT EXISTS idx_read_json_file_filename ON read_json_file (filename)",
        "CREATE INDEX IF NOT EXISTS idx_cve_published_at ON cve (published_at)",
        "CREATE INDEX IF NOT EXISTS idx_cve_updated_at ON cve (updated_at)",
        "CREATE INDEX IF NOT EXISTS idx_cve_published_at_cve_id ON cve (published_at, cve_id)",
        "CREATE INDEX IF NOT EXISTS idx_cve_updated_at_cve_id ON cve (updated_at, cve_id)",
        "CREATE INDEX IF NOT EXISTS idx_cve_cvss_cve_db_id ON cve_cvss (cve_db_id)",
        "CREATE INDEX IF NOT EXISTS idx_cve_cvss_version ON cve_cvss (version)",
        "CREATE INDEX IF NOT EXISTS idx_cve_cvss_base_score ON cve_cvss (base_score)",
        "CREATE INDEX IF NOT EXISTS idx_cve_cvss_base_severity ON cve_cvss (base_severity)",
        "CREATE INDEX IF NOT EXISTS idx_cve_cvss_severity_score ON cve_cvss (base_severity, base_score)",
        "CREATE INDEX IF NOT EXISTS idx_cve_cvss_version_score ON cve_cvss (version, base_score)",
        "CREATE INDEX IF NOT EXISTS idx_cve_cvss_cve_db_id_score_version ON cve_cvss (cve_db_id, base_score, version)",
        "CREATE INDEX IF NOT EXISTS idx_cve_affected_cve_db_id ON cve_affected (cve_db_id)",
        "CREATE INDEX IF NOT EXISTS idx_cve_affected_vendor ON cve_affected (vendor)",
        "CREATE INDEX IF NOT EXISTS idx_cve_affected_product ON cve_affected (product)",
        "CREATE INDEX IF NOT EXISTS idx_cve_affected_package ON cve_affected (package_name)",
        "CREATE INDEX IF NOT EXISTS idx_cve_affected_cve_db_id_vendor_product ON cve_affected (cve_db_id, vendor, product)",
        "CREATE INDEX IF NOT EXISTS idx_cve_cwe_cve_db_id ON cve_cwe (cve_db_id)",
        "CREATE INDEX IF NOT EXISTS idx_cve_cwe_cwe_id ON cve_cwe (cwe_id)",
        "CREATE INDEX IF NOT EXISTS idx_cve_cwe_cwe_id_cve_db_id ON cve_cwe (cwe_id, cve_db_id)",
        "CREATE INDEX IF NOT EXISTS idx_cwe_id ON cwe (id)",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_cve_zip_file_filename ON cve_zip_file (zip_filename)",
        "CREATE INDEX IF NOT EXISTS idx_cve_zip_file_datetime ON cve_zip_file (zip_datetime)",
        "CREATE INDEX IF NOT EXISTS idx_cve_zip_file_type_datetime ON cve_zip_file (zip_type, zip_datetime)",
    ] {
        db.execute_unprepared(sql).await?;
    }
    Ok(())
}

async fn create_cve_search_fts<C>(db: &C) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
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
        LEFT JOIN cve_affected ON cve_affected.cve_db_id = cve.id
        GROUP BY cve.cve_id
        "#,
    )
    .await?;
    Ok(())
}

async fn create_cve_affected_fts<C>(db: &C) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    db.execute_unprepared(
        r#"
        CREATE VIRTUAL TABLE IF NOT EXISTS cve_affected_fts USING fts5(
            cve_id UNINDEXED,
            vendor,
            product,
            package_name,
            tokenize = 'unicode61'
        )
        "#,
    )
    .await?;
    Ok(())
}

async fn rebuild_cve_affected_fts<C>(db: &C) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    db.execute_unprepared("DELETE FROM cve_affected_fts")
        .await?;
    db.execute_unprepared(
        r#"
        INSERT INTO cve_affected_fts (cve_id, vendor, product, package_name)
        SELECT
            cve.cve_id,
            COALESCE(cve_affected.vendor, ''),
            COALESCE(cve_affected.product, ''),
            COALESCE(cve_affected.package_name, '')
        FROM cve_affected
        INNER JOIN cve ON cve.id = cve_affected.cve_db_id
        "#,
    )
    .await?;
    Ok(())
}
