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
        create_current_search_tables(manager.get_connection()).await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for table in [
            "cve_affected_search",
            "cve_cvss_search",
            "cve_cwe_search",
            "cve_affected_summary_fts",
            "cve_summary_fts",
            "cve_summary_index",
        ] {
            manager
                .get_connection()
                .execute_unprepared(&format!("DROP TABLE IF EXISTS {table}"))
                .await?;
        }

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
        "CREATE INDEX IF NOT EXISTS idx_cve_reference_text ON cve (reference_text)",
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
        "CREATE INDEX IF NOT EXISTS idx_cve_affected_version_text ON cve_affected (version_text)",
        "CREATE INDEX IF NOT EXISTS idx_cve_affected_cve_db_id_vendor_product ON cve_affected (cve_db_id, vendor, product)",
        "CREATE INDEX IF NOT EXISTS idx_cve_affected_vendor_cve_db_id ON cve_affected (vendor, cve_db_id)",
        "CREATE INDEX IF NOT EXISTS idx_cve_affected_product_cve_db_id ON cve_affected (product, cve_db_id)",
        "CREATE INDEX IF NOT EXISTS idx_cve_affected_vendor_product_cve_db_id ON cve_affected (vendor, product, cve_db_id)",
        "CREATE INDEX IF NOT EXISTS idx_cve_cwe_cve_db_id ON cve_cwe (cve_db_id)",
        "CREATE INDEX IF NOT EXISTS idx_cve_cwe_cwe_id ON cve_cwe (cwe_id)",
        "CREATE INDEX IF NOT EXISTS idx_cve_cwe_cwe_id_cve_db_id ON cve_cwe (cwe_id, cve_db_id)",
        "CREATE INDEX IF NOT EXISTS idx_cwe_id ON cwe (id)",
        "CREATE INDEX IF NOT EXISTS idx_cwe_status ON cwe (status)",
        "CREATE INDEX IF NOT EXISTS idx_cwe_parent_id ON cwe (parent_id)",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_cve_zip_file_filename ON cve_zip_file (zip_filename)",
        "CREATE INDEX IF NOT EXISTS idx_cve_zip_file_datetime ON cve_zip_file (zip_datetime)",
        "CREATE INDEX IF NOT EXISTS idx_cve_zip_file_type_datetime ON cve_zip_file (zip_type, zip_datetime)",
    ] {
        db.execute_unprepared(sql).await?;
    }
    Ok(())
}

async fn create_current_search_tables<C>(db: &C) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    for sql in [
        r#"
        CREATE TABLE IF NOT EXISTS cve_summary_index (
            cve_db_id INTEGER PRIMARY KEY NOT NULL,
            cve_id TEXT NOT NULL UNIQUE,
            state INTEGER NOT NULL,
            published_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            title TEXT NOT NULL,
            description_en TEXT,
            max_cvss_score REAL,
            max_cvss_severity TEXT,
            cwe_ids TEXT NOT NULL DEFAULT '',
            affected_text TEXT NOT NULL DEFAULT '',
            vendor_text TEXT NOT NULL DEFAULT '',
            product_text TEXT NOT NULL DEFAULT '',
            reference_text TEXT NOT NULL DEFAULT ''
        )
        "#,
        "CREATE INDEX IF NOT EXISTS idx_cve_summary_state_published ON cve_summary_index (state, published_at DESC, cve_id)",
        "CREATE INDEX IF NOT EXISTS idx_cve_summary_published ON cve_summary_index (published_at DESC, cve_id)",
        "CREATE INDEX IF NOT EXISTS idx_cve_summary_updated ON cve_summary_index (updated_at DESC, cve_id)",
        "CREATE INDEX IF NOT EXISTS idx_cve_summary_cve_id ON cve_summary_index (cve_id)",
        "CREATE INDEX IF NOT EXISTS idx_cve_summary_score ON cve_summary_index (max_cvss_score DESC, published_at DESC, cve_id)",
        r#"
        CREATE VIRTUAL TABLE IF NOT EXISTS cve_summary_fts USING fts5(
            cve_id UNINDEXED,
            title,
            description_en,
            affected_text,
            reference_text,
            tokenize = 'unicode61'
        )
        "#,
        r#"
        CREATE VIRTUAL TABLE IF NOT EXISTS cve_affected_summary_fts USING fts5(
            cve_id UNINDEXED,
            vendor_text,
            product_text,
            affected_text,
            tokenize = 'unicode61'
        )
        "#,
        r#"
        CREATE TABLE IF NOT EXISTS cve_cwe_search (
            cwe_id INTEGER NOT NULL,
            cve_id TEXT NOT NULL,
            state INTEGER NOT NULL,
            published_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            title TEXT NOT NULL,
            description_en TEXT,
            PRIMARY KEY (cwe_id, cve_id)
        )
        "#,
        "CREATE INDEX IF NOT EXISTS idx_cve_cwe_search_sort ON cve_cwe_search (cwe_id, state, published_at DESC, cve_id)",
        r#"
        CREATE TABLE IF NOT EXISTS cve_cvss_search (
            cve_id TEXT PRIMARY KEY NOT NULL,
            state INTEGER NOT NULL,
            published_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            title TEXT NOT NULL,
            description_en TEXT,
            max_cvss_score REAL,
            max_cvss_severity TEXT,
            cvss_versions TEXT NOT NULL DEFAULT ''
        )
        "#,
        "CREATE INDEX IF NOT EXISTS idx_cve_cvss_search_score ON cve_cvss_search (state, max_cvss_score DESC, published_at DESC, cve_id)",
        "CREATE INDEX IF NOT EXISTS idx_cve_cvss_search_severity ON cve_cvss_search (max_cvss_severity, state, max_cvss_score DESC, published_at DESC, cve_id)",
        r#"
        CREATE TABLE IF NOT EXISTS cve_affected_search (
            cve_id TEXT PRIMARY KEY NOT NULL,
            state INTEGER NOT NULL,
            published_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            title TEXT NOT NULL,
            description_en TEXT,
            vendor_text TEXT NOT NULL DEFAULT '',
            product_text TEXT NOT NULL DEFAULT '',
            affected_text TEXT NOT NULL DEFAULT ''
        )
        "#,
        "CREATE INDEX IF NOT EXISTS idx_cve_affected_search_sort ON cve_affected_search (state, published_at DESC, cve_id)",
    ] {
        db.execute_unprepared(sql).await?;
    }
    Ok(())
}
