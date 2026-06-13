use crate::entity::{cve, cve_affected, cve_cvss, cve_cwe, cwe, read_json_file};
use sea_orm::{ConnectionTrait, EntityName, Schema};
use sea_orm_migration::prelude::*;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(M20260516CreateCveTables),
            Box::new(M20260604CreateReadJsonFileTable),
            Box::new(M20260605AddSearchIndexes),
            Box::new(M20260609CreateCweMaster),
            Box::new(M20260610OptimizeCweSearch),
            Box::new(M20260610CreateCveSearchFts),
            Box::new(M20260612OptimizeDetailLookup),
        ]
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
                    .create_table_from_entity(cwe::Entity)
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
        Index::create()
            .name("idx_cve_cwe_cwe_id_cve_id")
            .table(cve_cwe::Entity)
            .col(cve_cwe::Column::CweId)
            .col(cve_cwe::Column::CveId)
            .if_not_exists()
            .to_owned(),
        Index::create()
            .name("idx_cwe_id")
            .table(cwe::Entity)
            .col(cwe::Column::Id)
            .if_not_exists()
            .to_owned(),
    ]
}

pub struct M20260604CreateReadJsonFileTable;

impl MigrationName for M20260604CreateReadJsonFileTable {
    fn name(&self) -> &str {
        "m20260604_create_read_json_file_table"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for M20260604CreateReadJsonFileTable {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let schema = Schema::new(manager.get_database_backend());

        manager
            .create_table(
                schema
                    .create_table_from_entity(read_json_file::Entity)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;

        for statement in read_json_file_index_statements() {
            manager.create_index(statement).await?;
        }

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(read_json_file::Entity)
                    .if_exists()
                    .to_owned(),
            )
            .await
    }
}

fn read_json_file_index_statements() -> Vec<IndexCreateStatement> {
    vec![
        Index::create()
            .name("idx_read_json_file_filename")
            .table(read_json_file::Entity)
            .col(read_json_file::Column::Filename)
            .if_not_exists()
            .to_owned(),
        Index::create()
            .name("idx_read_json_file_filename_md5hash_unique")
            .table(read_json_file::Entity)
            .col(read_json_file::Column::Filename)
            .col(read_json_file::Column::Md5hash)
            .unique()
            .if_not_exists()
            .to_owned(),
    ]
}

pub struct M20260605AddSearchIndexes;

impl MigrationName for M20260605AddSearchIndexes {
    fn name(&self) -> &str {
        "m20260605_add_search_indexes"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for M20260605AddSearchIndexes {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for statement in search_index_statements() {
            manager.create_index(statement).await?;
        }

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for (table, index_name) in [
            (cve_cvss::Entity.table_ref(), "idx_cve_cvss_base_severity"),
            (cve_cvss::Entity.table_ref(), "idx_cve_cvss_severity_score"),
            (cve_cvss::Entity.table_ref(), "idx_cve_cvss_version_score"),
            (cve::Entity.table_ref(), "idx_cve_published_at_cve_id"),
            (cve::Entity.table_ref(), "idx_cve_updated_at_cve_id"),
        ] {
            manager
                .drop_index(
                    Index::drop()
                        .name(index_name)
                        .table(table)
                        .if_exists()
                        .to_owned(),
                )
                .await?;
        }

        Ok(())
    }
}

fn search_index_statements() -> Vec<IndexCreateStatement> {
    vec![
        Index::create()
            .name("idx_cve_cvss_base_severity")
            .table(cve_cvss::Entity)
            .col(cve_cvss::Column::BaseSeverity)
            .if_not_exists()
            .to_owned(),
        Index::create()
            .name("idx_cve_cvss_severity_score")
            .table(cve_cvss::Entity)
            .col(cve_cvss::Column::BaseSeverity)
            .col(cve_cvss::Column::BaseScore)
            .if_not_exists()
            .to_owned(),
        Index::create()
            .name("idx_cve_cvss_version_score")
            .table(cve_cvss::Entity)
            .col(cve_cvss::Column::Version)
            .col(cve_cvss::Column::BaseScore)
            .if_not_exists()
            .to_owned(),
        Index::create()
            .name("idx_cve_published_at_cve_id")
            .table(cve::Entity)
            .col(cve::Column::PublishedAt)
            .col(cve::Column::CveId)
            .if_not_exists()
            .to_owned(),
        Index::create()
            .name("idx_cve_updated_at_cve_id")
            .table(cve::Entity)
            .col(cve::Column::UpdatedAt)
            .col(cve::Column::CveId)
            .if_not_exists()
            .to_owned(),
    ]
}

pub struct M20260609CreateCweMaster;

impl MigrationName for M20260609CreateCweMaster {
    fn name(&self) -> &str {
        "m20260609_create_cwe_master"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for M20260609CreateCweMaster {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let schema = Schema::new(manager.get_database_backend());

        manager
            .create_table(
                schema
                    .create_table_from_entity(cwe::Entity)
                    .if_not_exists()
                    .to_owned(),
            )
            .await?;

        if !manager.has_column("cve_cwe", "description").await? {
            return Ok(());
        }

        let db = manager.get_connection();
        db.execute_unprepared("PRAGMA foreign_keys = OFF").await?;
        db.execute_unprepared(
            r#"
            INSERT OR REPLACE INTO cwe (id, description)
            SELECT DISTINCT
                CAST(
                    CASE
                        WHEN cwe_id LIKE 'CWE-%' THEN substr(cwe_id, 5)
                        WHEN cwe_id LIKE 'CWE%' THEN substr(cwe_id, 4)
                        ELSE cwe_id
                    END
                    AS INTEGER
                ) AS id,
                description
            FROM cve_cwe
            WHERE cwe_id GLOB 'CWE-[0-9]*'
               OR cwe_id GLOB 'CWE[0-9]*'
               OR cwe_id GLOB '[0-9]*'
            "#,
        )
        .await?;
        db.execute_unprepared(
            r#"
            CREATE TABLE IF NOT EXISTS cve_cwe_new (
                cve_id TEXT NOT NULL,
                cwe_id INTEGER NOT NULL,
                PRIMARY KEY (cve_id, cwe_id),
                FOREIGN KEY (cve_id) REFERENCES cve(cve_id) ON DELETE CASCADE,
                FOREIGN KEY (cwe_id) REFERENCES cwe(id) ON DELETE CASCADE
            )
            "#,
        )
        .await?;
        db.execute_unprepared(
            r#"
            INSERT OR IGNORE INTO cve_cwe_new (cve_id, cwe_id)
            SELECT
                cve_id,
                CAST(
                    CASE
                        WHEN cwe_id LIKE 'CWE-%' THEN substr(cwe_id, 5)
                        WHEN cwe_id LIKE 'CWE%' THEN substr(cwe_id, 4)
                        ELSE cwe_id
                    END
                    AS INTEGER
                ) AS cwe_id
            FROM cve_cwe
            WHERE cwe_id GLOB 'CWE-[0-9]*'
               OR cwe_id GLOB 'CWE[0-9]*'
               OR cwe_id GLOB '[0-9]*'
            "#,
        )
        .await?;
        db.execute_unprepared("DROP TABLE cve_cwe").await?;
        db.execute_unprepared("ALTER TABLE cve_cwe_new RENAME TO cve_cwe")
            .await?;
        db.execute_unprepared("CREATE INDEX IF NOT EXISTS idx_cve_cwe_cve_id ON cve_cwe (cve_id)")
            .await?;
        db.execute_unprepared("CREATE INDEX IF NOT EXISTS idx_cve_cwe_cwe_id ON cve_cwe (cwe_id)")
            .await?;
        db.execute_unprepared(
            "CREATE INDEX IF NOT EXISTS idx_cve_cwe_cwe_id_cve_id ON cve_cwe (cwe_id, cve_id)",
        )
        .await?;
        db.execute_unprepared("CREATE INDEX IF NOT EXISTS idx_cwe_id ON cwe (id)")
            .await?;
        db.execute_unprepared("PRAGMA foreign_keys = ON").await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if !manager.has_table("cve_cwe").await? {
            return Ok(());
        }

        let db = manager.get_connection();
        db.execute_unprepared("PRAGMA foreign_keys = OFF").await?;
        db.execute_unprepared(
            r#"
            CREATE TABLE IF NOT EXISTS cve_cwe_old (
                cve_id TEXT NOT NULL,
                cwe_id TEXT NOT NULL,
                description TEXT,
                PRIMARY KEY (cve_id, cwe_id),
                FOREIGN KEY (cve_id) REFERENCES cve(cve_id) ON DELETE CASCADE
            )
            "#,
        )
        .await?;
        db.execute_unprepared(
            r#"
            INSERT OR IGNORE INTO cve_cwe_old (cve_id, cwe_id, description)
            SELECT cve_cwe.cve_id, 'CWE-' || cve_cwe.cwe_id, cwe.description
            FROM cve_cwe
            LEFT JOIN cwe ON cwe.id = cve_cwe.cwe_id
            "#,
        )
        .await?;
        db.execute_unprepared("DROP TABLE cve_cwe").await?;
        db.execute_unprepared("ALTER TABLE cve_cwe_old RENAME TO cve_cwe")
            .await?;
        db.execute_unprepared("DROP TABLE IF EXISTS cwe").await?;
        db.execute_unprepared("CREATE INDEX IF NOT EXISTS idx_cve_cwe_cve_id ON cve_cwe (cve_id)")
            .await?;
        db.execute_unprepared("CREATE INDEX IF NOT EXISTS idx_cve_cwe_cwe_id ON cve_cwe (cwe_id)")
            .await?;
        db.execute_unprepared(
            "CREATE INDEX IF NOT EXISTS idx_cve_cwe_cwe_id_cve_id ON cve_cwe (cwe_id, cve_id)",
        )
        .await?;
        db.execute_unprepared("PRAGMA foreign_keys = ON").await?;

        Ok(())
    }
}

pub struct M20260610OptimizeCweSearch;

impl MigrationName for M20260610OptimizeCweSearch {
    fn name(&self) -> &str {
        "m20260610_optimize_cwe_search"
    }
}

pub struct M20260610CreateCveSearchFts;

impl MigrationName for M20260610CreateCveSearchFts {
    fn name(&self) -> &str {
        "m20260610_create_cve_search_fts"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for M20260610CreateCveSearchFts {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        create_cve_search_fts(db).await?;
        rebuild_cve_search_fts(db).await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("DROP TABLE IF EXISTS cve_search_fts")
            .await?;
        Ok(())
    }
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
        LEFT JOIN cve_affected ON cve_affected.cve_id = cve.cve_id
        GROUP BY cve.cve_id
        "#,
    )
    .await?;
    Ok(())
}

#[async_trait::async_trait]
impl MigrationTrait for M20260610OptimizeCweSearch {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_index(
                Index::create()
                    .name("idx_cve_cwe_cwe_id_cve_id")
                    .table(cve_cwe::Entity)
                    .col(cve_cwe::Column::CweId)
                    .col(cve_cwe::Column::CveId)
                    .if_not_exists()
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name("idx_cve_cwe_cwe_id_cve_id")
                    .table(cve_cwe::Entity)
                    .if_exists()
                    .to_owned(),
            )
            .await
    }
}

pub struct M20260612OptimizeDetailLookup;

impl MigrationName for M20260612OptimizeDetailLookup {
    fn name(&self) -> &str {
        "m20260612_optimize_detail_lookup"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for M20260612OptimizeDetailLookup {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for statement in detail_lookup_index_statements() {
            manager.create_index(statement).await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for (table, index_name) in [
            (
                cve_cvss::Entity.table_ref(),
                "idx_cve_cvss_cve_id_score_version",
            ),
            (
                cve_affected::Entity.table_ref(),
                "idx_cve_affected_cve_id_vendor_product",
            ),
        ] {
            manager
                .drop_index(
                    Index::drop()
                        .name(index_name)
                        .table(table)
                        .if_exists()
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }
}

fn detail_lookup_index_statements() -> Vec<IndexCreateStatement> {
    vec![
        Index::create()
            .name("idx_cve_cvss_cve_id_score_version")
            .table(cve_cvss::Entity)
            .col(cve_cvss::Column::CveId)
            .col(cve_cvss::Column::BaseScore)
            .col(cve_cvss::Column::Version)
            .if_not_exists()
            .to_owned(),
        Index::create()
            .name("idx_cve_affected_cve_id_vendor_product")
            .table(cve_affected::Entity)
            .col(cve_affected::Column::CveId)
            .col(cve_affected::Column::Vendor)
            .col(cve_affected::Column::Product)
            .if_not_exists()
            .to_owned(),
    ]
}
