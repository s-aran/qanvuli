use crate::entity::{
    app_metadata, cve, cve_affected, cve_cvss, cve_cwe, cve_zip_file, cwe, read_json_file,
};
use sea_orm::{ConnectionTrait, Schema};
use sea_orm_migration::prelude::*;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(M20260616CreateCveCoreSchema),
            #[cfg(feature = "enrichment")]
            Box::new(M20260617CreateEnrichmentSchema),
        ]
    }
}

pub struct M20260616CreateCveCoreSchema;

impl MigrationName for M20260616CreateCveCoreSchema {
    fn name(&self) -> &str {
        "m20260616_create_cve_core_schema"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for M20260616CreateCveCoreSchema {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let schema = Schema::new(manager.get_database_backend());
        for statement in [
            schema.create_table_from_entity(cve::Entity).to_owned(),
            schema.create_table_from_entity(cwe::Entity).to_owned(),
            schema.create_table_from_entity(cve_cvss::Entity).to_owned(),
            schema
                .create_table_from_entity(cve_affected::Entity)
                .to_owned(),
            schema.create_table_from_entity(cve_cwe::Entity).to_owned(),
            schema
                .create_table_from_entity(read_json_file::Entity)
                .to_owned(),
            schema
                .create_table_from_entity(app_metadata::Entity)
                .to_owned(),
            schema
                .create_table_from_entity(cve_zip_file::Entity)
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
                .execute_unprepared(&format!("DROP TABLE {table}"))
                .await?;
        }

        for statement in [
            Table::drop().table(cve_zip_file::Entity).to_owned(),
            Table::drop().table(app_metadata::Entity).to_owned(),
            Table::drop().table(read_json_file::Entity).to_owned(),
            Table::drop().table(cve_cwe::Entity).to_owned(),
            Table::drop().table(cwe::Entity).to_owned(),
            Table::drop().table(cve_affected::Entity).to_owned(),
            Table::drop().table(cve_cvss::Entity).to_owned(),
            Table::drop().table(cve::Entity).to_owned(),
        ] {
            manager.drop_table(statement).await?;
        }
        Ok(())
    }
}

#[cfg(feature = "enrichment")]
pub struct M20260617CreateEnrichmentSchema;

#[cfg(feature = "enrichment")]
impl MigrationName for M20260617CreateEnrichmentSchema {
    fn name(&self) -> &str {
        "m20260617_create_enrichment_schema"
    }
}

#[cfg(feature = "enrichment")]
#[async_trait::async_trait]
impl MigrationTrait for M20260617CreateEnrichmentSchema {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        create_enrichment_tables(manager.get_connection()).await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for table in [
            "vulnerability_identifier_edges",
            "vulnerability_identifiers",
            "epss_current",
            "kev_entries",
            "osv_text_vocab",
            "osv_text_fts",
            "osv_token_cve_search",
            "osv_references",
            "osv_versions",
            "osv_range_events",
            "osv_ranges",
            "osv_affected_packages",
            "osv_cve_search",
            "osv_aliases",
            "osv_advisories",
            "source_raw_records",
            "source_sync_state",
            "db_sources",
        ] {
            manager
                .get_connection()
                .execute_unprepared(&format!("DROP TABLE {table}"))
                .await?;
        }
        Ok(())
    }
}

#[cfg(feature = "enrichment")]
async fn create_enrichment_tables<C>(db: &C) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    for sql in [
        r#"
        CREATE TABLE db_sources (
            source TEXT PRIMARY KEY NOT NULL,
            display_name TEXT NOT NULL,
            source_type TEXT NOT NULL,
            default_filename TEXT NOT NULL,
            raw_format TEXT NOT NULL
        )
        "#,
        r#"
        CREATE TABLE source_sync_state (
            source TEXT PRIMARY KEY NOT NULL,
            last_attempt_at TEXT,
            last_success_at TEXT,
            status TEXT NOT NULL DEFAULT 'never_synced',
            error_message TEXT,
            last_cursor TEXT,
            content_hash TEXT,
            schema_version TEXT,
            record_count INTEGER NOT NULL DEFAULT 0
        )
        "#,
        r#"
        CREATE TABLE source_raw_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
            source TEXT NOT NULL,
            source_record_id TEXT NOT NULL,
            source_path TEXT,
            provider_published_at TEXT,
            provider_modified_at TEXT,
            score_date TEXT,
            fetched_at TEXT NOT NULL,
            content_hash TEXT NOT NULL,
            raw_content TEXT NOT NULL,
            raw_json TEXT,
            raw_csv TEXT,
            content_type TEXT NOT NULL,
            UNIQUE(source, source_record_id)
        )
        "#,
        r#"
        CREATE TABLE osv_advisories (
            osv_id TEXT PRIMARY KEY NOT NULL,
            schema_version TEXT,
            published_at TEXT,
            modified_at TEXT,
            withdrawn_at TEXT,
            summary TEXT,
            details TEXT,
            raw_record_id INTEGER NOT NULL,
            FOREIGN KEY(raw_record_id) REFERENCES source_raw_records(id)
        )
        "#,
        "CREATE TABLE osv_aliases (osv_id TEXT NOT NULL, alias_id TEXT NOT NULL, PRIMARY KEY(osv_id, alias_id))",
        "CREATE TABLE osv_cve_search (osv_id TEXT NOT NULL, cve_id TEXT NOT NULL, PRIMARY KEY(osv_id, cve_id))",
        "CREATE TABLE osv_token_cve_search (token TEXT NOT NULL, cve_id TEXT NOT NULL, state INTEGER NOT NULL, published_at TEXT NOT NULL, PRIMARY KEY(token, cve_id))",
        r#"
        CREATE TABLE osv_affected_packages (
            id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
            osv_id TEXT NOT NULL,
            affected_order INTEGER NOT NULL DEFAULT 0,
            ecosystem TEXT,
            package_name TEXT,
            purl TEXT
        )
        "#,
        "CREATE TABLE osv_ranges (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, affected_package_id INTEGER NOT NULL, affected_order INTEGER NOT NULL DEFAULT 0, range_order INTEGER NOT NULL DEFAULT 0, range_type TEXT)",
        "CREATE TABLE osv_range_events (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, range_id INTEGER NOT NULL, event_type TEXT NOT NULL, value TEXT NOT NULL, event_order INTEGER NOT NULL)",
        "CREATE TABLE osv_versions (affected_package_id INTEGER NOT NULL, version TEXT NOT NULL, PRIMARY KEY(affected_package_id, version))",
        "CREATE TABLE osv_references (osv_id TEXT NOT NULL, reference_type TEXT, url TEXT NOT NULL, PRIMARY KEY(osv_id, url))",
        r#"
        CREATE VIRTUAL TABLE osv_text_fts USING fts5(
            osv_id UNINDEXED,
            summary,
            details,
            aliases,
            packages,
            tokenize = 'unicode61'
        )
        "#,
        r#"
        CREATE TABLE kev_entries (
            cve_id TEXT PRIMARY KEY NOT NULL,
            vendor_project TEXT,
            product TEXT,
            vulnerability_name TEXT,
            date_added TEXT,
            short_description TEXT,
            required_action TEXT,
            due_date TEXT,
            known_ransomware_campaign_use TEXT,
            notes TEXT,
            fetched_at TEXT NOT NULL,
            raw_record_id INTEGER NOT NULL
        )
        "#,
        r#"
        CREATE TABLE epss_current (
            cve_id TEXT PRIMARY KEY NOT NULL,
            epss REAL NOT NULL,
            percentile REAL NOT NULL,
            score_date TEXT,
            model_version TEXT,
            fetched_at TEXT NOT NULL,
            raw_record_id INTEGER
        )
        "#,
        r#"
        CREATE TABLE vulnerability_identifiers (
            identifier TEXT PRIMARY KEY NOT NULL,
            identifier_type TEXT NOT NULL,
            source TEXT NOT NULL,
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL
        )
        "#,
        r#"
        CREATE TABLE vulnerability_identifier_edges (
            from_identifier TEXT NOT NULL,
            to_identifier TEXT NOT NULL,
            relation_type TEXT NOT NULL,
            source TEXT NOT NULL,
            confidence TEXT NOT NULL,
            evidence_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY(from_identifier, to_identifier, relation_type, source)
        )
        "#,
        "CREATE INDEX idx_source_raw_records_source_hash ON source_raw_records (source, content_hash)",
        "CREATE INDEX idx_osv_aliases_alias ON osv_aliases (alias_id)",
        "CREATE INDEX idx_osv_cve_search_cve_id ON osv_cve_search (cve_id)",
        "CREATE INDEX idx_osv_affected_packages_lookup ON osv_affected_packages (ecosystem, package_name)",
        "CREATE INDEX idx_osv_ranges_package ON osv_ranges (affected_package_id)",
        "CREATE INDEX idx_osv_range_events_range ON osv_range_events (range_id, event_order)",
        "CREATE INDEX idx_identifier_edges_to ON vulnerability_identifier_edges (to_identifier)",
        "CREATE INDEX idx_identifier_edges_from ON vulnerability_identifier_edges (from_identifier)",
        "CREATE INDEX idx_kev_entries_date_added_cve_id ON kev_entries (date_added DESC, cve_id)",
        "CREATE INDEX idx_epss_current_score ON epss_current (epss DESC, percentile DESC, cve_id)",
        "CREATE INDEX idx_epss_current_percentile ON epss_current (percentile DESC, epss DESC, cve_id)",
    ] {
        db.execute_unprepared(sql).await?;
    }

    db.execute_unprepared(
        r#"
        INSERT INTO db_sources (source, display_name, source_type, default_filename, raw_format)
        VALUES
            ('CVE', 'CVE List V5', 'vulnerability_db', 'all_CVEs_at_midnight.zip', 'json'),
            ('OSV', 'OSV.dev', 'vulnerability_db', 'all.zip', 'json'),
            ('KEV', 'CISA Known Exploited Vulnerabilities', 'enrichment', 'known_exploited_vulnerabilities.json', 'json'),
            ('EPSS', 'FIRST EPSS Current Scores', 'enrichment', 'epss_scores-current.csv', 'csv')
        "#,
    )
    .await?;
    Ok(())
}

async fn create_current_indexes<C>(db: &C) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    for sql in [
        "CREATE INDEX idx_read_json_file_filename ON read_json_file (filename)",
        "CREATE INDEX idx_cve_published_at ON cve (published_at)",
        "CREATE INDEX idx_cve_updated_at ON cve (updated_at)",
        "CREATE INDEX idx_cve_published_at_cve_id ON cve (published_at, cve_id)",
        "CREATE INDEX idx_cve_updated_at_cve_id ON cve (updated_at, cve_id)",
        "CREATE INDEX idx_cve_reference_text ON cve (reference_text)",
        "CREATE INDEX idx_cve_cvss_cve_db_id ON cve_cvss (cve_db_id)",
        "CREATE INDEX idx_cve_cvss_version ON cve_cvss (version)",
        "CREATE INDEX idx_cve_cvss_base_score ON cve_cvss (base_score)",
        "CREATE INDEX idx_cve_cvss_base_severity ON cve_cvss (base_severity)",
        "CREATE INDEX idx_cve_cvss_severity_score ON cve_cvss (base_severity, base_score)",
        "CREATE INDEX idx_cve_cvss_version_score ON cve_cvss (version, base_score)",
        "CREATE INDEX idx_cve_cvss_cve_db_id_score_version ON cve_cvss (cve_db_id, base_score, version)",
        "CREATE INDEX idx_cve_affected_cve_db_id ON cve_affected (cve_db_id)",
        "CREATE INDEX idx_cve_affected_vendor ON cve_affected (vendor)",
        "CREATE INDEX idx_cve_affected_product ON cve_affected (product)",
        "CREATE INDEX idx_cve_affected_package ON cve_affected (package_name)",
        "CREATE INDEX idx_cve_affected_version_text ON cve_affected (version_text)",
        "CREATE INDEX idx_cve_affected_cve_db_id_vendor_product ON cve_affected (cve_db_id, vendor, product)",
        "CREATE INDEX idx_cve_affected_vendor_cve_db_id ON cve_affected (vendor, cve_db_id)",
        "CREATE INDEX idx_cve_affected_product_cve_db_id ON cve_affected (product, cve_db_id)",
        "CREATE INDEX idx_cve_affected_vendor_product_cve_db_id ON cve_affected (vendor, product, cve_db_id)",
        "CREATE INDEX idx_cve_cwe_cve_db_id ON cve_cwe (cve_db_id)",
        "CREATE INDEX idx_cve_cwe_cwe_id ON cve_cwe (cwe_id)",
        "CREATE INDEX idx_cve_cwe_cwe_id_cve_db_id ON cve_cwe (cwe_id, cve_db_id)",
        "CREATE INDEX idx_cwe_id ON cwe (id)",
        "CREATE INDEX idx_cwe_status ON cwe (status)",
        "CREATE INDEX idx_cwe_parent_id ON cwe (parent_id)",
        "CREATE UNIQUE INDEX idx_cve_zip_file_filename ON cve_zip_file (zip_filename)",
        "CREATE INDEX idx_cve_zip_file_datetime ON cve_zip_file (zip_datetime)",
        "CREATE INDEX idx_cve_zip_file_type_datetime ON cve_zip_file (zip_type, zip_datetime)",
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
        CREATE TABLE cve_summary_index (
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
        "CREATE INDEX idx_cve_summary_state_published ON cve_summary_index (state, published_at DESC, cve_id)",
        "CREATE INDEX idx_cve_summary_published ON cve_summary_index (published_at DESC, cve_id)",
        "CREATE INDEX idx_cve_summary_updated ON cve_summary_index (updated_at DESC, cve_id)",
        "CREATE INDEX idx_cve_summary_cve_id ON cve_summary_index (cve_id)",
        "CREATE INDEX idx_cve_summary_score ON cve_summary_index (max_cvss_score DESC, published_at DESC, cve_id)",
        r#"
        CREATE VIRTUAL TABLE cve_summary_fts USING fts5(
            cve_id UNINDEXED,
            title,
            description_en,
            affected_text,
            reference_text,
            tokenize = 'unicode61'
        )
        "#,
        r#"
        CREATE VIRTUAL TABLE cve_affected_summary_fts USING fts5(
            cve_id UNINDEXED,
            vendor_text,
            product_text,
            affected_text,
            tokenize = 'unicode61'
        )
        "#,
        r#"
        CREATE TABLE cve_cwe_search (
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
        "CREATE INDEX idx_cve_cwe_search_sort ON cve_cwe_search (cwe_id, state, published_at DESC, cve_id)",
        r#"
        CREATE TABLE cve_cvss_search (
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
        "CREATE INDEX idx_cve_cvss_search_score ON cve_cvss_search (state, max_cvss_score DESC, published_at DESC, cve_id)",
        "CREATE INDEX idx_cve_cvss_search_severity ON cve_cvss_search (max_cvss_severity, state, max_cvss_score DESC, published_at DESC, cve_id)",
        r#"
        CREATE TABLE cve_affected_search (
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
        "CREATE INDEX idx_cve_affected_search_sort ON cve_affected_search (state, published_at DESC, cve_id)",
    ] {
        db.execute_unprepared(sql).await?;
    }
    Ok(())
}
