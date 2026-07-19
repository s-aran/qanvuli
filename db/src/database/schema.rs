//! SQLx schema preserving devel's canonical table layout.

use sqlx::{Connection, SqliteConnection};

pub(crate) const SCHEMA_VERSION: i64 = 7;

pub(crate) async fn suspend_cve_search_sync(
    _connection: &mut SqliteConnection,
) -> Result<(), sqlx::Error> {
    Ok(())
}

pub(crate) async fn restore_cve_search_sync(
    _connection: &mut SqliteConnection,
) -> Result<(), sqlx::Error> {
    Ok(())
}

pub(crate) async fn initialize(connection: &mut SqliteConnection) -> Result<(), sqlx::Error> {
    let existing_objects: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'")
            .fetch_one(&mut *connection)
            .await?;
    if existing_objects != 0 {
        // Rebuild-only policy: never fill gaps in, or certify, an existing schema.
        // A current database must already pass the same quick shape checks used at startup.
        super::maintenance::check_required_schema(connection).await?;
        return Ok(());
    }

    let mut transaction = connection.begin().await?;
    sqlx::raw_sql(
        r#"
        PRAGMA foreign_keys = ON;
        CREATE TABLE IF NOT EXISTS schema_meta (version INTEGER NOT NULL);

        CREATE TABLE IF NOT EXISTS cve (
            id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
            cve_id TEXT NOT NULL UNIQUE,
            state INTEGER NOT NULL,
            published_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            serial INTEGER NOT NULL,
            title TEXT NOT NULL,
            description_en TEXT,
            reference_text TEXT NOT NULL,
            raw_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS cwe (
            id INTEGER PRIMARY KEY NOT NULL,
            description TEXT,
            status TEXT,
            parent_id INTEGER
        );
        CREATE TABLE IF NOT EXISTS cve_cvss (
            id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
            cve_db_id INTEGER NOT NULL REFERENCES cve(id) ON DELETE CASCADE,
            version TEXT NOT NULL,
            base_score REAL,
            base_severity TEXT,
            vector_string TEXT,
            source TEXT,
            raw_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS cve_affected (
            id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
            cve_db_id INTEGER NOT NULL REFERENCES cve(id) ON DELETE CASCADE,
            vendor TEXT,
            product TEXT,
            package_name TEXT,
            collection_url TEXT,
            default_status TEXT,
            version_text TEXT NOT NULL,
            raw_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS cve_cwe (
            cve_db_id INTEGER NOT NULL REFERENCES cve(id) ON DELETE CASCADE,
            cwe_id INTEGER NOT NULL REFERENCES cwe(id) ON DELETE CASCADE,
            PRIMARY KEY(cve_db_id, cwe_id)
        );
        CREATE TABLE IF NOT EXISTS read_json_file (
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            filename TEXT NOT NULL,
            md5hash TEXT NOT NULL,
            PRIMARY KEY(filename, md5hash)
        );
        CREATE TABLE IF NOT EXISTS app_metadata (
            key TEXT PRIMARY KEY NOT NULL,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS cve_zip_file (
            id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
            created_at TEXT NOT NULL,
            zip_filename TEXT NOT NULL UNIQUE,
            zip_datetime TEXT NOT NULL,
            zip_type INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS db_sources (
            source TEXT PRIMARY KEY NOT NULL,
            display_name TEXT NOT NULL,
            source_type TEXT NOT NULL,
            default_filename TEXT NOT NULL,
            raw_format TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS source_sync_state (
            source TEXT PRIMARY KEY NOT NULL,
            last_attempt_at TEXT,
            last_success_at TEXT,
            status TEXT NOT NULL DEFAULT 'never_synced',
            error_message TEXT,
            last_cursor TEXT,
            content_hash TEXT,
            schema_version TEXT,
            record_count INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS osv_raw_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
            osv_id TEXT NOT NULL UNIQUE,
            source_path TEXT,
            provider_published_at TEXT,
            provider_modified_at TEXT,
            fetched_at TEXT NOT NULL,
            content_hash TEXT NOT NULL,
            raw_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS kev_raw_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
            record_id TEXT NOT NULL UNIQUE,
            source_path TEXT,
            provider_modified_at TEXT,
            score_date TEXT,
            fetched_at TEXT NOT NULL,
            content_hash TEXT NOT NULL,
            raw_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS epss_raw_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
            score_date TEXT NOT NULL UNIQUE,
            fetched_at TEXT NOT NULL,
            content_hash TEXT NOT NULL UNIQUE,
            raw_csv TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS osv_advisories (
            osv_id TEXT PRIMARY KEY NOT NULL,
            schema_version TEXT,
            published_at TEXT,
            modified_at TEXT,
            withdrawn_at TEXT,
            summary TEXT,
            details TEXT,
            raw_record_id INTEGER NOT NULL REFERENCES osv_raw_records(id)
        );
        CREATE TABLE IF NOT EXISTS osv_aliases (osv_id TEXT NOT NULL, alias_id TEXT NOT NULL, PRIMARY KEY(osv_id, alias_id));
        CREATE TABLE IF NOT EXISTS osv_cve_search (osv_id TEXT NOT NULL, cve_id TEXT NOT NULL, PRIMARY KEY(osv_id, cve_id));
        CREATE TABLE IF NOT EXISTS osv_token_cve_search (token TEXT NOT NULL, cve_id TEXT NOT NULL, state INTEGER NOT NULL, published_at TEXT NOT NULL, PRIMARY KEY(token, cve_id));
        CREATE TABLE IF NOT EXISTS osv_affected_packages (
            id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
            osv_id TEXT NOT NULL,
            affected_order INTEGER NOT NULL DEFAULT 0,
            ecosystem TEXT,
            package_name TEXT,
            purl TEXT
        );
        CREATE TABLE IF NOT EXISTS osv_ranges (
            id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
            affected_package_id INTEGER NOT NULL,
            affected_order INTEGER NOT NULL DEFAULT 0,
            range_order INTEGER NOT NULL DEFAULT 0,
            range_type TEXT
        );
        CREATE TABLE IF NOT EXISTS osv_range_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
            range_id INTEGER NOT NULL,
            event_type TEXT NOT NULL,
            value TEXT NOT NULL,
            event_order INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS osv_versions (affected_package_id INTEGER NOT NULL, version TEXT NOT NULL, PRIMARY KEY(affected_package_id, version));
        CREATE TABLE IF NOT EXISTS osv_references (osv_id TEXT NOT NULL, reference_type TEXT, url TEXT NOT NULL, PRIMARY KEY(osv_id, url));
        CREATE VIRTUAL TABLE IF NOT EXISTS osv_text_fts USING fts5(osv_id UNINDEXED, summary, details, aliases, packages, tokenize='unicode61');
        CREATE TABLE IF NOT EXISTS kev_entries (
            cve_id TEXT PRIMARY KEY NOT NULL,
            vendor_project TEXT, product TEXT, vulnerability_name TEXT, date_added TEXT,
            short_description TEXT, required_action TEXT, due_date TEXT,
            known_ransomware_campaign_use TEXT, notes TEXT,
            fetched_at TEXT NOT NULL,
            raw_record_id INTEGER NOT NULL REFERENCES kev_raw_records(id)
        );
        CREATE TABLE IF NOT EXISTS epss_current (
            cve_id TEXT PRIMARY KEY NOT NULL,
            epss REAL NOT NULL,
            percentile REAL NOT NULL,
            score_date TEXT,
            model_version TEXT,
            fetched_at TEXT NOT NULL,
            raw_record_id INTEGER NOT NULL REFERENCES epss_raw_records(id)
        );
        CREATE TABLE IF NOT EXISTS vulnerability_identifiers (
            identifier TEXT PRIMARY KEY NOT NULL,
            identifier_type TEXT NOT NULL,
            source TEXT NOT NULL,
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS vulnerability_identifier_edges (
            from_identifier TEXT NOT NULL,
            to_identifier TEXT NOT NULL,
            relation_type TEXT NOT NULL,
            source TEXT NOT NULL,
            confidence TEXT NOT NULL,
            evidence_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY(from_identifier, to_identifier, relation_type, source)
        );
        CREATE TABLE IF NOT EXISTS identifier_components (identifier TEXT PRIMARY KEY, component_id TEXT NOT NULL);

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
        );
        CREATE VIRTUAL TABLE IF NOT EXISTS cve_summary_fts USING fts5(cve_id UNINDEXED, title, description_en, affected_text, reference_text, tokenize='unicode61');
        CREATE VIRTUAL TABLE IF NOT EXISTS cve_affected_summary_fts USING fts5(cve_id UNINDEXED, vendor_text, product_text, affected_text, tokenize='unicode61');
        CREATE TABLE IF NOT EXISTS cve_cwe_search (
            cwe_id INTEGER NOT NULL, cve_id TEXT NOT NULL, state INTEGER NOT NULL,
            published_at TEXT NOT NULL, updated_at TEXT NOT NULL, title TEXT NOT NULL,
            description_en TEXT, PRIMARY KEY(cwe_id, cve_id)
        );
        CREATE TABLE IF NOT EXISTS cve_cvss_search (
            cve_id TEXT PRIMARY KEY NOT NULL, state INTEGER NOT NULL, published_at TEXT NOT NULL,
            updated_at TEXT NOT NULL, title TEXT NOT NULL, description_en TEXT,
            max_cvss_score REAL, max_cvss_severity TEXT, cvss_versions TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS cve_affected_search (
            cve_id TEXT PRIMARY KEY NOT NULL, state INTEGER NOT NULL, published_at TEXT NOT NULL,
            updated_at TEXT NOT NULL, title TEXT NOT NULL, description_en TEXT,
            vendor_text TEXT NOT NULL DEFAULT '', product_text TEXT NOT NULL DEFAULT '',
            affected_text TEXT NOT NULL DEFAULT ''
        );

        CREATE INDEX IF NOT EXISTS idx_read_json_file_filename ON read_json_file(filename);
        CREATE INDEX IF NOT EXISTS idx_cve_published_at ON cve(published_at);
        CREATE INDEX IF NOT EXISTS idx_cve_updated_at ON cve(updated_at);
        CREATE INDEX IF NOT EXISTS idx_cve_published_at_cve_id ON cve(published_at, cve_id);
        CREATE INDEX IF NOT EXISTS idx_cve_updated_at_cve_id ON cve(updated_at, cve_id);
        CREATE INDEX IF NOT EXISTS idx_cve_cvss_cve_db_id ON cve_cvss(cve_db_id);
        CREATE INDEX IF NOT EXISTS idx_cve_cvss_severity_score ON cve_cvss(base_severity, base_score);
        CREATE INDEX IF NOT EXISTS idx_cve_affected_cve_db_id ON cve_affected(cve_db_id);
        CREATE INDEX IF NOT EXISTS idx_cve_affected_vendor_product_cve_db_id ON cve_affected(vendor, product, cve_db_id);
        CREATE INDEX IF NOT EXISTS idx_cve_cwe_cwe_id_cve_db_id ON cve_cwe(cwe_id, cve_db_id);
        CREATE INDEX IF NOT EXISTS idx_osv_affected_packages_lookup ON osv_affected_packages(ecosystem COLLATE NOCASE, package_name COLLATE NOCASE);
        CREATE INDEX IF NOT EXISTS idx_osv_affected_packages_osv_id ON osv_affected_packages(osv_id);
        CREATE INDEX IF NOT EXISTS idx_osv_raw_records_content_hash ON osv_raw_records(content_hash);
        CREATE INDEX IF NOT EXISTS idx_osv_aliases_alias ON osv_aliases(alias_id);
        CREATE INDEX IF NOT EXISTS idx_osv_cve_search_cve_id ON osv_cve_search(cve_id);
        CREATE INDEX IF NOT EXISTS idx_osv_ranges_package ON osv_ranges(affected_package_id);
        CREATE INDEX IF NOT EXISTS idx_osv_range_events_range ON osv_range_events(range_id, event_order);
        CREATE INDEX IF NOT EXISTS idx_identifier_edges_to ON vulnerability_identifier_edges(to_identifier);
        CREATE INDEX IF NOT EXISTS idx_identifier_edges_from ON vulnerability_identifier_edges(from_identifier);
        CREATE INDEX IF NOT EXISTS idx_identifier_components_component ON identifier_components(component_id);
        CREATE INDEX IF NOT EXISTS idx_cve_summary_state_published ON cve_summary_index(state, published_at DESC, cve_id);
        CREATE INDEX IF NOT EXISTS idx_cve_summary_updated ON cve_summary_index(updated_at DESC, cve_id);
        CREATE INDEX IF NOT EXISTS idx_cve_cwe_search_sort ON cve_cwe_search(cwe_id, state, published_at DESC, cve_id);
        CREATE INDEX IF NOT EXISTS idx_cve_cvss_search_score ON cve_cvss_search(state, max_cvss_score DESC, published_at DESC, cve_id);
        CREATE INDEX IF NOT EXISTS idx_cve_affected_search_sort ON cve_affected_search(state, published_at DESC, cve_id);

        INSERT OR IGNORE INTO db_sources(source, display_name, source_type, default_filename, raw_format) VALUES
            ('CVE', 'CVE List V5', 'vulnerability_db', 'all_CVEs_at_midnight.zip', 'json'),
            ('OSV', 'OSV.dev', 'vulnerability_db', 'all.zip', 'json'),
            ('KEV', 'CISA Known Exploited Vulnerabilities', 'enrichment', 'known_exploited_vulnerabilities.json', 'json'),
            ('EPSS', 'FIRST EPSS Current Scores', 'enrichment', 'epss_scores-current.csv', 'csv');

        INSERT INTO schema_meta(rowid, version) VALUES(1, 7);
        "#,
    )
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(())
}
