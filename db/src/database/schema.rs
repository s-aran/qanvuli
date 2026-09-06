//! SQLite schema.

use sqlx::{Connection, SqliteConnection};

pub(crate) const SCHEMA_VERSION: i64 = 12;

pub(crate) async fn create_package_identity_indexes(
    connection: &mut SqliteConnection,
) -> Result<(), sqlx::Error> {
    let ecosystem = super::sqlx_database::sql_ecosystem_key("ecosystem");
    let name = super::sqlx_database::sql_normalized_package_name("package_name", "ecosystem");
    for (index, key) in [
        ("idx_osv_package_identity", name),
        ("idx_osv_package_purl", "purl".to_owned()),
    ] {
        let statement = format!(
            "CREATE INDEX IF NOT EXISTS {index} ON osv_affected_packages({ecosystem} COLLATE BINARY, {key} COLLATE BINARY)"
        );
        sqlx::query(sqlx::AssertSqlSafe(statement))
            .execute(&mut *connection)
            .await?;
    }
    Ok(())
}

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
        CREATE TABLE IF NOT EXISTS capec (
            id INTEGER PRIMARY KEY NOT NULL,
            name TEXT NOT NULL,
            description TEXT NOT NULL,
            extended_description TEXT,
            status TEXT NOT NULL,
            abstraction TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS capec_parent (
            capec_id INTEGER NOT NULL REFERENCES capec(id) ON DELETE CASCADE,
            parent_id INTEGER NOT NULL REFERENCES capec(id) ON DELETE CASCADE,
            relation_order INTEGER NOT NULL,
            PRIMARY KEY(capec_id, parent_id)
        );
        CREATE TABLE IF NOT EXISTS capec_cwe (
            capec_id INTEGER NOT NULL REFERENCES capec(id) ON DELETE CASCADE,
            cwe_id INTEGER NOT NULL REFERENCES cwe(id) ON DELETE CASCADE,
            relation_order INTEGER NOT NULL,
            PRIMARY KEY(capec_id, cwe_id)
        );
        CREATE TABLE IF NOT EXISTS capec_category (
            id INTEGER PRIMARY KEY NOT NULL,
            name TEXT NOT NULL,
            status TEXT NOT NULL,
            summary TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS capec_category_member (
            category_id INTEGER NOT NULL REFERENCES capec_category(id) ON DELETE CASCADE,
            capec_id INTEGER NOT NULL REFERENCES capec(id) ON DELETE CASCADE,
            member_order INTEGER NOT NULL,
            PRIMARY KEY(category_id, capec_id)
        );
        CREATE TABLE IF NOT EXISTS capec_view (
            id INTEGER PRIMARY KEY NOT NULL,
            name TEXT NOT NULL,
            view_type TEXT NOT NULL,
            status TEXT NOT NULL,
            objective TEXT NOT NULL,
            filter TEXT
        );
        CREATE TABLE IF NOT EXISTS capec_view_category (
            view_id INTEGER NOT NULL REFERENCES capec_view(id) ON DELETE CASCADE,
            category_id INTEGER NOT NULL REFERENCES capec_category(id) ON DELETE CASCADE,
            member_order INTEGER NOT NULL,
            PRIMARY KEY(view_id, category_id)
        );
        CREATE TABLE IF NOT EXISTS capec_view_capec (
            view_id INTEGER NOT NULL REFERENCES capec_view(id) ON DELETE CASCADE,
            capec_id INTEGER NOT NULL REFERENCES capec(id) ON DELETE CASCADE,
            member_order INTEGER NOT NULL,
            PRIMARY KEY(view_id, capec_id)
        );
        CREATE TABLE IF NOT EXISTS capec_external_reference (
            reference_id TEXT PRIMARY KEY NOT NULL,
            title TEXT NOT NULL,
            edition TEXT,
            publication TEXT,
            publication_year TEXT,
            publication_month TEXT,
            publication_day TEXT,
            publisher TEXT,
            url TEXT,
            url_date TEXT
        );
        CREATE TABLE IF NOT EXISTS capec_external_reference_author (
            reference_id TEXT NOT NULL REFERENCES capec_external_reference(reference_id) ON DELETE CASCADE,
            author_order INTEGER NOT NULL,
            author TEXT NOT NULL,
            PRIMARY KEY(reference_id, author_order)
        );
        CREATE TABLE IF NOT EXISTS capec_reference (
            capec_id INTEGER NOT NULL REFERENCES capec(id) ON DELETE CASCADE,
            reference_id TEXT NOT NULL REFERENCES capec_external_reference(reference_id) ON DELETE CASCADE,
            section TEXT,
            reference_order INTEGER NOT NULL,
            PRIMARY KEY(capec_id, reference_id, reference_order)
        );
        CREATE TABLE IF NOT EXISTS capec_category_reference (
            category_id INTEGER NOT NULL REFERENCES capec_category(id) ON DELETE CASCADE,
            reference_id TEXT NOT NULL REFERENCES capec_external_reference(reference_id) ON DELETE CASCADE,
            section TEXT,
            reference_order INTEGER NOT NULL,
            PRIMARY KEY(category_id, reference_id, reference_order)
        );
        CREATE TABLE IF NOT EXISTS capec_view_reference (
            view_id INTEGER NOT NULL REFERENCES capec_view(id) ON DELETE CASCADE,
            reference_id TEXT NOT NULL REFERENCES capec_external_reference(reference_id) ON DELETE CASCADE,
            section TEXT,
            reference_order INTEGER NOT NULL,
            PRIMARY KEY(view_id, reference_id, reference_order)
        );
        CREATE TABLE IF NOT EXISTS capec_category_history (
            category_id INTEGER NOT NULL REFERENCES capec_category(id) ON DELETE CASCADE,
            event_order INTEGER NOT NULL,
            event_type TEXT NOT NULL,
            event_date TEXT NOT NULL,
            actor_name TEXT,
            organization TEXT,
            comment TEXT,
            previous_name TEXT,
            PRIMARY KEY(category_id, event_order)
        );
        CREATE TABLE IF NOT EXISTS capec_view_history (
            view_id INTEGER NOT NULL REFERENCES capec_view(id) ON DELETE CASCADE,
            event_order INTEGER NOT NULL,
            event_type TEXT NOT NULL,
            event_date TEXT NOT NULL,
            actor_name TEXT,
            organization TEXT,
            comment TEXT,
            previous_name TEXT,
            PRIMARY KEY(view_id, event_order)
        );
        CREATE TABLE IF NOT EXISTS capec_category_note (
            category_id INTEGER NOT NULL REFERENCES capec_category(id) ON DELETE CASCADE,
            note_order INTEGER NOT NULL,
            note_type TEXT NOT NULL,
            note_text TEXT NOT NULL,
            PRIMARY KEY(category_id, note_order)
        );
        CREATE TABLE IF NOT EXISTS capec_view_note (
            view_id INTEGER NOT NULL REFERENCES capec_view(id) ON DELETE CASCADE,
            note_order INTEGER NOT NULL,
            note_type TEXT NOT NULL,
            note_text TEXT NOT NULL,
            PRIMARY KEY(view_id, note_order)
        );
        CREATE TABLE IF NOT EXISTS capec_category_taxonomy_mapping (
            category_id INTEGER NOT NULL REFERENCES capec_category(id) ON DELETE CASCADE,
            mapping_order INTEGER NOT NULL,
            taxonomy TEXT NOT NULL,
            entry_id TEXT,
            entry_name TEXT,
            PRIMARY KEY(category_id, mapping_order)
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
        CREATE TABLE IF NOT EXISTS osv_aliases (osv_id TEXT NOT NULL REFERENCES osv_advisories(osv_id) ON DELETE CASCADE, alias_id TEXT NOT NULL, PRIMARY KEY(osv_id, alias_id));
        CREATE TABLE IF NOT EXISTS osv_cve_search (osv_id TEXT NOT NULL, cve_id TEXT NOT NULL, PRIMARY KEY(osv_id, cve_id));
        CREATE TABLE IF NOT EXISTS osv_token_cve_search (token TEXT NOT NULL, cve_id TEXT NOT NULL, state INTEGER NOT NULL, published_at TEXT NOT NULL, PRIMARY KEY(token, cve_id));
        CREATE TABLE IF NOT EXISTS osv_affected_packages (
            id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
            osv_id TEXT NOT NULL REFERENCES osv_advisories(osv_id) ON DELETE CASCADE,
            affected_order INTEGER NOT NULL DEFAULT 0,
            ecosystem TEXT,
            package_name TEXT,
            purl TEXT
        );
        CREATE TABLE IF NOT EXISTS osv_ranges (
            id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
            affected_package_id INTEGER NOT NULL REFERENCES osv_affected_packages(id) ON DELETE CASCADE,
            affected_order INTEGER NOT NULL DEFAULT 0,
            range_order INTEGER NOT NULL DEFAULT 0,
            range_type TEXT
        );
        CREATE TABLE IF NOT EXISTS osv_range_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
            range_id INTEGER NOT NULL REFERENCES osv_ranges(id) ON DELETE CASCADE,
            event_type TEXT NOT NULL,
            value TEXT NOT NULL,
            event_order INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS osv_versions (affected_package_id INTEGER NOT NULL REFERENCES osv_affected_packages(id) ON DELETE CASCADE, version TEXT NOT NULL, PRIMARY KEY(affected_package_id, version));
        CREATE TABLE IF NOT EXISTS osv_references (osv_id TEXT NOT NULL REFERENCES osv_advisories(osv_id) ON DELETE CASCADE, reference_type TEXT, url TEXT NOT NULL, PRIMARY KEY(osv_id, url));
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
        CREATE TABLE IF NOT EXISTS ssvc_assessments (
            cve_id TEXT NOT NULL REFERENCES cve(cve_id) ON DELETE CASCADE,
            provider TEXT NOT NULL,
            role TEXT NOT NULL,
            version TEXT NOT NULL,
            assessed_at TEXT NOT NULL,
            exploitation TEXT CHECK(exploitation IS NULL OR exploitation IN ('none', 'poc', 'active')),
            automatable TEXT CHECK(automatable IS NULL OR automatable IN ('no', 'yes')),
            technical_impact TEXT CHECK(technical_impact IS NULL OR technical_impact IN ('partial', 'total')),
            fetched_at TEXT NOT NULL,
            raw_json TEXT NOT NULL,
            PRIMARY KEY(cve_id, provider, role)
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
            title TEXT NOT NULL,
            description_en TEXT,
            affected_text TEXT NOT NULL DEFAULT '',
            vendor_text TEXT NOT NULL DEFAULT '',
            product_text TEXT NOT NULL DEFAULT '',
            reference_text TEXT NOT NULL DEFAULT ''
        );
        CREATE VIRTUAL TABLE IF NOT EXISTS cve_summary_fts USING fts5(cve_id UNINDEXED, title, description_en, affected_text, reference_text, tokenize='unicode61');
        CREATE VIRTUAL TABLE IF NOT EXISTS cve_affected_summary_fts USING fts5(cve_id UNINDEXED, vendor_text, product_text, affected_text, tokenize='unicode61');

        CREATE INDEX IF NOT EXISTS idx_read_json_file_filename ON read_json_file(filename);
        CREATE INDEX IF NOT EXISTS idx_cve_published_at_cve_id ON cve(published_at, cve_id);
        CREATE INDEX IF NOT EXISTS idx_cve_updated_at_cve_id ON cve(updated_at, cve_id);
        CREATE INDEX IF NOT EXISTS idx_cve_cvss_cve_db_id ON cve_cvss(cve_db_id);
        CREATE INDEX IF NOT EXISTS idx_cve_cvss_severity_score ON cve_cvss(base_severity, base_score);
        CREATE INDEX IF NOT EXISTS idx_cve_affected_cve_db_id ON cve_affected(cve_db_id);
        CREATE INDEX IF NOT EXISTS idx_cve_affected_vendor_product_cve_db_id ON cve_affected(vendor, product, cve_db_id);
        CREATE INDEX IF NOT EXISTS idx_cve_cwe_cwe_id_cve_db_id ON cve_cwe(cwe_id, cve_db_id);
        CREATE INDEX IF NOT EXISTS idx_capec_status_type ON capec(status, abstraction, id);
        CREATE INDEX IF NOT EXISTS idx_capec_parent_parent ON capec_parent(parent_id, capec_id);
        CREATE INDEX IF NOT EXISTS idx_capec_cwe_cwe ON capec_cwe(cwe_id, capec_id);
        CREATE INDEX IF NOT EXISTS idx_capec_category_member_capec ON capec_category_member(capec_id, category_id);
        CREATE INDEX IF NOT EXISTS idx_capec_view_capec_capec ON capec_view_capec(capec_id, view_id);
        CREATE INDEX IF NOT EXISTS idx_capec_view_category_category ON capec_view_category(category_id, view_id);
        CREATE INDEX IF NOT EXISTS idx_osv_affected_packages_lookup ON osv_affected_packages(ecosystem COLLATE NOCASE, package_name COLLATE NOCASE);
        CREATE INDEX IF NOT EXISTS idx_osv_affected_packages_osv_id ON osv_affected_packages(osv_id);
        CREATE INDEX IF NOT EXISTS idx_osv_published_asc ON osv_advisories(published_at IS NULL, published_at ASC, osv_id ASC);
        CREATE INDEX IF NOT EXISTS idx_osv_published_desc ON osv_advisories(published_at IS NULL, published_at DESC, osv_id DESC);
        CREATE INDEX IF NOT EXISTS idx_osv_modified_osv_id ON osv_advisories(modified_at, osv_id);
        CREATE INDEX IF NOT EXISTS idx_osv_raw_records_content_hash ON osv_raw_records(content_hash);
        CREATE INDEX IF NOT EXISTS idx_osv_aliases_alias ON osv_aliases(alias_id);
        CREATE INDEX IF NOT EXISTS idx_osv_cve_search_cve_id ON osv_cve_search(cve_id);
        CREATE INDEX IF NOT EXISTS idx_osv_ranges_package ON osv_ranges(affected_package_id);
        CREATE INDEX IF NOT EXISTS idx_osv_range_events_range ON osv_range_events(range_id, event_order);
        CREATE INDEX IF NOT EXISTS idx_identifier_edges_to ON vulnerability_identifier_edges(to_identifier);
        CREATE INDEX IF NOT EXISTS idx_identifier_edges_from ON vulnerability_identifier_edges(from_identifier);
        CREATE INDEX IF NOT EXISTS idx_identifier_components_component ON identifier_components(component_id);
        CREATE INDEX IF NOT EXISTS idx_ssvc_decision_points ON ssvc_assessments(exploitation, automatable, technical_impact, cve_id);

        INSERT OR IGNORE INTO db_sources(source, display_name, source_type, default_filename, raw_format) VALUES
            ('CVE', 'CVE List V5', 'vulnerability_db', 'all_CVEs_at_midnight.zip', 'json'),
            ('OSV', 'OSV.dev', 'vulnerability_db', 'all.zip', 'json'),
            ('KEV', 'CISA Known Exploited Vulnerabilities', 'enrichment', 'known_exploited_vulnerabilities.json', 'json'),
            ('EPSS', 'FIRST EPSS Current Scores', 'enrichment', 'epss_scores-current.csv', 'csv'),
            ('SSVC', 'CVE ADP SSVC assessments', 'enrichment', 'CVE ADP containers', 'json');

        INSERT INTO schema_meta(rowid, version) VALUES(1, 12);
        "#,
    )
    .execute(&mut *transaction)
    .await?;
    create_package_identity_indexes(&mut transaction).await?;
    transaction.commit().await?;
    Ok(())
}
