//! SQLite maintenance and integrity checks for SQLx-owned connections.

use sqlx::{Connection, Row, SqliteConnection};

/// Applies the same SQLite bulk-load policy used by devel's full replacement import.
pub(crate) async fn prepare_cve_bulk_load(
    connection: &mut SqliteConnection,
) -> Result<(), sqlx::Error> {
    sqlx::raw_sql(
        r#"
        PRAGMA foreign_keys=OFF;
        PRAGMA journal_mode=MEMORY;
        PRAGMA synchronous=OFF;
        PRAGMA temp_store=MEMORY;
        PRAGMA cache_size=-400000;
        PRAGMA locking_mode=EXCLUSIVE;
        DROP INDEX IF EXISTS idx_read_json_file_filename;
        DROP INDEX IF EXISTS idx_cve_published_at;
        DROP INDEX IF EXISTS idx_cve_updated_at;
        DROP INDEX IF EXISTS idx_cve_published_at_cve_id;
        DROP INDEX IF EXISTS idx_cve_updated_at_cve_id;
        DROP INDEX IF EXISTS idx_cve_cvss_cve_db_id;
        DROP INDEX IF EXISTS idx_cve_cvss_severity_score;
        DROP INDEX IF EXISTS idx_cve_affected_cve_db_id;
        DROP INDEX IF EXISTS idx_cve_affected_vendor_product_cve_db_id;
        DROP INDEX IF EXISTS idx_cve_cwe_cwe_id_cve_db_id;
        DROP INDEX IF EXISTS idx_cve_summary_state_published;
        DROP INDEX IF EXISTS idx_cve_summary_updated;
        DROP INDEX IF EXISTS idx_cve_cwe_search_sort;
        DROP INDEX IF EXISTS idx_cve_cvss_search_score;
        DROP INDEX IF EXISTS idx_cve_affected_search_sort;
        "#,
    )
    .execute(&mut *connection)
    .await?;
    Ok(())
}

/// Recreates deferred indexes and restores normal SQLite durability after a full import.
pub(crate) async fn finish_cve_bulk_load(
    connection: &mut SqliteConnection,
) -> Result<(), sqlx::Error> {
    finish_cve_bulk_load_with_index_signal(connection, None).await
}

pub(crate) async fn finish_cve_bulk_load_with_index_signal(
    connection: &mut SqliteConnection,
    index_started: Option<tokio::sync::oneshot::Sender<()>>,
) -> Result<(), sqlx::Error> {
    sqlx::raw_sql(r#"
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
        "#)
    .execute(&mut *connection)
    .await?;
    if let Some(index_started) = index_started {
        let _ = index_started.send(());
    }
    rebuild_cve_search(connection).await?;
    sqlx::raw_sql(r#"
        CREATE INDEX IF NOT EXISTS idx_cve_summary_state_published ON cve_summary_index(state, published_at DESC, cve_id);
        CREATE INDEX IF NOT EXISTS idx_cve_summary_updated ON cve_summary_index(updated_at DESC, cve_id);
        CREATE INDEX IF NOT EXISTS idx_cve_cwe_search_sort ON cve_cwe_search(cwe_id, state, published_at DESC, cve_id);
        CREATE INDEX IF NOT EXISTS idx_cve_cvss_search_score ON cve_cvss_search(state, max_cvss_score DESC, published_at DESC, cve_id);
        CREATE INDEX IF NOT EXISTS idx_cve_affected_search_sort ON cve_affected_search(state, published_at DESC, cve_id);
        DROP INDEX IF EXISTS idx_cve_reference_text;
        "#)
    .execute(&mut *connection)
    .await?;
    sqlx::query("ANALYZE").execute(&mut *connection).await?;
    sqlx::query("PRAGMA optimize")
        .execute(&mut *connection)
        .await?;
    sqlx::raw_sql(
        "PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA locking_mode=NORMAL; PRAGMA wal_checkpoint(TRUNCATE);",
    )
    .execute(&mut *connection)
    .await?;
    Ok(())
}

pub(crate) async fn prepare_osv_bulk_load(
    connection: &mut SqliteConnection,
) -> Result<(), sqlx::Error> {
    sqlx::raw_sql(
        r#"
        PRAGMA foreign_keys=OFF;
        PRAGMA journal_mode=MEMORY;
        PRAGMA synchronous=OFF;
        PRAGMA temp_store=MEMORY;
        PRAGMA cache_size=-400000;
        PRAGMA locking_mode=EXCLUSIVE;
        DROP INDEX IF EXISTS idx_osv_raw_records_content_hash;
        DROP INDEX IF EXISTS idx_osv_aliases_alias;
        DROP INDEX IF EXISTS idx_osv_cve_search_cve_id;
        DROP INDEX IF EXISTS idx_osv_affected_packages_lookup;
        DROP INDEX IF EXISTS idx_osv_affected_packages_osv_id;
        DROP INDEX IF EXISTS idx_osv_ranges_package;
        DROP INDEX IF EXISTS idx_osv_range_events_range;
        DROP INDEX IF EXISTS idx_identifier_edges_to;
        DROP INDEX IF EXISTS idx_identifier_edges_from;
        "#,
    )
    .execute(&mut *connection)
    .await?;
    Ok(())
}

pub(crate) async fn finish_osv_bulk_load(
    connection: &mut SqliteConnection,
) -> Result<(), sqlx::Error> {
    // SQLite may retain locks through cached prepared statements after hundreds of thousands of
    // inserts. Finalize them before schema DDL and journal-mode transitions.
    connection
        .clear_cached_statements()
        .await
        .map_err(|error| {
            sqlx::Error::Protocol(format!(
                "failed to clear OSV bulk-load statement cache: {error}"
            ))
        })?;
    sqlx::raw_sql(r#"
        CREATE INDEX IF NOT EXISTS idx_osv_raw_records_content_hash ON osv_raw_records(content_hash);
        CREATE INDEX IF NOT EXISTS idx_osv_aliases_alias ON osv_aliases(alias_id);
        CREATE INDEX IF NOT EXISTS idx_osv_cve_search_cve_id ON osv_cve_search(cve_id);
        CREATE INDEX IF NOT EXISTS idx_osv_affected_packages_lookup ON osv_affected_packages(ecosystem COLLATE NOCASE, package_name COLLATE NOCASE);
        CREATE INDEX IF NOT EXISTS idx_osv_affected_packages_osv_id ON osv_affected_packages(osv_id);
        CREATE INDEX IF NOT EXISTS idx_osv_ranges_package ON osv_ranges(affected_package_id);
        CREATE INDEX IF NOT EXISTS idx_osv_range_events_range ON osv_range_events(range_id, event_order);
        CREATE INDEX IF NOT EXISTS idx_identifier_edges_to ON vulnerability_identifier_edges(to_identifier);
        CREATE INDEX IF NOT EXISTS idx_identifier_edges_from ON vulnerability_identifier_edges(from_identifier);
    "#)
    .execute(&mut *connection)
    .await
    .map_err(|error| {
        sqlx::Error::Protocol(format!("failed to rebuild OSV indexes: {error}"))
    })?;
    rebuild_osv_search(connection).await.map_err(|error| {
        sqlx::Error::Protocol(format!("failed to rebuild OSV search data: {error}"))
    })?;
    connection
        .clear_cached_statements()
        .await
        .map_err(|error| {
            sqlx::Error::Protocol(format!(
                "failed to clear OSV maintenance statement cache: {error}"
            ))
        })?;
    sqlx::query("PRAGMA foreign_keys=ON")
        .execute(&mut *connection)
        .await
        .map_err(|error| {
            sqlx::Error::Protocol(format!("failed to restore OSV foreign keys: {error}"))
        })?;
    sqlx::query("PRAGMA locking_mode=NORMAL")
        .execute(&mut *connection)
        .await
        .map_err(|error| {
            sqlx::Error::Protocol(format!("failed to restore OSV locking mode: {error}"))
        })?;
    let database_path: String = sqlx::query("PRAGMA database_list")
        .fetch_one(&mut *connection)
        .await
        .map_err(|error| {
            sqlx::Error::Protocol(format!("failed to inspect OSV database path: {error}"))
        })?
        .try_get("file")?;
    let journal_mode: String = sqlx::query_scalar("PRAGMA journal_mode=WAL")
        .fetch_one(&mut *connection)
        .await
        .map_err(|error| {
            sqlx::Error::Protocol(format!("failed to restore OSV WAL mode: {error}"))
        })?;
    let in_memory = database_path.is_empty() || database_path.eq_ignore_ascii_case(":memory:");
    if !journal_mode.eq_ignore_ascii_case("wal")
        && !(in_memory && journal_mode.eq_ignore_ascii_case("memory"))
    {
        return Err(sqlx::Error::Protocol(format!(
            "failed to restore OSV WAL mode: SQLite selected {journal_mode}"
        )));
    }
    sqlx::query("PRAGMA synchronous=NORMAL")
        .execute(&mut *connection)
        .await
        .map_err(|error| {
            sqlx::Error::Protocol(format!("failed to restore OSV synchronous mode: {error}"))
        })?;
    Ok(())
}

/// Rebuilds every SQLx-owned external-content FTS5 index on one writer connection.
pub(crate) async fn rebuild_search(connection: &mut SqliteConnection) -> Result<(), sqlx::Error> {
    rebuild_cve_search(connection).await?;
    rebuild_osv_search(connection).await
}

/// Rebuilds only the OSV FTS projection after a deferred OSV ZIP import.
pub(crate) async fn rebuild_osv_search(
    connection: &mut SqliteConnection,
) -> Result<(), sqlx::Error> {
    sqlx::raw_sql(
        "DELETE FROM osv_text_fts; INSERT INTO osv_text_fts(osv_id, summary, details, aliases, packages) SELECT advisory.osv_id, COALESCE(advisory.summary, ''), COALESCE(advisory.details, ''), COALESCE((SELECT group_concat(alias_id, ' ') FROM osv_aliases WHERE osv_aliases.osv_id=advisory.osv_id), ''), COALESCE((SELECT group_concat(COALESCE(ecosystem, '') || ' ' || COALESCE(package_name, '') || ' ' || COALESCE(purl, ''), ' ') FROM osv_affected_packages WHERE osv_affected_packages.osv_id=advisory.osv_id), '') FROM osv_advisories advisory;",
    )
    .execute(&mut *connection)
    .await?;
    Ok(())
}

/// Rebuilds CVE FTS after a bulk transaction deliberately deferred trigger maintenance.
pub(crate) async fn rebuild_cve_search(
    connection: &mut SqliteConnection,
) -> Result<(), sqlx::Error> {
    sqlx::raw_sql(
        r#"
        DELETE FROM cve_summary_index;
        INSERT INTO cve_summary_index(cve_db_id, cve_id, state, published_at, updated_at, title, description_en, max_cvss_score, max_cvss_severity, cwe_ids, affected_text, vendor_text, product_text, reference_text)
        WITH
        cvss_agg AS (
            SELECT cve_db_id, MAX(base_score) AS max_score
            FROM cve_cvss GROUP BY cve_db_id
        ),
        cwe_agg AS (
            SELECT cve_db_id, group_concat('CWE-' || cwe_id, ' ') AS cwe_ids
            FROM cve_cwe GROUP BY cve_db_id
        ),
        affected_agg AS (
            SELECT cve_db_id,
                   group_concat(COALESCE(vendor, '') || ' ' || COALESCE(product, '') || ' ' || COALESCE(package_name, '') || ' ' || version_text, ' ') AS affected_text,
                   group_concat(COALESCE(vendor, ''), ' ') AS vendor_text,
                   group_concat(COALESCE(product, '') || ' ' || COALESCE(package_name, ''), ' ') AS product_text
            FROM cve_affected GROUP BY cve_db_id
        )
        SELECT c.id, c.cve_id, c.state, c.published_at, c.updated_at, c.title, c.description_en,
               cvss.max_score,
               (SELECT base_severity FROM cve_cvss severity
                WHERE severity.cve_db_id=c.id ORDER BY base_score DESC LIMIT 1),
               COALESCE(cwe.cwe_ids, ''),
               COALESCE(affected.affected_text, ''), COALESCE(affected.vendor_text, ''),
               COALESCE(affected.product_text, ''), c.reference_text
        FROM cve c
        LEFT JOIN cvss_agg cvss ON cvss.cve_db_id=c.id
        LEFT JOIN cwe_agg cwe ON cwe.cve_db_id=c.id
        LEFT JOIN affected_agg affected ON affected.cve_db_id=c.id;
        DELETE FROM cve_summary_fts;
        INSERT INTO cve_summary_fts(cve_id, title, description_en, affected_text, reference_text)
        SELECT cve_id, title, COALESCE(description_en, ''), affected_text, reference_text FROM cve_summary_index;
        DELETE FROM cve_affected_summary_fts;
        INSERT INTO cve_affected_summary_fts(cve_id, vendor_text, product_text, affected_text)
        SELECT cve_id, vendor_text, product_text, affected_text FROM cve_summary_index;
        DELETE FROM cve_cwe_search;
        INSERT INTO cve_cwe_search SELECT link.cwe_id, c.cve_id, c.state, c.published_at, c.updated_at, c.title, c.description_en FROM cve_cwe link JOIN cve c ON c.id=link.cve_db_id;
        DELETE FROM cve_cvss_search;
        INSERT INTO cve_cvss_search
        SELECT summary.cve_id, summary.state, summary.published_at, summary.updated_at,
               summary.title, summary.description_en, summary.max_cvss_score,
               summary.max_cvss_severity, COALESCE(versions.cvss_versions, '')
        FROM cve_summary_index summary
        LEFT JOIN (
            SELECT cve_db_id, group_concat(DISTINCT version) AS cvss_versions
            FROM cve_cvss GROUP BY cve_db_id
        ) versions ON versions.cve_db_id=summary.cve_db_id;
        DELETE FROM cve_affected_search;
        INSERT INTO cve_affected_search SELECT cve_id, state, published_at, updated_at, title, description_en, vendor_text, product_text, affected_text FROM cve_summary_index;
        "#,
    )
    .execute(&mut *connection)
    .await?;
    Ok(())
}

/// Ensures the destructive SQLx schema contains the objects required by query paths.
pub(crate) async fn check_required_schema(
    connection: &mut SqliteConnection,
) -> Result<(), sqlx::Error> {
    for name in [
        "schema_meta",
        "app_metadata",
        "cve",
        "cwe",
        "cve_cvss",
        "cve_affected",
        "cve_cwe",
        "read_json_file",
        "cve_zip_file",
        "db_sources",
        "source_sync_state",
        "osv_raw_records",
        "osv_advisories",
        "osv_aliases",
        "osv_cve_search",
        "osv_token_cve_search",
        "osv_affected_packages",
        "osv_ranges",
        "osv_range_events",
        "osv_versions",
        "osv_references",
        "kev_raw_records",
        "kev_entries",
        "epss_raw_records",
        "epss_current",
        "vulnerability_identifiers",
        "vulnerability_identifier_edges",
        "identifier_components",
        "cve_summary_index",
        "cve_summary_fts",
        "cve_affected_summary_fts",
        "cve_cwe_search",
        "cve_cvss_search",
        "cve_affected_search",
        "osv_text_fts",
        "idx_cve_summary_state_published",
        "idx_cve_summary_updated",
        "idx_cve_cwe_search_sort",
        "idx_cve_cvss_search_score",
        "idx_cve_affected_search_sort",
        "idx_read_json_file_filename",
        "idx_cve_published_at",
        "idx_cve_updated_at",
        "idx_cve_cvss_cve_db_id",
        "idx_cve_affected_cve_db_id",
        "idx_cve_cwe_cwe_id_cve_db_id",
        "idx_osv_affected_packages_lookup",
        "idx_osv_aliases_alias",
        "idx_osv_ranges_package",
        "idx_osv_range_events_range",
        "idx_identifier_edges_to",
        "idx_identifier_edges_from",
    ] {
        let found: Option<String> =
            sqlx::query_scalar("SELECT name FROM sqlite_master WHERE name = ? LIMIT 1")
                .bind(name)
                .fetch_optional(&mut *connection)
                .await?;
        if found.is_none() {
            return Err(sqlx::Error::Protocol(format!(
                "required schema object is missing: {name}; database rebuild required"
            )));
        }
    }
    let schema_version: Option<i64> = sqlx::query_scalar("SELECT version FROM schema_meta LIMIT 1")
        .fetch_optional(&mut *connection)
        .await?;
    if schema_version != Some(super::schema::SCHEMA_VERSION) {
        return Err(sqlx::Error::Protocol(format!(
            "unsupported schema version {schema_version:?}; database rebuild required"
        )));
    }
    for (table, columns, pragma) in [
        (
            "cve",
            &[
                "id",
                "cve_id",
                "state",
                "published_at",
                "updated_at",
                "serial",
                "title",
                "description_en",
                "reference_text",
                "raw_json",
            ][..],
            "SELECT name FROM pragma_table_info('cve')",
        ),
        (
            "cve_cvss",
            &[
                "id",
                "cve_db_id",
                "version",
                "base_score",
                "base_severity",
                "vector_string",
                "source",
                "raw_json",
            ][..],
            "SELECT name FROM pragma_table_info('cve_cvss')",
        ),
        (
            "cve_affected",
            &[
                "id",
                "cve_db_id",
                "vendor",
                "product",
                "package_name",
                "collection_url",
                "default_status",
                "version_text",
                "raw_json",
            ][..],
            "SELECT name FROM pragma_table_info('cve_affected')",
        ),
        (
            "cve_cwe",
            &["cve_db_id", "cwe_id"][..],
            "SELECT name FROM pragma_table_info('cve_cwe')",
        ),
        (
            "cve_summary_index",
            &[
                "cve_db_id",
                "cve_id",
                "state",
                "published_at",
                "updated_at",
                "title",
                "description_en",
                "max_cvss_score",
                "max_cvss_severity",
                "cwe_ids",
                "affected_text",
                "vendor_text",
                "product_text",
                "reference_text",
            ][..],
            "SELECT name FROM pragma_table_info('cve_summary_index')",
        ),
        (
            "osv_raw_records",
            &[
                "id",
                "osv_id",
                "source_path",
                "provider_published_at",
                "provider_modified_at",
                "fetched_at",
                "content_hash",
                "raw_json",
            ][..],
            "SELECT name FROM pragma_table_info('osv_raw_records')",
        ),
        (
            "osv_advisories",
            &[
                "osv_id",
                "schema_version",
                "published_at",
                "modified_at",
                "withdrawn_at",
                "summary",
                "details",
                "raw_record_id",
            ][..],
            "SELECT name FROM pragma_table_info('osv_advisories')",
        ),
        (
            "osv_aliases",
            &["osv_id", "alias_id"][..],
            "SELECT name FROM pragma_table_info('osv_aliases')",
        ),
        (
            "osv_affected_packages",
            &[
                "id",
                "osv_id",
                "affected_order",
                "ecosystem",
                "package_name",
                "purl",
            ][..],
            "SELECT name FROM pragma_table_info('osv_affected_packages')",
        ),
        (
            "osv_ranges",
            &[
                "id",
                "affected_package_id",
                "affected_order",
                "range_order",
                "range_type",
            ][..],
            "SELECT name FROM pragma_table_info('osv_ranges')",
        ),
        (
            "osv_range_events",
            &["id", "range_id", "event_type", "value", "event_order"][..],
            "SELECT name FROM pragma_table_info('osv_range_events')",
        ),
        (
            "osv_versions",
            &["affected_package_id", "version"][..],
            "SELECT name FROM pragma_table_info('osv_versions')",
        ),
        (
            "source_sync_state",
            &[
                "source",
                "last_attempt_at",
                "last_success_at",
                "status",
                "error_message",
                "last_cursor",
                "content_hash",
                "schema_version",
                "record_count",
            ][..],
            "SELECT name FROM pragma_table_info('source_sync_state')",
        ),
        (
            "kev_entries",
            &[
                "cve_id",
                "vendor_project",
                "product",
                "vulnerability_name",
                "date_added",
                "short_description",
                "required_action",
                "due_date",
                "known_ransomware_campaign_use",
                "notes",
                "fetched_at",
                "raw_record_id",
            ][..],
            "SELECT name FROM pragma_table_info('kev_entries')",
        ),
        (
            "epss_current",
            &[
                "cve_id",
                "epss",
                "percentile",
                "score_date",
                "model_version",
                "fetched_at",
                "raw_record_id",
            ][..],
            "SELECT name FROM pragma_table_info('epss_current')",
        ),
    ] {
        let actual: Vec<String> = sqlx::query_scalar(pragma)
            .fetch_all(&mut *connection)
            .await?;
        for column in columns {
            if !actual.iter().any(|actual| actual == column) {
                return Err(sqlx::Error::Protocol(format!(
                    "required column is missing: {table}.{column}; database rebuild required"
                )));
            }
        }
    }
    for fts_table in [
        "cve_summary_fts",
        "cve_affected_summary_fts",
        "osv_text_fts",
    ] {
        let definition: Option<String> =
            sqlx::query_scalar("SELECT sql FROM sqlite_master WHERE name=? AND type='table'")
                .bind(fts_table)
                .fetch_optional(&mut *connection)
                .await?;
        if !definition.is_some_and(|sql| sql.to_ascii_lowercase().contains("using fts5")) {
            return Err(sqlx::Error::Protocol(format!(
                "required FTS5 virtual table is invalid: {fts_table}; database rebuild required"
            )));
        }
    }
    for (index, expected_columns) in [
        ("idx_cve_cvss_cve_db_id", &["cve_db_id"][..]),
        ("idx_cve_affected_cve_db_id", &["cve_db_id"][..]),
        ("idx_cve_cwe_cwe_id_cve_db_id", &["cwe_id", "cve_db_id"][..]),
        (
            "idx_osv_affected_packages_lookup",
            &["ecosystem", "package_name"][..],
        ),
        ("idx_osv_aliases_alias", &["alias_id"][..]),
        ("idx_osv_ranges_package", &["affected_package_id"][..]),
        (
            "idx_osv_range_events_range",
            &["range_id", "event_order"][..],
        ),
    ] {
        let actual: Vec<String> =
            sqlx::query_scalar("SELECT name FROM pragma_index_info(?) ORDER BY seqno")
                .bind(index)
                .fetch_all(&mut *connection)
                .await?;
        if actual.iter().map(String::as_str).collect::<Vec<_>>() != expected_columns {
            return Err(sqlx::Error::Protocol(format!(
                "required index has wrong columns: {index}; database rebuild required"
            )));
        }
    }
    for (table, columns) in [
        ("osv_raw_records", &["osv_id"][..]),
        ("osv_aliases", &["osv_id", "alias_id"][..]),
        ("osv_versions", &["affected_package_id", "version"][..]),
    ] {
        let index_names: Vec<String> =
            sqlx::query_scalar("SELECT name FROM pragma_index_list(?) WHERE \"unique\"=1")
                .bind(table)
                .fetch_all(&mut *connection)
                .await?;
        let mut found = false;
        for index in index_names {
            let actual: Vec<String> =
                sqlx::query_scalar("SELECT name FROM pragma_index_info(?) ORDER BY seqno")
                    .bind(index)
                    .fetch_all(&mut *connection)
                    .await?;
            if actual.iter().map(String::as_str).collect::<Vec<_>>() == columns {
                found = true;
                break;
            }
        }
        if !found {
            return Err(sqlx::Error::Protocol(format!(
                "required UNIQUE constraint is missing: {table}({}); database rebuild required",
                columns.join(", ")
            )));
        }
    }
    for (table, from_column, target_table, target_column) in [
        ("cve_cvss", "cve_db_id", "cve", "id"),
        ("cve_affected", "cve_db_id", "cve", "id"),
        ("osv_advisories", "raw_record_id", "osv_raw_records", "id"),
        ("osv_aliases", "osv_id", "osv_advisories", "osv_id"),
        (
            "osv_affected_packages",
            "osv_id",
            "osv_advisories",
            "osv_id",
        ),
        (
            "osv_ranges",
            "affected_package_id",
            "osv_affected_packages",
            "id",
        ),
        ("osv_range_events", "range_id", "osv_ranges", "id"),
        (
            "osv_versions",
            "affected_package_id",
            "osv_affected_packages",
            "id",
        ),
        ("kev_entries", "raw_record_id", "kev_raw_records", "id"),
        ("epss_current", "raw_record_id", "epss_raw_records", "id"),
    ] {
        let rows = sqlx::query("SELECT * FROM pragma_foreign_key_list(?)")
            .bind(table)
            .fetch_all(&mut *connection)
            .await?;
        let found = rows.iter().any(|row| {
            row.try_get::<String, _>("from").ok().as_deref() == Some(from_column)
                && row.try_get::<String, _>("table").ok().as_deref() == Some(target_table)
                && row.try_get::<String, _>("to").ok().as_deref() == Some(target_column)
        });
        if !found {
            return Err(sqlx::Error::Protocol(format!(
                "required foreign key is missing: {table}.{from_column} -> {target_table}.{target_column}; database rebuild required"
            )));
        }
    }
    check_foreign_keys_enabled(connection).await
}

pub(crate) async fn check_foreign_keys_enabled(
    connection: &mut SqliteConnection,
) -> Result<(), sqlx::Error> {
    let foreign_keys: i64 = sqlx::query_scalar("PRAGMA foreign_keys")
        .fetch_one(&mut *connection)
        .await?;
    if foreign_keys != 1 {
        return Err(sqlx::Error::Protocol(
            "SQLite foreign key enforcement is disabled on this connection".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) async fn check_sqlite_quick(
    connection: &mut SqliteConnection,
) -> Result<(), sqlx::Error> {
    check_foreign_keys_enabled(connection).await?;
    let result: String = sqlx::query_scalar("PRAGMA quick_check(1)")
        .fetch_one(&mut *connection)
        .await?;
    if result != "ok" {
        return Err(sqlx::Error::Protocol(format!(
            "SQLite quick_check failed: {result}"
        )));
    }
    Ok(())
}

pub(crate) async fn check_sqlite_integrity(
    connection: &mut SqliteConnection,
) -> Result<(), sqlx::Error> {
    let result: String = sqlx::query_scalar("PRAGMA integrity_check")
        .fetch_one(&mut *connection)
        .await?;
    if result != "ok" {
        return Err(sqlx::Error::Protocol(format!(
            "SQLite integrity_check failed: {result}"
        )));
    }
    Ok(())
}

pub(crate) async fn check_foreign_key_integrity(
    connection: &mut SqliteConnection,
) -> Result<(), sqlx::Error> {
    let violation = sqlx::query("PRAGMA foreign_key_check")
        .fetch_optional(&mut *connection)
        .await?;
    if violation.is_some() {
        return Err(sqlx::Error::Protocol(
            "SQLite foreign_key_check found a violation".to_owned(),
        ));
    }
    Ok(())
}

/// Checks an FTS5 index using SQLite's native integrity command.
pub(crate) async fn check_fts5_integrity(
    connection: &mut SqliteConnection,
    table: &str,
) -> Result<(), sqlx::Error> {
    let integrity_sql = match table {
        "cve_summary_fts" => {
            "INSERT INTO cve_summary_fts(cve_summary_fts) VALUES('integrity-check')"
        }
        "cve_affected_summary_fts" => {
            "INSERT INTO cve_affected_summary_fts(cve_affected_summary_fts) VALUES('integrity-check')"
        }
        "osv_text_fts" => "INSERT INTO osv_text_fts(osv_text_fts) VALUES('integrity-check')",
        "cve_search_fts" => {
            "INSERT INTO cve_search_fts(cve_search_fts, rank) VALUES('integrity-check', 1)"
        }
        "osv_search_fts" => {
            "INSERT INTO osv_search_fts(osv_search_fts, rank) VALUES('integrity-check', 1)"
        }
        _ => return Err(sqlx::Error::Protocol("unknown FTS table".to_owned())),
    };
    sqlx::query(integrity_sql).execute(&mut *connection).await?;
    Ok(())
}

async fn require_no_mismatch(
    connection: &mut SqliteConnection,
    label: &str,
    query: &'static str,
) -> Result<(), sqlx::Error> {
    if sqlx::query_scalar::<_, i64>(query)
        .fetch_optional(&mut *connection)
        .await?
        .is_some()
    {
        return Err(sqlx::Error::Protocol(format!(
            "search projection mismatch: {label}"
        )));
    }
    Ok(())
}

/// Performs a fixed number of indexed sentinel checks suitable for routine health checks.
/// These statements intentionally contain no COUNT, OFFSET, or full anti-join.
pub(crate) async fn check_search_integrity_quick(
    connection: &mut SqliteConnection,
) -> Result<(), sqlx::Error> {
    for (label, query) in [
        (
            "CVE summary FTS first row",
            "SELECT 1 WHERE (SELECT cve_id FROM cve_summary_index ORDER BY rowid LIMIT 1) IS NOT (SELECT cve_id FROM cve_summary_fts ORDER BY rowid LIMIT 1)",
        ),
        (
            "CVE summary FTS last row",
            "SELECT 1 WHERE (SELECT cve_id FROM cve_summary_index ORDER BY rowid DESC LIMIT 1) IS NOT (SELECT cve_id FROM cve_summary_fts ORDER BY rowid DESC LIMIT 1)",
        ),
        (
            "CVE affected FTS first row",
            "SELECT 1 WHERE (SELECT cve_id FROM cve_summary_index ORDER BY rowid LIMIT 1) IS NOT (SELECT cve_id FROM cve_affected_summary_fts ORDER BY rowid LIMIT 1)",
        ),
        (
            "CVE affected FTS last row",
            "SELECT 1 WHERE (SELECT cve_id FROM cve_summary_index ORDER BY rowid DESC LIMIT 1) IS NOT (SELECT cve_id FROM cve_affected_summary_fts ORDER BY rowid DESC LIMIT 1)",
        ),
        (
            "OSV text FTS first row",
            "SELECT 1 WHERE (SELECT osv_id FROM osv_advisories ORDER BY rowid LIMIT 1) IS NOT (SELECT osv_id FROM osv_text_fts ORDER BY rowid LIMIT 1)",
        ),
        (
            "OSV text FTS last row",
            "SELECT 1 WHERE (SELECT osv_id FROM osv_advisories ORDER BY rowid DESC LIMIT 1) IS NOT (SELECT osv_id FROM osv_text_fts ORDER BY rowid DESC LIMIT 1)",
        ),
    ] {
        if sqlx::query_scalar::<_, i64>(query)
            .fetch_optional(&mut *connection)
            .await?
            .is_some()
        {
            return Err(sqlx::Error::Protocol(format!(
                "search projection mismatch: {label}"
            )));
        }
    }
    Ok(())
}

/// Performs complete correspondence checks and may scan tables.
pub(crate) async fn check_search_integrity_full(
    connection: &mut SqliteConnection,
) -> Result<(), sqlx::Error> {
    for (label, query) in [
        (
            "cve missing summary",
            "SELECT 1 FROM cve c LEFT JOIN cve_summary_index s ON s.cve_db_id=c.id WHERE s.cve_db_id IS NULL LIMIT 1",
        ),
        (
            "extra CVE summary",
            "SELECT 1 FROM cve_summary_index s LEFT JOIN cve c ON c.id=s.cve_db_id WHERE c.id IS NULL LIMIT 1",
        ),
        (
            "CVE summary missing CVSS projection",
            "SELECT 1 FROM cve_summary_index s LEFT JOIN cve_cvss_search d ON d.cve_id=s.cve_id WHERE d.cve_id IS NULL LIMIT 1",
        ),
        (
            "extra CVSS projection",
            "SELECT 1 FROM cve_cvss_search d LEFT JOIN cve_summary_index s ON s.cve_id=d.cve_id WHERE s.cve_id IS NULL LIMIT 1",
        ),
        (
            "CVE summary missing affected projection",
            "SELECT 1 FROM cve_summary_index s LEFT JOIN cve_affected_search d ON d.cve_id=s.cve_id WHERE d.cve_id IS NULL LIMIT 1",
        ),
        (
            "extra affected projection",
            "SELECT 1 FROM cve_affected_search d LEFT JOIN cve_summary_index s ON s.cve_id=d.cve_id WHERE s.cve_id IS NULL LIMIT 1",
        ),
        (
            "CWE link missing projection",
            "SELECT 1 FROM cve_cwe x JOIN cve c ON c.id=x.cve_db_id LEFT JOIN cve_cwe_search d ON d.cve_id=c.cve_id AND d.cwe_id=x.cwe_id WHERE d.cve_id IS NULL LIMIT 1",
        ),
        (
            "extra CWE projection",
            "SELECT 1 FROM cve_cwe_search d LEFT JOIN cve c ON c.cve_id=d.cve_id LEFT JOIN cve_cwe x ON x.cve_db_id=c.id AND x.cwe_id=d.cwe_id WHERE x.cve_db_id IS NULL LIMIT 1",
        ),
    ] {
        require_no_mismatch(connection, label, query).await?;
    }
    Ok(())
}

async fn check_complete_fts_correspondence(
    connection: &mut SqliteConnection,
    label: &str,
    missing_sql: &'static str,
    extra_sql: &'static str,
) -> Result<(), sqlx::Error> {
    require_no_mismatch(connection, &format!("{label} missing row"), missing_sql).await?;
    require_no_mismatch(connection, &format!("{label} extra row"), extra_sql).await
}

pub(crate) async fn check_cve_search_full(
    connection: &mut SqliteConnection,
) -> Result<(), sqlx::Error> {
    check_fts5_integrity(connection, "cve_summary_fts").await?;
    check_fts5_integrity(connection, "cve_affected_summary_fts").await?;
    check_search_integrity_full(connection).await?;
    check_complete_fts_correspondence(
        connection,
        "CVE summary FTS",
        "SELECT cve_id FROM cve_summary_index EXCEPT SELECT cve_id FROM cve_summary_fts LIMIT 1",
        "SELECT cve_id FROM cve_summary_fts EXCEPT SELECT cve_id FROM cve_summary_index LIMIT 1",
    )
    .await?;
    check_complete_fts_correspondence(
        connection,
        "CVE affected FTS",
        "SELECT cve_id FROM cve_summary_index EXCEPT SELECT cve_id FROM cve_affected_summary_fts LIMIT 1",
        "SELECT cve_id FROM cve_affected_summary_fts EXCEPT SELECT cve_id FROM cve_summary_index LIMIT 1",
    )
    .await
}

pub(crate) async fn check_osv_search_full(
    connection: &mut SqliteConnection,
) -> Result<(), sqlx::Error> {
    check_fts5_integrity(connection, "osv_text_fts").await?;
    check_complete_fts_correspondence(
        connection,
        "OSV text FTS",
        "SELECT osv_id FROM osv_advisories EXCEPT SELECT osv_id FROM osv_text_fts LIMIT 1",
        "SELECT osv_id FROM osv_text_fts EXCEPT SELECT osv_id FROM osv_advisories LIMIT 1",
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::Connection;

    #[tokio::test]
    async fn detects_foreign_key_violations_on_the_same_connection() {
        let mut connection = SqliteConnection::connect("sqlite::memory:").await.unwrap();
        sqlx::query("PRAGMA foreign_keys = ON")
            .execute(&mut connection)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE parent (id INTEGER PRIMARY KEY) STRICT")
            .execute(&mut connection)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE child (parent_id INTEGER NOT NULL REFERENCES parent(id)) STRICT")
            .execute(&mut connection)
            .await
            .unwrap();
        assert!(
            sqlx::query("INSERT INTO child VALUES (1)")
                .execute(&mut connection)
                .await
                .is_err()
        );
        check_sqlite_integrity(&mut connection).await.unwrap();
        sqlx::query(
            "CREATE TABLE search_content (id INTEGER PRIMARY KEY, body TEXT NOT NULL) STRICT",
        )
        .execute(&mut connection)
        .await
        .unwrap();
        sqlx::query(
            "CREATE VIRTUAL TABLE cve_search_fts USING fts5(body, content='search_content', content_rowid='id')",
        )
        .execute(&mut connection)
        .await
        .unwrap();
        sqlx::query("INSERT INTO search_content VALUES (1, 'verified text')")
            .execute(&mut connection)
            .await
            .unwrap();
        sqlx::query("INSERT INTO cve_search_fts(cve_search_fts) VALUES('rebuild')")
            .execute(&mut connection)
            .await
            .unwrap();
        check_fts5_integrity(&mut connection, "cve_search_fts")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn rebuild_search_reports_missing_fts_objects() {
        let mut connection = SqliteConnection::connect("sqlite::memory:").await.unwrap();
        assert!(rebuild_search(&mut connection).await.is_err());
    }

    #[tokio::test]
    async fn missing_schema_reports_rebuild_required() {
        let mut connection = SqliteConnection::connect("sqlite::memory:").await.unwrap();
        let error = check_required_schema(&mut connection).await.unwrap_err();
        assert!(error.to_string().contains("database rebuild required"));
    }
}
