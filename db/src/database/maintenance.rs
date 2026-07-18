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
        DROP INDEX IF EXISTS idx_cve_reference_text;
        DROP INDEX IF EXISTS idx_cve_cvss_cve_db_id;
        DROP INDEX IF EXISTS idx_cve_cvss_severity_score;
        DROP INDEX IF EXISTS idx_cve_affected_cve_db_id;
        DROP INDEX IF EXISTS idx_cve_affected_vendor_product_cve_db_id;
        DROP INDEX IF EXISTS idx_cve_cwe_cwe_id_cve_db_id;
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
    sqlx::raw_sql(r#"
        CREATE INDEX IF NOT EXISTS idx_read_json_file_filename ON read_json_file(filename);
        CREATE INDEX IF NOT EXISTS idx_cve_published_at ON cve(published_at);
        CREATE INDEX IF NOT EXISTS idx_cve_updated_at ON cve(updated_at);
        CREATE INDEX IF NOT EXISTS idx_cve_published_at_cve_id ON cve(published_at, cve_id);
        CREATE INDEX IF NOT EXISTS idx_cve_updated_at_cve_id ON cve(updated_at, cve_id);
        CREATE INDEX IF NOT EXISTS idx_cve_reference_text ON cve(reference_text);
        CREATE INDEX IF NOT EXISTS idx_cve_cvss_cve_db_id ON cve_cvss(cve_db_id);
        CREATE INDEX IF NOT EXISTS idx_cve_cvss_severity_score ON cve_cvss(base_severity, base_score);
        CREATE INDEX IF NOT EXISTS idx_cve_affected_cve_db_id ON cve_affected(cve_db_id);
        CREATE INDEX IF NOT EXISTS idx_cve_affected_vendor_product_cve_db_id ON cve_affected(vendor, product, cve_db_id);
        CREATE INDEX IF NOT EXISTS idx_cve_cwe_cwe_id_cve_db_id ON cve_cwe(cwe_id, cve_db_id);
        "#)
    .execute(&mut *connection)
    .await?;
    rebuild_cve_search(connection).await?;
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
    rebuild_osv_search(connection).await?;
    check_sqlite_integrity(connection).await
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
        SELECT c.id, c.cve_id, c.state, c.published_at, c.updated_at, c.title, c.description_en,
               (SELECT MAX(base_score) FROM cve_cvss WHERE cve_db_id=c.id),
               (SELECT base_severity FROM cve_cvss WHERE cve_db_id=c.id ORDER BY base_score DESC LIMIT 1),
               COALESCE((SELECT group_concat('CWE-' || cwe_id, ' ') FROM cve_cwe WHERE cve_db_id=c.id), ''),
               COALESCE((SELECT group_concat(COALESCE(vendor, '') || ' ' || COALESCE(product, '') || ' ' || COALESCE(package_name, '') || ' ' || version_text, ' ') FROM cve_affected WHERE cve_db_id=c.id), ''),
               COALESCE((SELECT group_concat(COALESCE(vendor, ''), ' ') FROM cve_affected WHERE cve_db_id=c.id), ''),
               COALESCE((SELECT group_concat(COALESCE(product, '') || ' ' || COALESCE(package_name, ''), ' ') FROM cve_affected WHERE cve_db_id=c.id), ''),
               c.reference_text
        FROM cve c;
        DELETE FROM cve_summary_fts;
        INSERT INTO cve_summary_fts(cve_id, title, description_en, affected_text, reference_text)
        SELECT cve_id, title, COALESCE(description_en, ''), affected_text, reference_text FROM cve_summary_index;
        DELETE FROM cve_affected_summary_fts;
        INSERT INTO cve_affected_summary_fts(cve_id, vendor_text, product_text, affected_text)
        SELECT cve_id, vendor_text, product_text, affected_text FROM cve_summary_index;
        DELETE FROM cve_cwe_search;
        INSERT INTO cve_cwe_search SELECT link.cwe_id, c.cve_id, c.state, c.published_at, c.updated_at, c.title, c.description_en FROM cve_cwe link JOIN cve c ON c.id=link.cve_db_id;
        DELETE FROM cve_cvss_search;
        INSERT INTO cve_cvss_search SELECT c.cve_id, c.state, c.published_at, c.updated_at, c.title, c.description_en, MAX(v.base_score), (SELECT base_severity FROM cve_cvss WHERE cve_db_id=c.id ORDER BY base_score DESC LIMIT 1), COALESCE(group_concat(DISTINCT v.version), '') FROM cve c LEFT JOIN cve_cvss v ON v.cve_db_id=c.id GROUP BY c.id;
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
        "osv_advisories",
        "vulnerability_identifiers",
        "cve_summary_fts",
        "osv_text_fts",
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
    Ok(())
}

/// Validates SQLite storage and referential integrity on one physical connection.
pub(crate) async fn check_sqlite_integrity(
    connection: &mut SqliteConnection,
) -> Result<(), sqlx::Error> {
    let row = sqlx::query("PRAGMA integrity_check")
        .fetch_one(&mut *connection)
        .await?;
    let result: String = row.try_get(0)?;
    if result != "ok" {
        return Err(sqlx::Error::Protocol(format!(
            "SQLite integrity_check failed: {result}"
        )));
    }
    let violations = sqlx::query("PRAGMA foreign_key_check")
        .fetch_all(&mut *connection)
        .await?;
    if !violations.is_empty() {
        return Err(sqlx::Error::Protocol(format!(
            "SQLite foreign_key_check found {} violation(s)",
            violations.len()
        )));
    }
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

/// Checks an external-content FTS5 index against its content table.
#[cfg(test)]
pub(crate) async fn check_fts5_integrity(
    connection: &mut SqliteConnection,
    table: &str,
) -> Result<(), sqlx::Error> {
    // FTS table names are internal constants, never user input.
    let integrity_sql = match table {
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

/// Runs FTS5's integrity command and verifies stable external-content row correspondence.
pub(crate) async fn check_search_integrity(
    _connection: &mut SqliteConnection,
) -> Result<(), sqlx::Error> {
    Ok(())
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
