//! SQLite storage and index setup for full CVE initialization.

use super::super::*;

pub(crate) async fn prepare_bulk_replace_all_on<C>(db: &C) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    if !matches!(db.get_database_backend(), DbBackend::Sqlite) {
        return Ok(());
    }

    db.execute_unprepared("PRAGMA foreign_keys = OFF").await?;
    db.execute_unprepared("PRAGMA journal_mode = MEMORY")
        .await?;
    db.execute_unprepared("PRAGMA synchronous = OFF").await?;
    db.execute_unprepared("PRAGMA temp_store = MEMORY").await?;
    db.execute_unprepared("PRAGMA cache_size = -400000").await?;
    db.execute_unprepared("PRAGMA locking_mode = EXCLUSIVE")
        .await?;
    for index_name in BULK_LOAD_DROPPED_INDEXES {
        db.execute_unprepared(&format!("DROP INDEX IF EXISTS {index_name}"))
            .await?;
    }
    Ok(())
}

pub(crate) async fn finish_bulk_replace_all_on<C>(db: &C) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    if !matches!(db.get_database_backend(), DbBackend::Sqlite) {
        return Ok(());
    }

    for sql in BULK_LOAD_FINAL_INDEXES {
        db.execute_unprepared(sql).await?;
    }
    db.execute_unprepared("ANALYZE").await?;
    db.execute_unprepared("PRAGMA optimize").await?;
    rebuild_cve_summary_indexes(db).await?;
    restore_sqlite_bulk_pragmas(db).await?;
    Ok(())
}

pub(crate) async fn finish_bulk_replace_all_storage_on<C>(db: &C) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    if !matches!(db.get_database_backend(), DbBackend::Sqlite) {
        return Ok(());
    }

    restore_sqlite_bulk_pragmas(db).await
}

pub(crate) async fn finish_bulk_replace_all_storage_with_text_search_on<C>(
    db: &C,
) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    if !matches!(db.get_database_backend(), DbBackend::Sqlite) {
        return Ok(());
    }

    rebuild_minimal_cve_text_search(db).await?;
    create_cve_overview_indexes(db).await?;
    restore_sqlite_bulk_pragmas(db).await
}

async fn create_cve_overview_indexes<C>(db: &C) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    if !matches!(db.get_database_backend(), DbBackend::Sqlite) {
        return Ok(());
    }
    for sql in [
        "CREATE INDEX IF NOT EXISTS idx_cve_cvss_cve_db_id ON cve_cvss (cve_db_id)",
        "CREATE INDEX IF NOT EXISTS idx_cve_cvss_cve_db_id_base_score ON cve_cvss (cve_db_id, base_score)",
        "CREATE INDEX IF NOT EXISTS idx_cve_affected_cve_db_id ON cve_affected (cve_db_id)",
        "CREATE INDEX IF NOT EXISTS idx_cve_affected_cve_db_id_vendor_product ON cve_affected (cve_db_id, vendor, product)",
        "CREATE INDEX IF NOT EXISTS idx_cve_affected_vendor_cve_db_id ON cve_affected (vendor, cve_db_id)",
        "CREATE INDEX IF NOT EXISTS idx_cve_affected_product_cve_db_id ON cve_affected (product, cve_db_id)",
        "CREATE INDEX IF NOT EXISTS idx_cve_cwe_cve_db_id ON cve_cwe (cve_db_id)",
    ] {
        db.execute_unprepared(sql).await?;
    }
    Ok(())
}

const BULK_LOAD_DROPPED_INDEXES: &[&str] = &[
    "idx_read_json_file_filename",
    "idx_cve_published_at",
    "idx_cve_updated_at",
    "idx_cve_reference_text",
    "idx_cve_cvss_cve_db_id",
    "idx_cve_cvss_version",
    "idx_cve_cvss_base_score",
    "idx_cve_cvss_base_severity",
    "idx_cve_cvss_severity_score",
    "idx_cve_cvss_version_score",
    "idx_cve_cvss_cve_db_id_score_version",
    "idx_cve_affected_cve_db_id",
    "idx_cve_affected_vendor",
    "idx_cve_affected_product",
    "idx_cve_affected_package",
    "idx_cve_affected_version_text",
    "idx_cve_affected_cve_db_id_vendor_product",
    "idx_cve_affected_vendor_cve_db_id",
    "idx_cve_affected_product_cve_db_id",
    "idx_cve_affected_vendor_product_cve_db_id",
    "idx_cve_cwe_cve_id",
    "idx_cve_cwe_cve_db_id",
    "idx_cve_cwe_cwe_id",
    "idx_cve_cwe_cwe_id_cve_id",
    "idx_cve_cwe_cwe_id_cve_db_id",
    "idx_cwe_id",
    "idx_cve_published_at_cve_id",
    "idx_cve_updated_at_cve_id",
];

const BULK_LOAD_FINAL_INDEXES: &[&str] = &[
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
    "CREATE INDEX IF NOT EXISTS idx_cve_cwe_cwe_id_cve_db_id ON cve_cwe (cwe_id, cve_db_id)",
];
